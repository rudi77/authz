"""Tests confirming bulk_authorize resolves the subject's permissions once."""

from __future__ import annotations

from authzkit.rbac.checker import (
    AuthorizationEngine,
    BulkAuthorizeRequest,
    Subject,
)
from authzkit.rbac.models import RoleScope
from authzkit.storage.memory import InMemoryStore


class CountingStore(InMemoryStore):
    """Wraps the in-memory store and counts permission-resolution calls.

    Exists only in this test module so we can prove that bulk_authorize no
    longer asks the repository per check.
    """

    def __init__(self) -> None:
        super().__init__()
        self.user_perm_calls = 0
        self.agent_perm_calls = 0
        self.tenant_perm_calls = 0

    def resolve_user_permissions(self, **kwargs) -> set[str]:
        self.user_perm_calls += 1
        return super().resolve_user_permissions(**kwargs)

    def resolve_agent_permissions(self, **kwargs) -> set[str]:
        self.agent_perm_calls += 1
        return super().resolve_agent_permissions(**kwargs)

    def resolve_tenant_permissions(self, **kwargs) -> set[str]:
        self.tenant_perm_calls += 1
        return super().resolve_tenant_permissions(**kwargs)


def _seed(store: InMemoryStore):
    tenant = store.create_tenant(slug="t", name="T")
    app = store.create_application(slug="a", name="A")
    for p in ["docs.read", "docs.write", "tools.gmail.send"]:
        store.create_permission(name=p, application_id=app.id)
    role = store.create_role(name="r", scope=RoleScope.APPLICATION, application_id=app.id)
    store.set_role_permissions(role.id, {"docs.read", "docs.write"})
    user, _ = store.upsert_user_from_identity(
        provider="oidc",
        issuer="i",
        subject="s",
        email=None,
        external_tenant_id=None,
    )
    store.create_membership(
        tenant_id=tenant.id, application_id=app.id, user_id=user.id, roles={"r"}
    )
    return tenant, app, user


def test_bulk_authorize_resolves_subject_permissions_once():
    store = CountingStore()
    tenant, app, user = _seed(store)
    engine = AuthorizationEngine(store)
    decisions = engine.bulk_authorize(
        BulkAuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="user", user_id=user.id),
            checks=[
                ("docs", "read"),
                ("docs", "write"),
                ("tools.gmail", "send"),
            ],
        )
    )
    assert [d.allowed for d in decisions] == [True, True, False]
    assert decisions[2].reason == "missing_permission"
    # Single user-permissions resolution and single tenant-mask resolution
    # for three checks. Without the fast-path each check would call both.
    assert store.user_perm_calls == 1
    assert store.tenant_perm_calls == 1


def test_bulk_authorize_short_circuits_inactive_tenant():
    store = CountingStore()
    tenant, app, user = _seed(store)
    from dataclasses import replace

    store.tenants[tenant.id] = replace(store.tenants[tenant.id], status="suspended")
    engine = AuthorizationEngine(store)
    decisions = engine.bulk_authorize(
        BulkAuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="user", user_id=user.id),
            checks=[("docs", "read"), ("docs", "write")],
        )
    )
    # Both denied with same reason; no permission resolution attempted.
    assert all(not d.allowed and d.reason == "tenant_not_active" for d in decisions)
    assert store.user_perm_calls == 0
