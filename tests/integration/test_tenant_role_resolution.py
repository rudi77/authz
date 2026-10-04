"""Tenant-first role resolution (Z-8) for both storage backends.

Regression: ``create_membership`` / ``set_membership_roles`` used to pick
roles by ``(application_id, name)`` only, so a tenant-bound role of tenant A
could be attached to a membership in tenant B. Role names now resolve to the
role of *this* tenant first, else the application-wide role, and never to a
role of another tenant. A tenant role named like an application role
overrides it in permission resolution, whenever it was created.
"""

from __future__ import annotations

import pytest

from authzkit.rbac.models import RoleScope
from authzkit.storage.memory import InMemoryStore
from authzkit.storage.sqlalchemy import (
    SqlAlchemyStore,
    create_engine_from_url,
    init_schema,
)


@pytest.fixture(params=["memory", "sql"])
def store(request, temp_db_url):
    if request.param == "memory":
        yield InMemoryStore()
        return
    engine = create_engine_from_url(temp_db_url)
    init_schema(engine)
    yield SqlAlchemyStore(engine)
    engine.dispose()


def _seed(store):
    """Tenant A overrides ``operator``; tenant B uses the application role.

    The tenant role is created *before* the application role so a
    first-match lookup by ``(application_id, name)`` hits the wrong one.
    """
    tenant_a = store.create_tenant(slug="a", name="A")
    tenant_b = store.create_tenant(slug="b", name="B")
    app = store.create_application(slug="app", name="App")
    store.create_permission(name="docs.read", application_id=app.id)
    store.create_permission(name="docs.delete", application_id=app.id)

    override = store.create_role(
        name="operator",
        scope=RoleScope.TENANT,
        application_id=app.id,
        tenant_id=tenant_a.id,
    )
    store.set_role_permissions(override.id, {"docs.delete"})
    default = store.create_role(
        name="operator", scope=RoleScope.APPLICATION, application_id=app.id
    )
    store.set_role_permissions(default.id, {"docs.read"})
    return tenant_a, tenant_b, app


def _user(store, subject: str):
    user, _ = store.upsert_user_from_identity(
        provider="oidc", issuer="i", subject=subject, email=None, external_tenant_id=None
    )
    return user


def _perms(store, tenant, app, user) -> set[str]:
    return store.resolve_user_permissions(
        tenant_id=tenant.id, application_id=app.id, user_id=user.id
    )


def test_create_membership_never_attaches_other_tenants_role(store):
    _tenant_a, tenant_b, app = _seed(store)
    bob = _user(store, "bob")
    store.create_membership(
        tenant_id=tenant_b.id, application_id=app.id, user_id=bob.id, roles={"operator"}
    )
    assert _perms(store, tenant_b, app, bob) == {"docs.read"}


def test_set_membership_roles_never_attaches_other_tenants_role(store):
    _tenant_a, tenant_b, app = _seed(store)
    bob = _user(store, "bob")
    membership = store.create_membership(
        tenant_id=tenant_b.id, application_id=app.id, user_id=bob.id
    )
    store.set_membership_roles(membership.id, {"operator"})
    assert _perms(store, tenant_b, app, bob) == {"docs.read"}


def test_membership_resolves_tenant_role_first(store):
    tenant_a, _tenant_b, app = _seed(store)
    alice = _user(store, "alice")
    store.create_membership(
        tenant_id=tenant_a.id, application_id=app.id, user_id=alice.id, roles={"operator"}
    )
    assert _perms(store, tenant_a, app, alice) == {"docs.delete"}


def test_override_created_later_wins_over_application_role(store):
    tenant = store.create_tenant(slug="t", name="T")
    app = store.create_application(slug="app", name="App")
    store.create_permission(name="docs.read", application_id=app.id)
    store.create_permission(name="docs.delete", application_id=app.id)
    default = store.create_role(
        name="operator", scope=RoleScope.APPLICATION, application_id=app.id
    )
    store.set_role_permissions(default.id, {"docs.read"})
    alice = _user(store, "alice")
    store.create_membership(
        tenant_id=tenant.id, application_id=app.id, user_id=alice.id, roles={"operator"}
    )
    assert _perms(store, tenant, app, alice) == {"docs.read"}

    override = store.create_role(
        name="operator", scope=RoleScope.TENANT, application_id=app.id, tenant_id=tenant.id
    )
    store.set_role_permissions(override.id, {"docs.delete"})
    assert _perms(store, tenant, app, alice) == {"docs.delete"}


def test_agent_roles_resolve_tenant_first(store):
    tenant_a, tenant_b, app = _seed(store)
    agent_a = store.create_agent(tenant_id=tenant_a.id, application_id=app.id, name="bot")
    agent_b = store.create_agent(tenant_id=tenant_b.id, application_id=app.id, name="bot")
    store.set_agent_roles(agent_a.id, {"operator"})
    store.set_agent_roles(agent_b.id, {"operator"})
    assert store.resolve_agent_permissions(
        tenant_id=tenant_a.id, application_id=app.id, agent_id=agent_a.id
    ) == {"docs.delete"}
    assert store.resolve_agent_permissions(
        tenant_id=tenant_b.id, application_id=app.id, agent_id=agent_b.id
    ) == {"docs.read"}
