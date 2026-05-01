"""Round-trip tests for the SQLAlchemy-backed store using SQLite."""

from __future__ import annotations

import pytest

from authzkit.rbac.checker import (
    AuthorizationEngine,
    AuthorizeRequest,
    Subject,
)
from authzkit.rbac.models import RoleScope
from authzkit.storage.sqlalchemy import (
    SqlAlchemyStore,
    create_engine_from_url,
    init_schema,
)


@pytest.fixture()
def store(temp_db_url) -> SqlAlchemyStore:
    engine = create_engine_from_url(temp_db_url)
    init_schema(engine)
    return SqlAlchemyStore(engine)


def test_round_trip_authorize(store: SqlAlchemyStore):
    tenant = store.create_tenant(slug="t", name="T")
    app = store.create_application(slug="a", name="A")
    for name in ["files.read", "files.write"]:
        store.create_permission(name=name, application_id=app.id)
    role = store.create_role(
        name="editor", scope=RoleScope.APPLICATION, application_id=app.id
    )
    store.set_role_permissions(role.id, {"files.read", "files.write"})
    user, _ = store.upsert_user_from_identity(
        provider="oidc", issuer="x", subject="s", email=None, external_tenant_id=None
    )
    store.create_membership(
        tenant_id=tenant.id,
        application_id=app.id,
        user_id=user.id,
        roles={"editor"},
    )

    engine = AuthorizationEngine(store)
    decision = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="user", user_id=user.id),
            resource="files",
            action="read",
        )
    )
    assert decision.allowed


def test_external_identity_lookup_is_idempotent(store: SqlAlchemyStore):
    user1, _ = store.upsert_user_from_identity(
        provider="entra", issuer="i", subject="s1", email=None, external_tenant_id=None
    )
    user2, _ = store.upsert_user_from_identity(
        provider="entra", issuer="i", subject="s1", email=None, external_tenant_id=None
    )
    assert user1.id == user2.id


def test_tenant_mapping_lookup(store: SqlAlchemyStore):
    tenant = store.create_tenant(slug="t", name="T")
    store.create_tenant_identity_mapping(
        tenant_id=tenant.id,
        provider="entra",
        issuer="iss",
        external_tenant_id="ext",
    )
    found = store.find_tenant_by_external("entra", "iss", "ext")
    assert found is not None
    assert found.id == tenant.id


def test_audit_log_persisted(store: SqlAlchemyStore):
    from authzkit.audit.logger import AuditEntry

    entry = AuditEntry(
        decision="deny",
        reason="missing_permission",
        resource="x",
        action="y",
        tenant_id="t",
    )
    store.write_audit(entry, request_id="req-1")
    # Smoke check: at least one row exists.
    from sqlalchemy import select

    from authzkit.storage import orm

    with store.session() as s:
        rows = s.scalars(select(orm.AuditLog)).all()
        assert len(rows) == 1
        assert rows[0].decision == "deny"
        assert rows[0].request_id == "req-1"
