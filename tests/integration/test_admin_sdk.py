"""Tests for AuthzAdminClient against the in-process FastAPI app."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from authz_sdk import AuthzAdminClient, AuthzServiceError
from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine


@pytest.fixture()
def admin(temp_db_url) -> AuthzAdminClient:
    override_settings(
        Settings(
            database_url=temp_db_url,
            api_keys=("k1",),
            log_level="WARNING",
            audit_all_decisions=False,
            auto_provision_user=True,
            auto_provision_tenant=False,
        )
    )
    reset_engine()
    from authz_service.main import create_app

    app = create_app()
    test_client = TestClient(app)
    return AuthzAdminClient(
        base_url="http://testserver", api_key="k1", http_client=test_client
    )


def test_create_and_get_tenant(admin: AuthzAdminClient):
    tenant = admin.create_tenant(slug="acme", name="ACME")
    assert tenant.slug == "acme"
    fetched = admin.get_tenant("acme")
    assert fetched.id == tenant.id


def test_full_provisioning_flow(admin: AuthzAdminClient):
    admin.create_tenant(slug="t1", name="T1")
    app = admin.create_application(slug="a1", name="A1")
    admin.create_permission(app.id, name="docs.read")
    admin.create_permission(app.id, name="docs.write")

    role = admin.upsert_role_with_permissions(
        app.id,
        name="editor",
        permissions=["docs.read", "docs.write"],
    )
    perms = admin.get_role_permissions(role.id)
    assert sorted(perms) == ["docs.read", "docs.write"]

    # Idempotent re-run keeps the same role id.
    same_role = admin.upsert_role_with_permissions(
        app.id, name="editor", permissions=["docs.read"]
    )
    assert same_role.id == role.id
    assert admin.get_role_permissions(role.id) == ["docs.read"]


def test_list_memberships_pagination(admin: AuthzAdminClient):
    tenant = admin.create_tenant(slug="p", name="P")
    app = admin.create_application(slug="pa", name="PA")
    admin.create_permission(app.id, name="x.y")
    admin.upsert_role_with_permissions(app.id, name="reader", permissions=["x.y"])

    from authz_service.config import get_settings
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url

    store = SqlAlchemyStore(create_engine_from_url(get_settings().database_url))
    user_ids = []
    for i in range(5):
        user, _ = store.upsert_user_from_identity(
            provider="oidc",
            issuer="i",
            subject=f"u{i}",
            email=None,
            external_tenant_id=None,
        )
        admin.create_membership(
            tenant.id,
            user_id=user.id,
            application_id=app.id,
            roles=["reader"],
        )
        user_ids.append(user.id)

    page1 = admin.list_memberships(tenant.id, page=1, page_size=2)
    page2 = admin.list_memberships(tenant.id, page=2, page_size=2)
    page3 = admin.list_memberships(tenant.id, page=3, page_size=2)
    assert len(page1) == 2
    assert len(page2) == 2
    assert len(page3) == 1
    seen = {m.id for m in page1 + page2 + page3}
    assert len(seen) == 5


def test_unknown_tenant_raises_service_error(admin: AuthzAdminClient):
    with pytest.raises(AuthzServiceError) as exc:
        admin.get_tenant("does-not-exist")
    assert exc.value.status_code == 404
