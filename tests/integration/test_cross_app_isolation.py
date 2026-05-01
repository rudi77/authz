"""Regression tests for permission isolation across applications.

Two cases covered:

1. A user with memberships in app-A and app-B (same tenant) should only see
   app-A's permissions when evaluated against app-A. Previously the SQL store
   leaked roles across apps.

2. A user with both an app-scoped membership AND a tenant-wide membership
   should get the union of both sets. Previously the in-memory store picked
   only one membership.
"""

from __future__ import annotations

import pytest

from authzkit.rbac.checker import (
    AuthorizationEngine,
    AuthorizeRequest,
    Subject,
)
from authzkit.rbac.models import RoleScope
from authzkit.storage.memory import InMemoryStore
from authzkit.storage.sqlalchemy import (
    SqlAlchemyStore,
    create_engine_from_url,
    init_schema,
)


@pytest.fixture()
def sql_store(temp_db_url) -> SqlAlchemyStore:
    engine = create_engine_from_url(temp_db_url)
    init_schema(engine)
    return SqlAlchemyStore(engine)


def _seed_two_apps(store):
    """Create one tenant + two apps, each with its own role + permission."""
    tenant = store.create_tenant(slug="t", name="T")
    app_a = store.create_application(slug="app-a", name="A")
    app_b = store.create_application(slug="app-b", name="B")

    store.create_permission(name="docs.read", application_id=app_a.id)
    store.create_permission(name="invoices.read", application_id=app_b.id)

    role_a = store.create_role(
        name="reader", scope=RoleScope.APPLICATION, application_id=app_a.id
    )
    store.set_role_permissions(role_a.id, {"docs.read"})
    role_b = store.create_role(
        name="reader", scope=RoleScope.APPLICATION, application_id=app_b.id
    )
    store.set_role_permissions(role_b.id, {"invoices.read"})

    user, _ = store.upsert_user_from_identity(
        provider="oidc",
        issuer="i",
        subject="s",
        email=None,
        external_tenant_id=None,
    )
    store.create_membership(
        tenant_id=tenant.id,
        application_id=app_a.id,
        user_id=user.id,
        roles={"reader"},
    )
    store.create_membership(
        tenant_id=tenant.id,
        application_id=app_b.id,
        user_id=user.id,
        roles={"reader"},
    )
    return tenant, app_a, app_b, user


def test_sql_store_does_not_leak_permissions_across_apps(sql_store):
    tenant, app_a, app_b, user = _seed_two_apps(sql_store)
    perms_a = sql_store.resolve_user_permissions(
        tenant_id=tenant.id, application_id=app_a.id, user_id=user.id
    )
    perms_b = sql_store.resolve_user_permissions(
        tenant_id=tenant.id, application_id=app_b.id, user_id=user.id
    )
    assert perms_a == {"docs.read"}
    assert perms_b == {"invoices.read"}


def test_memory_store_does_not_leak_permissions_across_apps():
    store = InMemoryStore()
    tenant, app_a, app_b, user = _seed_two_apps(store)
    perms_a = store.resolve_user_permissions(
        tenant_id=tenant.id, application_id=app_a.id, user_id=user.id
    )
    perms_b = store.resolve_user_permissions(
        tenant_id=tenant.id, application_id=app_b.id, user_id=user.id
    )
    assert perms_a == {"docs.read"}
    assert perms_b == {"invoices.read"}


def test_memory_store_unions_app_scoped_and_tenant_wide_memberships():
    """Both memberships should grant their app-applicable permissions.

    The tenant-wide membership carries a platform-scoped permission
    (application_id NULL) which must be visible from any app.
    """
    store = InMemoryStore()
    tenant = store.create_tenant(slug="t", name="T")
    app = store.create_application(slug="a", name="A")

    store.create_permission(name="docs.read", application_id=app.id)
    store.create_permission(name="tenant.manage", application_id=None)

    app_role = store.create_role(
        name="reader", scope=RoleScope.APPLICATION, application_id=app.id
    )
    store.set_role_permissions(app_role.id, {"docs.read"})

    platform_role = store.create_role(
        name="tenant_admin", scope=RoleScope.PLATFORM, application_id=None
    )
    store.set_role_permissions(platform_role.id, {"tenant.manage"})

    user, _ = store.upsert_user_from_identity(
        provider="oidc",
        issuer="i",
        subject="s",
        email=None,
        external_tenant_id=None,
    )
    store.create_membership(
        tenant_id=tenant.id,
        application_id=app.id,
        user_id=user.id,
        roles={"reader"},
    )
    store.create_membership(
        tenant_id=tenant.id,
        application_id=None,
        user_id=user.id,
        roles={"tenant_admin"},
    )
    perms = store.resolve_user_permissions(
        tenant_id=tenant.id, application_id=app.id, user_id=user.id
    )
    assert perms == {"docs.read", "tenant.manage"}


def test_sql_store_unions_app_scoped_and_tenant_wide_memberships(sql_store):
    tenant = sql_store.create_tenant(slug="t", name="T")
    app = sql_store.create_application(slug="a", name="A")
    sql_store.create_permission(name="docs.read", application_id=app.id)
    sql_store.create_permission(name="tenant.manage", application_id=None)

    app_role = sql_store.create_role(
        name="reader", scope=RoleScope.APPLICATION, application_id=app.id
    )
    sql_store.set_role_permissions(app_role.id, {"docs.read"})

    platform_role = sql_store.create_role(
        name="tenant_admin", scope=RoleScope.PLATFORM, application_id=None
    )
    sql_store.set_role_permissions(platform_role.id, {"tenant.manage"})

    user, _ = sql_store.upsert_user_from_identity(
        provider="oidc",
        issuer="i",
        subject="s",
        email=None,
        external_tenant_id=None,
    )
    sql_store.create_membership(
        tenant_id=tenant.id,
        application_id=app.id,
        user_id=user.id,
        roles={"reader"},
    )
    sql_store.create_membership(
        tenant_id=tenant.id,
        application_id=None,
        user_id=user.id,
        roles={"tenant_admin"},
    )
    perms = sql_store.resolve_user_permissions(
        tenant_id=tenant.id, application_id=app.id, user_id=user.id
    )
    assert perms == {"docs.read", "tenant.manage"}


def test_authorization_engine_isolates_apps(sql_store):
    """End-to-end check via the AuthorizationEngine itself."""
    tenant, app_a, app_b, user = _seed_two_apps(sql_store)
    engine = AuthorizationEngine(sql_store)

    # Allowed in app A
    d = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app_a.id,
            subject=Subject(type="user", user_id=user.id),
            resource="docs",
            action="read",
        )
    )
    assert d.allowed

    # Asking for invoices.read in app A must be denied even though the user
    # has it in app B. This is the cross-app isolation guarantee.
    d = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app_a.id,
            subject=Subject(type="user", user_id=user.id),
            resource="invoices",
            action="read",
        )
    )
    assert not d.allowed
    assert d.reason == "missing_permission"
