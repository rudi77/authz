"""End-to-end tests against the FastAPI service via TestClient."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine


@pytest.fixture()
def client(temp_db_url) -> TestClient:
    override_settings(
        Settings(
            database_url=temp_db_url,
            api_keys=("test-key",),
            log_level="WARNING",
            audit_all_decisions=True,
            auto_provision_user=True,
            auto_provision_tenant=False,
        )
    )
    reset_engine()
    from authz_service.main import create_app

    app = create_app()
    return TestClient(app)


HEADERS = {"X-API-Key": "test-key"}


def _seed_basic(client: TestClient):
    """Create tenant + app + permissions + role + user + membership."""
    tenant = client.post(
        "/v1/tenants", json={"slug": "acme", "name": "ACME"}, headers=HEADERS
    ).json()
    app = client.post(
        "/v1/applications",
        json={"slug": "contract-ai", "name": "Contract AI"},
        headers=HEADERS,
    ).json()
    for name in ["contracts.read", "contracts.review", "contracts.classify"]:
        client.post(
            f"/v1/applications/{app['id']}/permissions",
            json={"name": name},
            headers=HEADERS,
        )
    role = client.post(
        f"/v1/applications/{app['id']}/roles",
        json={"name": "legal_reviewer", "scope": "application"},
        headers=HEADERS,
    ).json()
    client.put(
        f"/v1/roles/{role['id']}/permissions",
        json={"permissions": ["contracts.read", "contracts.review"]},
        headers=HEADERS,
    )
    return tenant, app, role


def test_authorize_unauthorized_without_api_key(client: TestClient):
    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": "t",
            "application_id": "a",
            "subject": {"type": "user", "user_id": "u"},
            "resource": "contracts",
            "action": "read",
        },
    )
    assert response.status_code == 401


def test_resolve_context_creates_user_and_returns_permissions(client: TestClient):
    tenant, app, role = _seed_basic(client)
    # Map external Entra tenant to our internal tenant.
    client.post(
        f"/v1/tenants/{tenant['id']}/mappings",
        json={
            "provider": "azure_entra",
            "issuer": "https://login.example/v2",
            "external_tenant_id": "ext-tenant-1",
        },
        headers=HEADERS,
    )
    # First call provisions the user; we need a membership next.
    response = client.post(
        "/v1/resolve-context",
        json={
            "application_id": app["slug"],
            "provider": "azure_entra",
            "issuer": "https://login.example/v2",
            "subject": "oid-1",
            "external_tenant_id": "ext-tenant-1",
            "email": "alice@acme.com",
            "claims": {},
        },
        headers=HEADERS,
    )
    # No membership yet so this should 404.
    assert response.status_code == 404

    # Get the auto-provisioned user_id from the database.
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url
    from authz_service.config import get_settings

    engine = create_engine_from_url(get_settings().database_url)
    store = SqlAlchemyStore(engine)
    user = store.find_user_by_external_identity(
        "azure_entra", "https://login.example/v2", "oid-1"
    )
    assert user is not None

    # Add membership with the legal_reviewer role.
    client.post(
        f"/v1/tenants/{tenant['id']}/memberships",
        json={
            "user_id": user.id,
            "application_id": app["id"],
            "roles": ["legal_reviewer"],
        },
        headers=HEADERS,
    )

    response = client.post(
        "/v1/resolve-context",
        json={
            "application_id": app["slug"],
            "provider": "azure_entra",
            "issuer": "https://login.example/v2",
            "subject": "oid-1",
            "external_tenant_id": "ext-tenant-1",
            "email": "alice@acme.com",
            "claims": {},
        },
        headers=HEADERS,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == tenant["id"]
    assert body["roles"] == ["legal_reviewer"]
    assert "contracts.read" in body["permissions"]


def test_authorize_allow_and_deny(client: TestClient):
    tenant, app, _ = _seed_basic(client)
    # Provision user + membership directly.
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url
    from authz_service.config import get_settings

    engine = create_engine_from_url(get_settings().database_url)
    store = SqlAlchemyStore(engine)
    user, _ = store.upsert_user_from_identity(
        provider="azure_entra",
        issuer="iss",
        subject="sub-1",
        email="a@b.com",
        external_tenant_id=None,
    )
    client.post(
        f"/v1/tenants/{tenant['id']}/memberships",
        json={
            "user_id": user.id,
            "application_id": app["id"],
            "roles": ["legal_reviewer"],
        },
        headers=HEADERS,
    )

    allow_resp = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant["id"],
            "application_id": app["id"],
            "subject": {"type": "user", "user_id": user.id},
            "resource": "contracts",
            "action": "read",
        },
        headers=HEADERS,
    ).json()
    assert allow_resp == {
        "allowed": True,
        "decision": "allow",
        "reason": "permission_granted",
        "required_permission": "contracts.read",
        "matched_permissions": ["contracts.read"],
    }

    deny_resp = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant["id"],
            "application_id": app["id"],
            "subject": {"type": "user", "user_id": user.id},
            "resource": "contracts",
            "action": "classify",
        },
        headers=HEADERS,
    ).json()
    assert deny_resp["allowed"] is False
    assert deny_resp["reason"] == "missing_permission"
    assert deny_resp["matched_permissions"] == []


def test_bulk_authorize(client: TestClient):
    tenant, app, _ = _seed_basic(client)
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url
    from authz_service.config import get_settings

    engine = create_engine_from_url(get_settings().database_url)
    store = SqlAlchemyStore(engine)
    user, _ = store.upsert_user_from_identity(
        provider="azure_entra",
        issuer="iss",
        subject="bulk-sub",
        email=None,
        external_tenant_id=None,
    )
    client.post(
        f"/v1/tenants/{tenant['id']}/memberships",
        json={
            "user_id": user.id,
            "application_id": app["id"],
            "roles": ["legal_reviewer"],
        },
        headers=HEADERS,
    )
    resp = client.post(
        "/v1/bulk-authorize",
        json={
            "tenant_id": tenant["id"],
            "application_id": app["id"],
            "subject": {"type": "user", "user_id": user.id},
            "checks": [
                {"resource": "contracts", "action": "read"},
                {"resource": "contracts", "action": "classify"},
            ],
        },
        headers=HEADERS,
    ).json()
    assert [r["allowed"] for r in resp["results"]] == [True, False]


def test_effective_permissions_endpoint(client: TestClient):
    tenant, app, _ = _seed_basic(client)
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url
    from authz_service.config import get_settings

    engine = create_engine_from_url(get_settings().database_url)
    store = SqlAlchemyStore(engine)
    user, _ = store.upsert_user_from_identity(
        provider="azure_entra",
        issuer="iss",
        subject="ep-sub",
        email=None,
        external_tenant_id=None,
    )
    client.post(
        f"/v1/tenants/{tenant['id']}/memberships",
        json={
            "user_id": user.id,
            "application_id": app["id"],
            "roles": ["legal_reviewer"],
        },
        headers=HEADERS,
    )
    resp = client.post(
        "/v1/effective-permissions",
        json={
            "tenant_id": tenant["id"],
            "application_id": app["id"],
            "subject": {"type": "user", "user_id": user.id},
        },
        headers=HEADERS,
    ).json()
    assert sorted(resp["permissions"]) == ["contracts.read", "contracts.review"]


def test_agent_authorization_respects_intersection(client: TestClient):
    tenant, app, _ = _seed_basic(client)
    # Create classify permission already exists; create an agent role.
    agent_role = client.post(
        f"/v1/applications/{app['id']}/roles",
        json={"name": "contract_classifier", "scope": "agent"},
        headers=HEADERS,
    ).json()
    client.put(
        f"/v1/roles/{agent_role['id']}/permissions",
        json={"permissions": ["contracts.read", "contracts.classify"]},
        headers=HEADERS,
    )
    # User + membership.
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url
    from authz_service.config import get_settings

    engine = create_engine_from_url(get_settings().database_url)
    store = SqlAlchemyStore(engine)
    user, _ = store.upsert_user_from_identity(
        provider="azure_entra",
        issuer="iss",
        subject="agent-user",
        email=None,
        external_tenant_id=None,
    )
    client.post(
        f"/v1/tenants/{tenant['id']}/memberships",
        json={
            "user_id": user.id,
            "application_id": app["id"],
            "roles": ["legal_reviewer"],
        },
        headers=HEADERS,
    )
    agent = client.post(
        f"/v1/tenants/{tenant['id']}/applications/{app['id']}/agents",
        json={"name": "Classifier", "role": "contract_classifier"},
        headers=HEADERS,
    ).json()
    client.put(
        f"/v1/agents/{agent['id']}/roles",
        json={"roles": ["contract_classifier"]},
        headers=HEADERS,
    )

    # contracts.classify only in agent set -> denied (user lacks it)
    deny = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant["id"],
            "application_id": app["id"],
            "subject": {"type": "agent", "user_id": user.id, "agent_id": agent["id"]},
            "resource": "contracts",
            "action": "classify",
        },
        headers=HEADERS,
    ).json()
    assert deny["allowed"] is False
    assert deny["reason"] == "missing_permission"

    # contracts.read in both -> allowed
    allow = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant["id"],
            "application_id": app["id"],
            "subject": {"type": "agent", "user_id": user.id, "agent_id": agent["id"]},
            "resource": "contracts",
            "action": "read",
        },
        headers=HEADERS,
    ).json()
    assert allow["allowed"] is True
