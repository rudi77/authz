"""Endpoints backing the admin UI: list/patch catalog, users, audit, masks."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine

HEADERS = {"X-API-Key": "test-key"}


@pytest.fixture()
def client(temp_db_url) -> TestClient:
    override_settings(
        Settings(
            database_url=temp_db_url,
            api_keys=("test-key",),
            log_level="WARNING",
            audit_all_decisions=False,
        )
    )
    reset_engine()
    from authz_service.main import create_app

    return TestClient(create_app())


def _seed(client: TestClient):
    tenant = client.post(
        "/v1/tenants", json={"slug": "acme", "name": "ACME"}, headers=HEADERS
    ).json()
    app = client.post(
        "/v1/applications", json={"slug": "contracts", "name": "Contracts"}, headers=HEADERS
    ).json()
    for name in ["contracts.read", "contracts.review"]:
        client.post(
            f"/v1/applications/{app['id']}/permissions", json={"name": name}, headers=HEADERS
        )
    role = client.post(
        f"/v1/applications/{app['id']}/roles", json={"name": "reviewer"}, headers=HEADERS
    ).json()
    client.put(
        f"/v1/roles/{role['id']}/permissions",
        json={"permissions": ["contracts.read", "contracts.review"]},
        headers=HEADERS,
    )
    user = client.post(
        "/v1/users",
        json={
            "provider": "entra",
            "issuer": "https://login.example.com",
            "subject": "u-1",
            "email": "alice@example.com",
            "display_name": "Alice",
        },
        headers=HEADERS,
    )
    assert user.status_code == 201, user.text
    user = user.json()
    m = client.post(
        f"/v1/tenants/{tenant['id']}/memberships",
        json={"user_id": user["id"], "application_id": app["id"], "roles": ["reviewer"]},
        headers=HEADERS,
    )
    assert m.status_code == 201, m.text
    return tenant, app, role, user


def test_admin_ui_is_served(client: TestClient):
    r = client.get("/admin/")
    assert r.status_code == 200
    assert "AuthZ Admin" in r.text
    # Browsers must revalidate, or an upgrade keeps showing the old UI.
    assert r.headers["cache-control"] == "no-cache"
    # Versioned asset URLs so stale pre-no-cache copies are never reused.
    assert 'src="./app.js?v=' in r.text and 'href="./styles.css?v=' in r.text
    js = client.get("/admin/app.js?v=3")
    assert js.status_code == 200 and js.headers["cache-control"] == "no-cache"
    # Conditional requests still get a cheap 304.
    again = client.get("/admin/app.js", headers={"If-None-Match": js.headers["etag"]})
    assert again.status_code == 304


def test_list_and_patch_tenants_and_applications(client: TestClient):
    tenant, app, _, _ = _seed(client)
    tenants = client.get("/v1/tenants", headers=HEADERS).json()
    assert [t["slug"] for t in tenants] == ["acme"]
    apps = client.get("/v1/applications", headers=HEADERS).json()
    assert [a["slug"] for a in apps] == ["contracts"]

    r = client.patch(
        f"/v1/tenants/{tenant['id']}", json={"status": "suspended"}, headers=HEADERS
    )
    assert r.status_code == 200 and r.json()["status"] == "suspended"
    r = client.patch("/v1/applications/contracts", json={"name": "Contracts 2"}, headers=HEADERS)
    assert r.status_code == 200 and r.json()["name"] == "Contracts 2"
    assert client.patch("/v1/tenants/nope", json={}, headers=HEADERS).status_code == 404


def test_list_endpoints_require_admin(client: TestClient):
    for path in ["/v1/tenants", "/v1/applications", "/v1/users", "/v1/audit"]:
        assert client.get(path, headers={"X-API-Key": "wrong"}).status_code == 401


def test_users_are_listed_and_searchable_and_idempotent(client: TestClient):
    _, _, _, user = _seed(client)
    again = client.post(
        "/v1/users",
        json={"provider": "entra", "issuer": "https://login.example.com", "subject": "u-1"},
        headers=HEADERS,
    ).json()
    assert again["id"] == user["id"]
    users = client.get("/v1/users", params={"q": "alice"}, headers=HEADERS).json()
    assert [u["id"] for u in users] == [user["id"]]
    assert users[0]["identities"][0]["subject"] == "u-1"
    assert client.get("/v1/users", params={"q": "bob"}, headers=HEADERS).json() == []


def test_mappings_listed(client: TestClient):
    tenant, *_ = _seed(client)
    client.post(
        f"/v1/tenants/{tenant['id']}/mappings",
        json={"provider": "entra", "issuer": "https://iss", "external_tenant_id": "tid-1"},
        headers=HEADERS,
    )
    rows = client.get(f"/v1/tenants/{tenant['id']}/mappings", headers=HEADERS).json()
    assert [r["external_tenant_id"] for r in rows] == ["tid-1"]


def test_permission_mask_round_trip_and_enforced(client: TestClient):
    tenant, app, _, user = _seed(client)
    mask_url = f"/v1/tenants/{tenant['id']}/applications/{app['id']}/permission-mask"
    assert client.get(mask_url, headers=HEADERS).json()["permissions"] == []

    r = client.put(mask_url, json={"permissions": ["contracts.read"]}, headers=HEADERS)
    assert r.json()["permissions"] == ["contracts.read"]
    assert client.get(mask_url, headers=HEADERS).json()["permissions"] == ["contracts.read"]

    decision = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant["id"],
            "application_id": app["id"],
            "subject": {"type": "user", "user_id": user["id"]},
            "resource": "contracts",
            "action": "review",
        },
        headers=HEADERS,
    ).json()
    assert decision["allowed"] is False
    assert decision["reason"] == "tenant_feature_disabled"

    audit = client.get("/v1/audit", params={"decision": "deny"}, headers=HEADERS).json()
    assert len(audit) == 1
    assert audit[0]["reason"] == "tenant_feature_disabled"
    assert audit[0]["user_id"] == user["id"]
    by_tenant = client.get("/v1/audit", params={"tenant_id": "acme"}, headers=HEADERS).json()
    assert len(by_tenant) == 1


def test_feature_flags_listed(client: TestClient):
    tenant, app, _, _ = _seed(client)
    client.put(
        f"/v1/tenants/{tenant['id']}/feature-flags",
        json={"key": "beta", "value": True},
        headers=HEADERS,
    )
    client.put(
        f"/v1/tenants/{tenant['id']}/feature-flags",
        json={"key": "limit", "value": {"max": 5}, "application_id": app["id"]},
        headers=HEADERS,
    )
    tenant_flags = client.get(f"/v1/tenants/{tenant['id']}/feature-flags", headers=HEADERS)
    assert tenant_flags.json()["flags"] == {"beta": True}
    app_flags = client.get(
        f"/v1/tenants/{tenant['id']}/feature-flags",
        params={"application_id": "contracts"},
        headers=HEADERS,
    )
    assert app_flags.json()["flags"] == {"limit": {"max": 5}}


def test_agent_roles_readable(client: TestClient):
    tenant, app, _, _ = _seed(client)
    agent = client.post(
        f"/v1/tenants/{tenant['id']}/applications/{app['id']}/agents",
        json={"name": "bot"},
        headers=HEADERS,
    ).json()
    client.put(f"/v1/agents/{agent['id']}/roles", json={"roles": ["reviewer"]}, headers=HEADERS)
    r = client.get(f"/v1/agents/{agent['id']}/roles", headers=HEADERS)
    assert r.json()["roles"] == ["reviewer"]
    assert client.get("/v1/agents/missing/roles", headers=HEADERS).status_code == 404


def test_preprovisioned_user_is_recognised_at_login(client: TestClient):
    """A user added in the admin UI must be the same user resolve-context finds."""
    tenant, app, _, user = _seed(client)
    r = client.post(
        "/v1/resolve-context",
        json={
            "application_id": app["slug"],  # resolve-context takes the slug
            "provider": "entra",  # as stored by _seed via POST /v1/users
            "issuer": "https://login.example.com",
            "subject": "u-1",
            "explicit_tenant_id": tenant["id"],
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_id"] == user["id"]
    assert "reviewer" in body["roles"]
