"""Z-5: role/permission assignment reports unknown ids and names instead of
silently succeeding."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine

HEADERS = {"X-API-Key": "test-key"}


@pytest.fixture()
def client(temp_db_url) -> TestClient:
    override_settings(
        Settings(database_url=temp_db_url, api_keys=("test-key",), log_level="WARNING")
    )
    reset_engine()
    from authz_service.main import create_app

    return TestClient(create_app())


def _seed(client: TestClient) -> dict:
    tenant = client.post("/v1/tenants", json={"slug": "t", "name": "T"}, headers=HEADERS).json()
    app = client.post(
        "/v1/applications", json={"slug": "app", "name": "App"}, headers=HEADERS
    ).json()
    client.post(
        f"/v1/applications/{app['id']}/permissions", json={"name": "docs.read"}, headers=HEADERS
    )
    role = client.post(
        f"/v1/applications/{app['id']}/roles", json={"name": "reader"}, headers=HEADERS
    ).json()
    agent = client.post(
        f"/v1/tenants/{tenant['id']}/applications/{app['id']}/agents",
        json={"name": "bot"},
        headers=HEADERS,
    ).json()
    return {"role": role["id"], "agent": agent["id"]}


def test_agent_roles_unknown_agent_is_404(client):
    r = client.put("/v1/agents/missing/roles", json={"roles": []}, headers=HEADERS)
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "agent_not_found"


def test_agent_roles_unknown_role_is_422_and_nothing_applied(client):
    ids = _seed(client)
    r = client.put(
        f"/v1/agents/{ids['agent']}/roles", json={"roles": ["reader"]}, headers=HEADERS
    )
    assert r.status_code == 200
    r = client.put(
        f"/v1/agents/{ids['agent']}/roles",
        json={"roles": ["ghost", "reader"]},
        headers=HEADERS,
    )
    assert r.status_code == 422
    assert r.json()["detail"] == {"error": "unknown_role", "roles": ["ghost"]}
    roles = client.get(f"/v1/agents/{ids['agent']}/roles", headers=HEADERS).json()
    assert roles["roles"] == ["reader"]


def test_role_permissions_unknown_role_is_404(client):
    r = client.put("/v1/roles/missing/permissions", json={"permissions": []}, headers=HEADERS)
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "role_not_found"


def test_role_permissions_unknown_permission_is_422_and_nothing_applied(client):
    ids = _seed(client)
    client.put(
        f"/v1/roles/{ids['role']}/permissions",
        json={"permissions": ["docs.read"]},
        headers=HEADERS,
    )
    r = client.put(
        f"/v1/roles/{ids['role']}/permissions",
        json={"permissions": ["docs.read", "docs.nuke"]},
        headers=HEADERS,
    )
    assert r.status_code == 422
    assert r.json()["detail"] == {"error": "unknown_permission", "permissions": ["docs.nuke"]}
    current = client.get(f"/v1/roles/{ids['role']}/permissions", headers=HEADERS).json()
    assert current["permissions"] == ["docs.read"]
