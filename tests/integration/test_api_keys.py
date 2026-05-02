"""Tests for the scoped API key system."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine


@pytest.fixture()
def make_client(temp_db_url):
    def _make(**overrides) -> TestClient:
        defaults = dict(
            database_url=temp_db_url,
            api_keys=("bootstrap-key",),
            log_level="WARNING",
            audit_all_decisions=False,
            auto_provision_user=True,
            auto_provision_tenant=False,
            cors_allow_origins=(),
            rate_limit_per_minute=0,
        )
        defaults.update(overrides)
        override_settings(Settings(**defaults))
        reset_engine()
        from authz_service.main import create_app

        return TestClient(create_app())

    return _make


def test_env_key_authenticates_admin_endpoints(make_client):
    """The bootstrap env key works as an admin until DB keys are provisioned."""
    client = make_client()
    response = client.post(
        "/v1/api-keys",
        json={"name": "first-real-key", "scopes": ["admin"]},
        headers={"X-API-Key": "bootstrap-key"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["scopes"] == ["admin"]
    assert body["key"].startswith("azk_")
    assert body["key_prefix"]


def test_db_key_replaces_bootstrap(make_client):
    """Once a DB key is active, requests must use a real key (or env key)."""
    client = make_client()
    created = client.post(
        "/v1/api-keys",
        json={"name": "real", "scopes": ["admin"]},
        headers={"X-API-Key": "bootstrap-key"},
    ).json()

    # Real key works
    response = client.post(
        "/v1/applications",
        json={"slug": "a", "name": "A"},
        headers={"X-API-Key": created["key"]},
    )
    assert response.status_code == 201

    # Bogus key fails
    response = client.post(
        "/v1/applications",
        json={"slug": "x", "name": "X"},
        headers={"X-API-Key": "totally-wrong"},
    )
    assert response.status_code == 401


def test_runtime_scope_cannot_create_admin_resources(make_client):
    client = make_client()
    runtime_key = client.post(
        "/v1/api-keys",
        json={"name": "runtime", "scopes": ["runtime"]},
        headers={"X-API-Key": "bootstrap-key"},
    ).json()["key"]

    # Runtime keys cannot create tenants (admin scope required).
    response = client.post(
        "/v1/tenants",
        json={"slug": "rl", "name": "RL"},
        headers={"X-API-Key": runtime_key},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "scope_required"

    # But the runtime path still works.
    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": "x",
            "application_id": "y",
            "subject": {"type": "user", "user_id": "u"},
            "resource": "r",
            "action": "a",
        },
        headers={"X-API-Key": runtime_key},
    )
    # 200 with allowed=false because tenant doesn't exist; what we care about
    # is that authentication + scope passed.
    assert response.status_code == 200
    assert response.json()["allowed"] is False


def test_revoked_key_immediately_rejects(make_client):
    client = make_client()
    created = client.post(
        "/v1/api-keys",
        json={"name": "victim", "scopes": ["admin"]},
        headers={"X-API-Key": "bootstrap-key"},
    ).json()

    # Revoke it.
    response = client.delete(
        f"/v1/api-keys/{created['id']}",
        headers={"X-API-Key": "bootstrap-key"},
    )
    assert response.status_code == 204

    # Subsequent calls with that key get 401.
    response = client.post(
        "/v1/applications",
        json={"slug": "a", "name": "A"},
        headers={"X-API-Key": created["key"]},
    )
    assert response.status_code == 401


def test_rotate_creates_new_key_inheriting_scopes(make_client):
    client = make_client()
    original = client.post(
        "/v1/api-keys",
        json={"name": "orig", "scopes": ["runtime"]},
        headers={"X-API-Key": "bootstrap-key"},
    ).json()
    rotated = client.post(
        f"/v1/api-keys/{original['id']}/rotate",
        headers={"X-API-Key": "bootstrap-key"},
    ).json()
    assert rotated["scopes"] == ["runtime"]
    assert rotated["rotates"] == original["id"]
    assert rotated["key"] != original["key"]
