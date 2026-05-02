"""Regression tests for the two P1 issues raised in Codex review of PR #2.

P1.1 — Tenant-scoped API keys (``tenant:<id>``) must be confined to their
       tenant on every runtime endpoint.
P1.2 — The idempotency cache must partition by the full credential, not
       just ``X-API-Key``, so bearer-authenticated callers don't share
       a replay bucket with each other (or with empty-header callers).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine

BOOTSTRAP_HEADERS = {"X-API-Key": "bootstrap-key"}


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


# ---------------------------------------------------------------------------
# P1.1 — tenant scope binding on the runtime path
# ---------------------------------------------------------------------------


def _seed_two_tenants(client: TestClient):
    """Two tenants, each with their own app + permission + reader role."""
    tenants = []
    apps = []
    for slug in ("tenant_a", "tenant_b"):
        t = client.post(
            "/v1/tenants", json={"slug": slug, "name": slug.upper()},
            headers=BOOTSTRAP_HEADERS,
        ).json()
        a = client.post(
            "/v1/applications",
            json={"slug": f"app-{slug}", "name": f"App {slug}"},
            headers=BOOTSTRAP_HEADERS,
        ).json()
        client.post(
            f"/v1/applications/{a['id']}/permissions",
            json={"name": "docs.read"},
            headers=BOOTSTRAP_HEADERS,
        )
        role = client.post(
            f"/v1/applications/{a['id']}/roles",
            json={"name": "reader", "scope": "application"},
            headers=BOOTSTRAP_HEADERS,
        ).json()
        client.put(
            f"/v1/roles/{role['id']}/permissions",
            json={"permissions": ["docs.read"]},
            headers=BOOTSTRAP_HEADERS,
        )
        tenants.append(t)
        apps.append(a)
    return tenants, apps


def test_tenant_scoped_key_can_authorize_in_its_own_tenant(make_client):
    client = make_client()
    tenants, apps = _seed_two_tenants(client)
    tenant_a, tenant_b = tenants
    app_a, _ = apps

    # Issue a key bound to tenant A
    key_a = client.post(
        "/v1/api-keys",
        json={"name": "tenant_a-runtime", "scopes": [f"tenant:{tenant_a['id']}"]},
        headers=BOOTSTRAP_HEADERS,
    ).json()["key"]

    # Calling /v1/authorize for tenant A passes the auth + binding check.
    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant_a["id"],
            "application_id": app_a["id"],
            "subject": {"type": "user", "user_id": "anyone"},
            "resource": "docs",
            "action": "read",
        },
        headers={"X-API-Key": key_a},
    )
    # 200 with allowed=false because the user has no membership; what we
    # care about is that 200 (not 403) means the binding accepted.
    assert response.status_code == 200


def test_tenant_scoped_key_cannot_authorize_in_other_tenant(make_client):
    """The bug Codex flagged: tenant:<A> calling authorize on <B>."""
    client = make_client()
    tenants, apps = _seed_two_tenants(client)
    tenant_a, tenant_b = tenants
    _, app_b = apps

    key_a = client.post(
        "/v1/api-keys",
        json={"name": "tenant_a-runtime", "scopes": [f"tenant:{tenant_a['id']}"]},
        headers=BOOTSTRAP_HEADERS,
    ).json()["key"]

    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant_b["id"],
            "application_id": app_b["id"],
            "subject": {"type": "user", "user_id": "anyone"},
            "resource": "docs",
            "action": "read",
        },
        headers={"X-API-Key": key_a},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "tenant_scope_mismatch"


def test_tenant_scoped_key_cannot_bulk_authorize_in_other_tenant(make_client):
    client = make_client()
    tenants, apps = _seed_two_tenants(client)
    tenant_a, tenant_b = tenants
    _, app_b = apps

    key_a = client.post(
        "/v1/api-keys",
        json={"name": "tenant_a-runtime", "scopes": [f"tenant:{tenant_a['id']}"]},
        headers=BOOTSTRAP_HEADERS,
    ).json()["key"]

    response = client.post(
        "/v1/bulk-authorize",
        json={
            "tenant_id": tenant_b["id"],
            "application_id": app_b["id"],
            "subject": {"type": "user", "user_id": "u"},
            "checks": [{"resource": "docs", "action": "read"}],
        },
        headers={"X-API-Key": key_a},
    )
    assert response.status_code == 403


def test_tenant_scoped_key_cannot_read_effective_permissions_in_other_tenant(
    make_client,
):
    client = make_client()
    tenants, apps = _seed_two_tenants(client)
    tenant_a, tenant_b = tenants
    _, app_b = apps

    key_a = client.post(
        "/v1/api-keys",
        json={"name": "tenant_a-runtime", "scopes": [f"tenant:{tenant_a['id']}"]},
        headers=BOOTSTRAP_HEADERS,
    ).json()["key"]

    response = client.post(
        "/v1/effective-permissions",
        json={
            "tenant_id": tenant_b["id"],
            "application_id": app_b["id"],
            "subject": {"type": "user", "user_id": "u"},
        },
        headers={"X-API-Key": key_a},
    )
    assert response.status_code == 403


def test_runtime_scope_key_unrestricted_across_tenants(make_client):
    """Plain runtime keys are intentionally tenant-agnostic."""
    client = make_client()
    tenants, apps = _seed_two_tenants(client)
    tenant_a, tenant_b = tenants
    _, app_b = apps

    runtime_key = client.post(
        "/v1/api-keys",
        json={"name": "runtime", "scopes": ["runtime"]},
        headers=BOOTSTRAP_HEADERS,
    ).json()["key"]

    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant_b["id"],
            "application_id": app_b["id"],
            "subject": {"type": "user", "user_id": "u"},
            "resource": "docs",
            "action": "read",
        },
        headers={"X-API-Key": runtime_key},
    )
    assert response.status_code == 200


def test_admin_bootstrap_key_unrestricted_across_tenants(make_client):
    client = make_client()
    tenants, apps = _seed_two_tenants(client)
    _, tenant_b = tenants
    _, app_b = apps
    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant_b["id"],
            "application_id": app_b["id"],
            "subject": {"type": "user", "user_id": "u"},
            "resource": "docs",
            "action": "read",
        },
        headers=BOOTSTRAP_HEADERS,
    )
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# P1.2 — idempotency partitioning
# ---------------------------------------------------------------------------


def test_bearer_clients_with_same_idempotency_key_do_not_share_cache(make_client):
    """Two clients using ``Authorization: Bearer`` with different keys but
    the same Idempotency-Key must each see their own response, not a
    replay of the first caller's.
    """
    client = make_client()
    # Issue two distinct admin keys
    k1 = client.post(
        "/v1/api-keys",
        json={"name": "first", "scopes": ["admin"]},
        headers=BOOTSTRAP_HEADERS,
    ).json()["key"]
    k2 = client.post(
        "/v1/api-keys",
        json={"name": "second", "scopes": ["admin"]},
        headers=BOOTSTRAP_HEADERS,
    ).json()["key"]

    headers1 = {
        "Authorization": f"Bearer {k1}",
        "Idempotency-Key": "shared-key",
    }
    headers2 = {
        "Authorization": f"Bearer {k2}",
        "Idempotency-Key": "shared-key",
    }

    r1 = client.post(
        "/v1/tenants", json={"slug": "alpha", "name": "Alpha"}, headers=headers1
    )
    r2 = client.post(
        "/v1/tenants", json={"slug": "beta", "name": "Beta"}, headers=headers2
    )
    assert r1.status_code == 201
    assert r2.status_code == 201
    # Each caller sees the response their own POST produced — no replay.
    assert r1.json()["slug"] == "alpha"
    assert r2.json()["slug"] == "beta"
    assert "Idempotent-Replay" not in r1.headers
    assert "Idempotent-Replay" not in r2.headers


def test_same_bearer_client_replays_on_repeat_idempotency_key(make_client):
    """Same caller (same bearer credential) gets the cached response."""
    client = make_client()
    k = client.post(
        "/v1/api-keys",
        json={"name": "k", "scopes": ["admin"]},
        headers=BOOTSTRAP_HEADERS,
    ).json()["key"]
    headers = {"Authorization": f"Bearer {k}", "Idempotency-Key": "dup-1"}
    body = {"slug": "gamma", "name": "Gamma"}
    r1 = client.post("/v1/tenants", json=body, headers=headers)
    r2 = client.post("/v1/tenants", json=body, headers=headers)
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json() == r2.json()
    assert r2.headers.get("Idempotent-Replay") == "true"


def test_xapi_and_bearer_with_same_value_do_not_collide(make_client):
    """Even if a caller routes the same secret through different headers,
    the cache partitions are independent because the fingerprint
    encodes which header carried the value.
    """
    client = make_client()
    headers_xapi = {
        "X-API-Key": "bootstrap-key",
        "Idempotency-Key": "boundary-test",
    }
    headers_bearer = {
        "Authorization": "Bearer bootstrap-key",
        "Idempotency-Key": "boundary-test",
    }
    r1 = client.post(
        "/v1/tenants",
        json={"slug": "delta", "name": "Delta"},
        headers=headers_xapi,
    )
    r2 = client.post(
        "/v1/tenants",
        json={"slug": "epsilon", "name": "Epsilon"},
        headers=headers_bearer,
    )
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["slug"] == "delta"
    assert r2.json()["slug"] == "epsilon"
