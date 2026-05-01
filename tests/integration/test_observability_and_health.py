"""Health-check, metrics, idempotency, and rate-limit tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine


@pytest.fixture()
def make_client(temp_db_url):
    """Return a factory that builds a fresh TestClient with custom settings."""

    def _make(**overrides) -> TestClient:
        defaults = dict(
            database_url=temp_db_url,
            api_keys=("k1",),
            log_level="WARNING",
            audit_all_decisions=False,
            auto_provision_user=True,
            auto_provision_tenant=False,
            cors_allow_origins=("*",),
            rate_limit_per_minute=0,
        )
        defaults.update(overrides)
        override_settings(Settings(**defaults))
        reset_engine()
        from authz_service.main import create_app

        return TestClient(create_app())

    return _make


def test_healthz_returns_db_status(make_client):
    client = make_client()
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"


def test_healthz_503_when_db_unreachable(make_client, monkeypatch):
    """Force ``SELECT 1`` to raise at runtime and check the 503 response.

    We can't simply point at an invalid URL because schema-init runs at
    engine-create time and would fail before the test reaches /healthz.
    """
    client = make_client()
    # First call materializes the engine via the dependency; second call hits
    # the broken connect() to verify the 503 path.
    assert client.get("/healthz").status_code == 200

    from authz_service import dependencies

    real_engine = dependencies._engine
    assert real_engine is not None

    class _BrokenConnection:
        def __enter__(self):
            raise RuntimeError("simulated DB outage")

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(real_engine, "connect", lambda: _BrokenConnection())
    response = client.get("/healthz")
    assert response.status_code == 503


def test_metrics_endpoint_exposes_counters(make_client):
    client = make_client()
    # Trigger at least one request so counters are non-zero.
    client.get("/healthz")
    response = client.get("/metrics")
    assert response.status_code == 200
    body = response.text
    assert "authz_http_requests_total" in body
    assert "authz_http_request_duration_seconds" in body


def test_idempotency_key_replays_response(make_client):
    client = make_client()
    headers = {"X-API-Key": "k1", "Idempotency-Key": "tenant-create-1"}
    body = {"slug": "idem", "name": "Idem"}

    first = client.post("/v1/tenants", json=body, headers=headers)
    assert first.status_code == 201
    first_payload = first.json()

    # Second call replays the cached response — no second insert.
    second = client.post("/v1/tenants", json=body, headers=headers)
    assert second.status_code == 201
    assert second.json() == first_payload
    assert second.headers.get("Idempotent-Replay") == "true"

    # Without the idempotency key, the unique slug constraint would normally
    # bite us. So a different key must hit the live handler.
    third = client.post(
        "/v1/tenants",
        json={"slug": "idem-2", "name": "Other"},
        headers={"X-API-Key": "k1", "Idempotency-Key": "tenant-create-2"},
    )
    assert third.status_code == 201
    assert third.json()["slug"] == "idem-2"


def test_rate_limit_enforces_limit(make_client):
    client = make_client(rate_limit_per_minute=2)
    headers = {"X-API-Key": "k1"}

    assert client.get("/healthz", headers=headers).status_code == 200
    assert client.get("/healthz", headers=headers).status_code == 200
    third = client.get("/healthz", headers=headers)
    assert third.status_code == 429
    assert third.json()["error"] == "rate_limited"
    assert third.headers.get("Retry-After") is not None


def test_request_id_is_propagated(make_client):
    client = make_client()
    response = client.get("/healthz", headers={"X-Request-Id": "abc-123"})
    assert response.headers.get("X-Request-Id") == "abc-123"

    response = client.get("/healthz")
    assert response.headers.get("X-Request-Id")  # auto-generated
