"""Tests for the fail-closed defaults introduced in the security hardening pass.

Two themes:

1. Dev mode is opt-in. With no API keys and ``AUTHZ_DEV_MODE`` unset,
   the service rejects every request. Setting ``AUTHZ_DEV_MODE=true``
   restores the legacy "accept any caller" passthrough.
2. CORS=* is rejected at startup unless ``AUTHZ_DEV_MODE=true``.
"""

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
            api_keys=(),
            log_level="WARNING",
            audit_all_decisions=False,
            auto_provision_user=True,
            auto_provision_tenant=False,
            cors_allow_origins=(),
            rate_limit_per_minute=0,
            dev_mode=False,
        )
        defaults.update(overrides)
        override_settings(Settings(**defaults))
        reset_engine()
        from authz_service.main import create_app

        return TestClient(create_app())

    return _make


# ---------------------------------------------------------------------------
# Fail-closed dev mode
# ---------------------------------------------------------------------------


def test_no_keys_and_no_dev_mode_rejects_every_request(make_client):
    client = make_client()  # no api_keys, no dev_mode
    response = client.post(
        "/v1/tenants", json={"slug": "x", "name": "X"}
    )
    assert response.status_code == 401
    assert response.json()["detail"]["error"] == "missing_or_invalid_api_key"


def test_no_keys_and_no_dev_mode_rejects_runtime_endpoints(make_client):
    client = make_client()
    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": "t",
            "application_id": "a",
            "subject": {"type": "user", "user_id": "u"},
            "resource": "docs",
            "action": "read",
        },
    )
    assert response.status_code == 401


def test_dev_mode_true_accepts_any_caller_when_no_keys(make_client):
    client = make_client(dev_mode=True)
    # No header at all — accepted because dev mode synthesises an admin record.
    response = client.post("/v1/tenants", json={"slug": "x", "name": "X"})
    assert response.status_code == 201


def test_dev_mode_true_with_env_keys_still_enforces(make_client):
    """The escape hatch only applies when zero keys are configured.

    With env keys present, the service must enforce them even with
    AUTHZ_DEV_MODE=true. This protects against a misconfigured deploy
    that ships both flags.
    """
    client = make_client(dev_mode=True, api_keys=("real-key",))
    response = client.post(
        "/v1/tenants",
        json={"slug": "x", "name": "X"},
    )
    assert response.status_code == 401

    response = client.post(
        "/v1/tenants",
        json={"slug": "x", "name": "X"},
        headers={"X-API-Key": "real-key"},
    )
    assert response.status_code == 201


def test_first_db_key_locks_down_even_with_dev_mode(make_client):
    """Once a real key exists, dev-mode passthrough is disabled.

    The auto-lockdown is intentional: a forgotten test deployment
    flipping into "real" use should not stay in dev mode just because
    the flag is set.
    """
    # Bootstrap with env key + dev mode so we can issue the DB key
    client = make_client(dev_mode=True, api_keys=("bootstrap",))
    issued = client.post(
        "/v1/api-keys",
        json={"name": "first", "scopes": ["admin"]},
        headers={"X-API-Key": "bootstrap"},
    ).json()
    new_key = issued["key"]

    # Now drop the env key; dev mode is still on but a DB key exists.
    client = make_client(dev_mode=True, api_keys=())
    # A request without credentials must be rejected.
    response = client.post(
        "/v1/tenants",
        json={"slug": "x", "name": "X"},
    )
    assert response.status_code == 401
    # The newly-issued key still works.
    response = client.post(
        "/v1/tenants",
        json={"slug": "x", "name": "X"},
        headers={"X-API-Key": new_key},
    )
    assert response.status_code == 201


# ---------------------------------------------------------------------------
# CORS hardening
# ---------------------------------------------------------------------------


def test_cors_wildcard_without_dev_mode_refuses_to_start(make_client):
    with pytest.raises(RuntimeError, match="AUTHZ_CORS_ORIGINS"):
        make_client(cors_allow_origins=("*",), dev_mode=False, api_keys=("k",))


def test_cors_wildcard_with_dev_mode_starts(make_client):
    client = make_client(
        cors_allow_origins=("*",), dev_mode=True, api_keys=("k",)
    )
    # Smoke check that the app is up.
    assert client.get("/healthz").status_code == 200


def test_cors_explicit_origin_without_dev_mode_starts(make_client):
    client = make_client(
        cors_allow_origins=("https://admin.example.com",),
        dev_mode=False,
        api_keys=("k",),
    )
    assert client.get("/healthz").status_code == 200


def test_cors_empty_origins_without_dev_mode_starts(make_client):
    """The new default — empty CORS origins — must always start."""
    client = make_client(cors_allow_origins=(), dev_mode=False, api_keys=("k",))
    assert client.get("/healthz").status_code == 200


# ---------------------------------------------------------------------------
# AUTHZ_DEV_MODE env-var parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        # Truthy: only the literal "true" (case-insensitive) flips the bit.
        ("true", True),
        ("TRUE", True),
        ("True", True),
        # Falsy / fail-closed defaults.
        ("false", False),
        ("", False),
        # Anything that isn't exactly "true" must stay False so a typo can't
        # accidentally enable dev mode.
        ("1", False),
        ("yes", False),
        ("on", False),
        ("enabled", False),
        ("treu", False),  # typo
        ("True ", False),  # trailing whitespace, not stripped
    ],
)
def test_dev_mode_env_parser_is_strict(monkeypatch, raw, expected):
    from authz_service.config import Settings

    monkeypatch.setenv("AUTHZ_DEV_MODE", raw)
    assert Settings().dev_mode is expected


def test_dev_mode_env_parser_unset_defaults_to_false(monkeypatch):
    from authz_service.config import Settings

    monkeypatch.delenv("AUTHZ_DEV_MODE", raising=False)
    assert Settings().dev_mode is False
