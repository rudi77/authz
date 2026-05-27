"""End-to-end: a token from /oauth/token validates on /v1/authorize in the same process."""

from __future__ import annotations

import base64

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine

ISSUER = "https://authz.local"
ADMIN_KEY = "bootstrap-admin"


@pytest.fixture()
def client(temp_db_url) -> TestClient:
    override_settings(
        Settings(
            database_url=temp_db_url,
            api_keys=(ADMIN_KEY,),
            log_level="WARNING",
            dev_mode=True,
            oauth_as_enabled=True,
            oauth_issuer=ISSUER,
            oauth_audience=ISSUER,
        )
    )
    reset_engine()
    from authz_service.main import create_app

    return TestClient(create_app())


def test_self_issued_token_validates_on_runtime_endpoint(client):
    # Bootstrap data path: tenant + application + permission + role.
    tenant = client.post(
        "/v1/tenants",
        json={"slug": "acme", "name": "ACME"},
        headers={"X-API-Key": ADMIN_KEY},
    ).json()
    app = client.post(
        "/v1/applications",
        json={"slug": "contracts", "name": "Contracts"},
        headers={"X-API-Key": ADMIN_KEY},
    ).json()
    # OAuth client — admin scope so it can reach /v1/authorize and pass tenant binding.
    created = client.post(
        "/v1/oauth/clients",
        json={"name": "demo", "scopes": ["admin"]},
        headers={"X-API-Key": ADMIN_KEY},
    ).json()
    # Mint a token via /oauth/token.
    raw = f"{created['client_id']}:{created['client_secret']}".encode()
    token_resp = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        headers={
            "Authorization": "Basic " + base64.b64encode(raw).decode("ascii")
        },
    )
    assert token_resp.status_code == 200, token_resp.text
    access_token = token_resp.json()["access_token"]
    # Present the same token to a runtime endpoint — bypasses HTTP loopback
    # because the resolver reads JWKS from the local SigningKeyService.
    resp = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant["id"],
            "application_id": app["id"],
            "subject": {"type": "user", "user_id": "u"},
            "resource": "contracts",
            "action": "read",
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 200, resp.text
