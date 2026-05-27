"""Integration tests for the Authorization-Server role.

Walks the full ``client_credentials`` flow: seed an OAuth client, hit
``/oauth/token`` with both Basic and form-body auth, verify the issued
JWT against the published JWKS, and exercise the error paths
(invalid_client, invalid_scope, unsupported_grant_type).
"""

from __future__ import annotations

import base64

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

import jwt as pyjwt
from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine

ISSUER = "https://authz.test"
ADMIN_KEY = "bootstrap-admin"


@pytest.fixture()
def client(temp_db_url):
    override_settings(
        Settings(
            database_url=temp_db_url,
            api_keys=(ADMIN_KEY,),
            log_level="WARNING",
            dev_mode=True,  # to allow ephemeral signing key on SQLite
            oauth_as_enabled=True,
            oauth_issuer=ISSUER,
            oauth_audience=ISSUER,
            oauth_access_token_ttl_seconds=300,
        )
    )
    reset_engine()
    from authz_service.main import create_app

    return TestClient(create_app())


def _basic(client_id: str, secret: str) -> str:
    raw = f"{client_id}:{secret}".encode()
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _issue_oauth_client(
    client: TestClient, *, scopes: list[str], tenant_id: str | None = None
):
    body = {"name": "demo", "scopes": scopes}
    if tenant_id is not None:
        body["tenant_id"] = tenant_id
    resp = client.post(
        "/v1/oauth/clients",
        json=body,
        headers={"X-API-Key": ADMIN_KEY},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_metadata_endpoint_shape(client):
    """RFC 8414 metadata advertises the right grant + auth methods."""
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    body = resp.json()
    assert body["issuer"] == ISSUER
    assert body["token_endpoint"].endswith("/oauth/token")
    assert body["jwks_uri"].endswith("/.well-known/jwks.json")
    assert body["grant_types_supported"] == ["client_credentials"]
    assert set(body["token_endpoint_auth_methods_supported"]) == {
        "client_secret_basic",
        "client_secret_post",
    }


def test_jwks_endpoint_returns_public_keys(client):
    """First call bootstraps the dev signing key; JWKS exposes its public half."""
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body.get("keys"), list)


def test_client_credentials_happy_path_basic_auth(client):
    created = _issue_oauth_client(client, scopes=["runtime"])
    resp = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": _basic(created["client_id"], created["client_secret"])},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 300
    assert body["scope"] == "runtime"
    # Token validates against the published JWKS.
    header = pyjwt.get_unverified_header(body["access_token"])
    jwks = client.get("/.well-known/jwks.json").json()
    matching = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    claims = pyjwt.decode(
        body["access_token"],
        pyjwt.PyJWK(matching).key,
        algorithms=["RS256"],
        audience=ISSUER,
        issuer=ISSUER,
    )
    assert claims["client_id"] == created["client_id"]
    assert "jti" in claims
    assert claims["scope"] == "runtime"


def test_client_credentials_happy_path_form_body(client):
    created = _issue_oauth_client(client, scopes=["runtime"])
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": created["client_id"],
            "client_secret": created["client_secret"],
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["scope"] == "runtime"


def test_invalid_client_returns_401(client):
    resp = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": _basic("oc_unknown", "bad")},
    )
    assert resp.status_code == 401
    body = resp.json()
    assert body["error"] == "invalid_client"
    assert resp.headers.get("WWW-Authenticate", "").startswith("Basic")


def test_invalid_scope_returns_400(client):
    created = _issue_oauth_client(client, scopes=["runtime"])
    resp = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "admin"},
        headers={"Authorization": _basic(created["client_id"], created["client_secret"])},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"


def test_unsupported_grant_type_returns_400(client):
    created = _issue_oauth_client(client, scopes=["runtime"])
    resp = client.post(
        "/oauth/token",
        data={"grant_type": "password"},
        headers={"Authorization": _basic(created["client_id"], created["client_secret"])},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"


def test_tenant_bound_client_cannot_request_cross_tenant_scope(client):
    """Scope-downscoping bug here = cross-tenant escape — explicit guard test."""
    created = _issue_oauth_client(
        client, scopes=["runtime", "tenant:acme"], tenant_id="acme"
    )
    resp = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "tenant:other"},
        headers={"Authorization": _basic(created["client_id"], created["client_secret"])},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"


def test_tenant_bound_client_token_carries_tenant_claim(client):
    created = _issue_oauth_client(
        client, scopes=["runtime"], tenant_id="acme-uuid"
    )
    resp = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": _basic(created["client_id"], created["client_secret"])},
    )
    assert resp.status_code == 200
    body = resp.json()
    # Decode without verification — we already trust the signer in this process.
    claims = pyjwt.decode(
        body["access_token"], options={"verify_signature": False}
    )
    assert claims["tenant_id"] == "acme-uuid"
