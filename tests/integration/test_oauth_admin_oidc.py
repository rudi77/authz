"""Integration tests for the admin OIDC login flow.

Stubs the external IdP via httpx transport — discovery, token exchange,
JWKS — so the whole login/callback can run offline. Covers the happy
path, bad-state rejection, group/email allowlist enforcement, CSRF on
mutating session calls, and logout invalidation.
"""

from __future__ import annotations

import hashlib
import time

import httpx
import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine
from authzkit.security.signing_keys import _b64url_uint

IDP_ISSUER = "https://idp.test"
CLIENT_ID = "admin-ui"
CLIENT_SECRET = "shh"
REDIRECT_URI = "http://testserver/oauth/callback"


@pytest.fixture()
def idp_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    nums = key.public_key().public_numbers()
    kid = hashlib.sha256(pem.encode()).hexdigest()[:16]
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(nums.n),
        "e": _b64url_uint(nums.e),
    }
    return pem, jwk, kid


@pytest.fixture()
def idp_state():
    """Mutable per-test state the stub IdP transport reads from."""
    return {
        "id_token_claims": None,
        "captured_callback": None,
    }


@pytest.fixture()
def httpx_stub(monkeypatch, idp_keys, idp_state):
    """Patch httpx.Client.get/post used by the admin OIDC router."""
    pem, jwk, _kid = idp_keys

    real_get = httpx.Client.get
    real_post = httpx.Client.post

    def fake_get(self, url, *args, **kwargs):
        if url.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": IDP_ISSUER,
                    "authorization_endpoint": f"{IDP_ISSUER}/auth",
                    "token_endpoint": f"{IDP_ISSUER}/token",
                    "jwks_uri": f"{IDP_ISSUER}/jwks",
                },
            )
        if url.endswith("/jwks"):
            return httpx.Response(200, json={"keys": [jwk]})
        return real_get(self, url, *args, **kwargs)

    def fake_post(self, url, *args, **kwargs):
        if url == f"{IDP_ISSUER}/token":
            id_token = pyjwt.encode(
                idp_state["id_token_claims"],
                pem,
                algorithm="RS256",
                headers={"kid": jwk["kid"]},
            )
            return httpx.Response(
                200,
                json={"access_token": "ignored", "id_token": id_token},
            )
        return real_post(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "get", fake_get)
    monkeypatch.setattr(httpx.Client, "post", fake_post)
    # Bust caches from previous tests (discovery + validator JWKS).
    from authz_service.api import oauth as oauth_mod

    oauth_mod.reset_admin_oidc()


@pytest.fixture()
def client(temp_db_url, httpx_stub) -> TestClient:
    override_settings(
        Settings(
            database_url=temp_db_url,
            api_keys=("bootstrap",),
            log_level="WARNING",
            dev_mode=True,
            admin_oidc_enabled="true",
            admin_oidc_issuer=IDP_ISSUER,
            admin_oidc_client_id=CLIENT_ID,
            admin_oidc_client_secret=CLIENT_SECRET,
            admin_oidc_redirect_uri=REDIRECT_URI,
            admin_oidc_groups_claim="groups",
            admin_oidc_admin_groups=("authz-admins",),
        )
    )
    reset_engine()
    from authz_service.main import create_app

    return TestClient(create_app(), follow_redirects=False)


def _do_login(client: TestClient, idp_state, *, groups=("authz-admins",)):
    """Drive /oauth/login → /oauth/callback with stubbed IdP. Returns the cookie jar."""
    login = client.get("/oauth/login")
    assert login.status_code == 302
    # The stub captures the state via the redirect URL's query string.
    from urllib.parse import parse_qs, urlparse

    qs = parse_qs(urlparse(login.headers["location"]).query)
    state = qs["state"][0]
    nonce = qs["nonce"][0]
    now = int(time.time())
    idp_state["id_token_claims"] = {
        "iss": IDP_ISSUER,
        "aud": CLIENT_ID,
        "sub": "alice",
        "email": "alice@example.com",
        "groups": list(groups),
        "nonce": nonce,
        "exp": now + 3600,
        "iat": now,
    }
    callback = client.get(
        "/oauth/callback",
        params={"code": "the-code", "state": state},
    )
    return callback


def test_login_callback_happy_path_sets_session_cookie(client, idp_state):
    response = _do_login(client, idp_state)
    assert response.status_code == 302
    assert "authz_session" in client.cookies
    # Probe the session and verify the principal info.
    probe = client.get("/admin/session")
    assert probe.status_code == 200
    body = probe.json()
    assert body["authenticated"] is True
    assert body["kind"] == "session"
    assert body["email"] == "alice@example.com"
    assert body["is_admin"] is True
    assert "csrf_token" in body


def test_callback_with_bad_state_rejects(client, idp_state):
    # Kick off a login to get the cookie + a real state value.
    login = client.get("/oauth/login")
    assert login.status_code == 302
    # Use a forged state — the row was created for the real state.
    callback = client.get(
        "/oauth/callback",
        params={"code": "x", "state": "forged-value"},
    )
    assert callback.status_code == 400
    assert callback.json()["detail"]["error"] == "invalid_state"


def test_callback_with_no_admin_group_returns_403(client, idp_state):
    response = _do_login(client, idp_state, groups=("everyone-else",))
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "admin_access_denied"


def test_csrf_token_required_for_mutating_session_calls(client, idp_state):
    _do_login(client, idp_state)
    # Mutating call without CSRF header — must be rejected.
    response = client.post(
        "/v1/tenants",
        json={"slug": "x", "name": "x"},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "csrf_token_required"


def test_csrf_token_accepted_when_supplied(client, idp_state):
    _do_login(client, idp_state)
    csrf = client.get("/admin/session").json()["csrf_token"]
    response = client.post(
        "/v1/tenants",
        json={"slug": "acme", "name": "ACME"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 201, response.text


def test_logout_invalidates_session(client, idp_state):
    _do_login(client, idp_state)
    cookie = client.cookies.get("authz_session")
    assert cookie is not None
    csrf = client.get("/admin/session").json()["csrf_token"]
    # Logout is mutating, so the SPA always echoes the CSRF token.
    client.post("/oauth/logout", headers={"X-CSRF-Token": csrf})
    # Reusing the old cookie should now fail.
    client.cookies.set("authz_session", cookie)
    probe = client.get("/admin/session")
    assert probe.status_code == 401
