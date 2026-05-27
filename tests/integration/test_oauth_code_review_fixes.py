"""Integration regression tests for the 2026-05 code-review fixes."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

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

ADMIN_KEY = "bootstrap"
EXTERNAL_ISSUER = "https://idp.example/v2"
EXTERNAL_AUDIENCE = "api"


def _rsa_pair():
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


@pytest.fixture(scope="module")
def signing():
    """Module-scoped so RSA generation only runs once for this file."""
    return _rsa_pair()


def _build_client(temp_db_url: str, signing, **overrides) -> TestClient:
    issuers_json = json.dumps(
        [
            {
                "issuer": EXTERNAL_ISSUER,
                "audience": EXTERNAL_AUDIENCE,
                "scope_claim": "scope",
                "tenant_claim": "tid",
            }
        ]
    )
    settings_kwargs = dict(
        database_url=temp_db_url,
        api_keys=(ADMIN_KEY,),
        log_level="WARNING",
        oauth_resource_issuers_json=issuers_json,
    )
    settings_kwargs.update(overrides)
    override_settings(Settings(**settings_kwargs))
    reset_engine()
    # Reset admin-OIDC caches too — they survive across tests in the same
    # process and a leftover validator can mask the SUT.
    try:
        from authz_service.api import oauth as _oauth_mod

        _oauth_mod.reset_admin_oidc()
    except ImportError:
        pass
    from authz_service.main import create_app

    app = create_app()
    # Pre-seed the JWKS cache so no live HTTP.
    pem, jwk, _kid = signing
    from authz_service.dependencies import (
        get_engine,
        get_jwt_resolver,
        get_settings,
        get_signing_key_service,
    )
    from authzkit.storage.sqlalchemy import SqlAlchemyStore

    s = get_settings()
    engine = get_engine(s)
    store = SqlAlchemyStore(engine)
    resolver = get_jwt_resolver(s, get_signing_key_service(store, s))
    if resolver is not None:
        resolver._validator._jwks_cache[EXTERNAL_ISSUER] = (
            {"keys": [jwk]},
            time.monotonic() + 600,
        )
    return TestClient(app, follow_redirects=False)


# ---------------------------------------------------------------------------
# #1 — Bearer trailing-space → 401, not 500
# ---------------------------------------------------------------------------


def test_malformed_bearer_returns_401_not_500(temp_db_url, signing):
    client = _build_client(temp_db_url, signing)
    # 'Bearer ' (trailing space, empty token).
    r = client.post(
        "/v1/authorize",
        json={
            "tenant_id": "x",
            "application_id": "y",
            "subject": {"type": "user", "user_id": "u"},
            "resource": "r",
            "action": "a",
        },
        headers={"Authorization": "Bearer "},
    )
    assert r.status_code == 401
    # Just 'Bearer' (no separator).
    r = client.post(
        "/v1/authorize",
        json={
            "tenant_id": "x",
            "application_id": "y",
            "subject": {"type": "user", "user_id": "u"},
            "resource": "r",
            "action": "a",
        },
        headers={"Authorization": "Bearer"},
    )
    assert r.status_code == 401


def test_malformed_basic_on_token_endpoint_returns_401_not_500(temp_db_url, signing):
    client = _build_client(
        temp_db_url,
        signing,
        dev_mode=True,
        oauth_as_enabled=True,
        oauth_issuer="https://authz.test",
    )
    r = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": "Basic "},
    )
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_client"


# ---------------------------------------------------------------------------
# #2 — rate-limit on /oauth/token form body no longer drains the body
# ---------------------------------------------------------------------------


def test_oauth_token_with_form_body_works_under_rate_limit(temp_db_url, signing):
    client = _build_client(
        temp_db_url,
        signing,
        dev_mode=True,
        oauth_as_enabled=True,
        oauth_issuer="https://authz.test",
        rate_limit_per_minute=100,
    )
    created = client.post(
        "/v1/oauth/clients",
        json={"name": "demo", "scopes": ["runtime"]},
        headers={"X-API-Key": ADMIN_KEY},
    ).json()
    # client_secret_post: credentials in form body, not Authorization header.
    r = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": created["client_id"],
            "client_secret": created["client_secret"],
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["token_type"] == "Bearer"


# ---------------------------------------------------------------------------
# #3 — /oauth/logout requires CSRF for session-authenticated callers
# ---------------------------------------------------------------------------


def test_oauth_logout_without_csrf_rejects_session_caller(temp_db_url, signing):
    """Build a session manually and POST /oauth/logout with no CSRF header."""
    client = _build_client(
        temp_db_url,
        signing,
        dev_mode=True,
        admin_oidc_enabled="true",
        admin_oidc_issuer="https://idp.test",
        admin_oidc_client_id="cli",
        admin_oidc_client_secret="shh",
        admin_oidc_redirect_uri="http://testserver/oauth/callback",
    )
    from authz_service.dependencies import (
        get_admin_session_service,
        get_engine,
        get_settings,
    )
    from authzkit.storage.sqlalchemy import SqlAlchemyStore

    s = get_settings()
    engine = get_engine(s)
    store = SqlAlchemyStore(engine)
    sessions = get_admin_session_service(store, s)
    session = sessions.create_session(
        subject="alice",
        email="alice@test",
        issuer="https://idp.test",
        scopes=("admin",),
        raw_claims={},
    )
    client.cookies.set("authz_session", session.id)
    # Without CSRF header → must be rejected.
    r = client.post("/oauth/logout")
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"] == "csrf_token_required"
    # With CSRF header → succeeds.
    r = client.post("/oauth/logout", headers={"X-CSRF-Token": session.csrf_token})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# #4 — idempotency partition includes the session cookie
# ---------------------------------------------------------------------------


def test_idempotency_partition_distinct_for_distinct_sessions(temp_db_url, signing):
    """Two different admin sessions must not share an Idempotency-Key bucket."""
    # Build two minimal Request objects (Starlette test client request shape).
    from starlette.requests import Request as StarletteRequest

    from authz_service.middleware import _credential_partition

    def fake_req(cookie_value: str) -> StarletteRequest:
        scope = {
            "type": "http",
            "headers": [(b"cookie", f"authz_session={cookie_value}".encode())],
        }
        return StarletteRequest(scope)

    a = _credential_partition(fake_req("alice-cookie"))
    b = _credential_partition(fake_req("bob-cookie"))
    assert a != b
    same = _credential_partition(fake_req("alice-cookie"))
    assert a == same


# ---------------------------------------------------------------------------
# #5 — JWT tenant_id claim is enforced even with 'runtime' scope
# ---------------------------------------------------------------------------


def test_jwt_tenant_pin_blocks_cross_tenant_runtime(temp_db_url, signing):
    pem, _jwk, kid = signing
    client = _build_client(temp_db_url, signing)
    # Seed two tenants.
    tenant_a = client.post(
        "/v1/tenants",
        json={"slug": "tenant-a", "name": "A"},
        headers={"X-API-Key": ADMIN_KEY},
    ).json()
    tenant_b = client.post(
        "/v1/tenants",
        json={"slug": "tenant-b", "name": "B"},
        headers={"X-API-Key": ADMIN_KEY},
    ).json()
    app = client.post(
        "/v1/applications",
        json={"slug": "x", "name": "X"},
        headers={"X-API-Key": ADMIN_KEY},
    ).json()
    now = int(time.time())
    # Token pinned to tenant-a but carrying broad 'runtime' scope.
    token = pyjwt.encode(
        {
            "iss": EXTERNAL_ISSUER,
            "aud": EXTERNAL_AUDIENCE,
            "exp": now + 3600,
            "iat": now,
            "sub": "u",
            "scope": "runtime",
            "tid": tenant_a["id"],
        },
        pem,
        algorithm="RS256",
        headers={"kid": kid},
    )
    body = {
        "tenant_id": tenant_b["id"],  # different tenant
        "application_id": app["id"],
        "subject": {"type": "user", "user_id": "u"},
        "resource": "r",
        "action": "a",
    }
    r = client.post(
        "/v1/authorize", json=body, headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"] == "tenant_scope_mismatch"
    # Same token against the matching tenant works.
    body["tenant_id"] = tenant_a["id"]
    r = client.post(
        "/v1/authorize", json=body, headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# #6 — protocol-relative return_to is rejected
# ---------------------------------------------------------------------------


def test_open_redirect_protocol_relative_return_to_is_neutralised(
    temp_db_url, signing, monkeypatch
):
    """`return_to=//evil.com/x` must NOT survive into the eventual redirect."""
    # Stub OIDC discovery; fall through for every other URL so the
    # TestClient's own httpx.Client (also routed through this method)
    # still talks to the in-process app rather than getting fake 404s.
    real_get = httpx.Client.get

    def fake_get(self, url, *args, **kwargs):
        if url.endswith("/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": "https://idp.test",
                    "authorization_endpoint": "https://idp.test/auth",
                    "token_endpoint": "https://idp.test/token",
                    "jwks_uri": "https://idp.test/jwks",
                },
            )
        return real_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "get", fake_get)
    from authz_service.api import oauth as oauth_mod

    oauth_mod.reset_admin_oidc()
    client = _build_client(
        temp_db_url,
        signing,
        dev_mode=True,
        admin_oidc_enabled="true",
        admin_oidc_issuer="https://idp.test",
        admin_oidc_client_id="cli",
        admin_oidc_client_secret="shh",
        admin_oidc_redirect_uri="http://testserver/oauth/callback",
    )
    for malicious in ("//evil.com/x", "/\\evil.com/x", "https://evil.com/x"):
        r = client.get("/oauth/login", params={"return_to": malicious})
        assert r.status_code == 302
        # Look up the stored attempt and confirm return_to was sanitised.
        from authz_service.dependencies import get_engine, get_settings
        from authzkit.storage import orm
        from authzkit.storage.sqlalchemy import SqlAlchemyStore

        s = get_settings()
        engine = get_engine(s)
        store = SqlAlchemyStore(engine)
        with store.session() as session:
            attempts = (
                session.query(orm.AdminLoginAttempt)
                .order_by(orm.AdminLoginAttempt.created_at.desc())
                .all()
            )
            assert attempts, "expected at least one login attempt"
            assert attempts[0].return_to == "/admin/"


# ---------------------------------------------------------------------------
# #7 — email allowlist requires email_verified
# ---------------------------------------------------------------------------


def test_admin_oidc_email_allowlist_requires_verified_email(
    temp_db_url, signing, monkeypatch
):
    pem, jwk, kid = signing
    real_get = httpx.Client.get
    real_post = httpx.Client.post

    def fake_get(self, url, *args, **kwargs):
        if url.endswith("/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": "https://idp.test",
                    "authorization_endpoint": "https://idp.test/auth",
                    "token_endpoint": "https://idp.test/token",
                    "jwks_uri": "https://idp.test/jwks",
                },
            )
        if url.endswith("/jwks"):
            return httpx.Response(200, json={"keys": [jwk]})
        return real_get(self, url, *args, **kwargs)

    state_holder: dict[str, Any] = {"claims": None}

    def fake_post(self, url, *args, **kwargs):
        if url == "https://idp.test/token":
            id_token = pyjwt.encode(
                state_holder["claims"], pem, algorithm="RS256", headers={"kid": kid}
            )
            return httpx.Response(200, json={"access_token": "x", "id_token": id_token})
        return real_post(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "get", fake_get)
    monkeypatch.setattr(httpx.Client, "post", fake_post)
    from authz_service.api import oauth as oauth_mod

    oauth_mod.reset_admin_oidc()

    client = _build_client(
        temp_db_url,
        signing,
        dev_mode=True,
        admin_oidc_enabled="true",
        admin_oidc_issuer="https://idp.test",
        admin_oidc_client_id="cli",
        admin_oidc_client_secret="shh",
        admin_oidc_redirect_uri="http://testserver/oauth/callback",
        admin_oidc_groups_claim="groups",
        admin_oidc_admin_groups=(),  # disable group path
        admin_oidc_email_allowlist=("alice@example.com",),
    )

    def run_callback(claims: dict[str, Any]):
        from urllib.parse import parse_qs, urlparse

        login = client.get("/oauth/login")
        qs = parse_qs(urlparse(login.headers["location"]).query)
        state = qs["state"][0]
        nonce = qs["nonce"][0]
        now = int(time.time())
        state_holder["claims"] = {
            "iss": "https://idp.test",
            "aud": "cli",
            "sub": "alice",
            "nonce": nonce,
            "exp": now + 3600,
            "iat": now,
            **claims,
        }
        return client.get(
            "/oauth/callback", params={"code": "c", "state": state}
        )

    # Without email_verified → 403.
    r = run_callback({"email": "alice@example.com"})
    assert r.status_code == 403

    # email_verified=false → 403.
    r = run_callback({"email": "alice@example.com", "email_verified": False})
    assert r.status_code == 403

    # email_verified=true → success (302 redirect, session set).
    r = run_callback({"email": "alice@example.com", "email_verified": True})
    assert r.status_code == 302

    # email_verified=true + case mismatch → still accepted (allowlist is case-insensitive).
    r = run_callback({"email": "Alice@EXAMPLE.com", "email_verified": True})
    assert r.status_code == 302


# ---------------------------------------------------------------------------
# #9 — admin OIDC JWTValidator is shared across callbacks
# ---------------------------------------------------------------------------


def test_admin_jwks_cache_shared_across_callbacks(temp_db_url, signing, monkeypatch):
    """Multiple /oauth/callback hits must reuse one JWTValidator + JWKS cache."""
    pem, jwk, kid = signing
    jwks_fetches = {"n": 0}
    real_get = httpx.Client.get
    real_post = httpx.Client.post

    def fake_get(self, url, *args, **kwargs):
        if url.endswith("/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": "https://idp.test",
                    "authorization_endpoint": "https://idp.test/auth",
                    "token_endpoint": "https://idp.test/token",
                    "jwks_uri": "https://idp.test/jwks",
                },
            )
        if url.endswith("/jwks"):
            jwks_fetches["n"] += 1
            return httpx.Response(200, json={"keys": [jwk]})
        return real_get(self, url, *args, **kwargs)

    state_holder: dict[str, Any] = {}

    def fake_post(self, url, *args, **kwargs):
        if url == "https://idp.test/token":
            id_token = pyjwt.encode(
                state_holder["claims"], pem, algorithm="RS256", headers={"kid": kid}
            )
            return httpx.Response(200, json={"access_token": "x", "id_token": id_token})
        return real_post(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "get", fake_get)
    monkeypatch.setattr(httpx.Client, "post", fake_post)
    from authz_service.api import oauth as oauth_mod

    oauth_mod.reset_admin_oidc()
    client = _build_client(
        temp_db_url,
        signing,
        dev_mode=True,
        admin_oidc_enabled="true",
        admin_oidc_issuer="https://idp.test",
        admin_oidc_client_id="cli",
        admin_oidc_client_secret="shh",
        admin_oidc_redirect_uri="http://testserver/oauth/callback",
        admin_oidc_groups_claim="groups",
        admin_oidc_admin_groups=("admins",),
    )

    from urllib.parse import parse_qs, urlparse

    for _ in range(3):
        login = client.get("/oauth/login")
        qs = parse_qs(urlparse(login.headers["location"]).query)
        state, nonce = qs["state"][0], qs["nonce"][0]
        now = int(time.time())
        state_holder["claims"] = {
            "iss": "https://idp.test",
            "aud": "cli",
            "sub": "alice",
            "groups": ["admins"],
            "nonce": nonce,
            "exp": now + 3600,
            "iat": now,
        }
        r = client.get("/oauth/callback", params={"code": "c", "state": state})
        assert r.status_code == 302
        # Clear the session cookie between iterations so we hit /oauth/login again.
        client.cookies.clear()

    # Three logins should fetch JWKS at most once thanks to the shared cache.
    assert jwks_fetches["n"] == 1, (
        f"expected 1 JWKS fetch shared across callbacks, got {jwks_fetches['n']}"
    )


# ---------------------------------------------------------------------------
# #10 — OIDC discovery cache TTL'd, can be reset for tests
# ---------------------------------------------------------------------------


def test_oidc_discovery_cache_can_be_reset():
    """The test hook must actually clear both caches."""
    from authz_service.api import oauth as oauth_mod

    oauth_mod._OIDC_DISCOVERY_CACHE["https://x"] = ({"a": 1}, time.monotonic() + 1000)
    oauth_mod._ADMIN_VALIDATORS[("https://x", "aud")] = object()  # type: ignore[assignment]
    oauth_mod.reset_admin_oidc()
    assert "https://x" not in oauth_mod._OIDC_DISCOVERY_CACHE
    assert ("https://x", "aud") not in oauth_mod._ADMIN_VALIDATORS
