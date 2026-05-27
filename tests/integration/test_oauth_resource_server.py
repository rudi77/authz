"""Integration tests for the OAuth Resource-Server JWT path.

Spins up a TestClient against a fresh SQLite, configures one trusted
external issuer (JWKS pre-seeded into the resolver — no live HTTP), then
exercises the runtime endpoints with both API keys and JWT bearers.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

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

ISSUER = "https://idp.example/v2"
AUDIENCE = "api://authz"
ADMIN_KEY = "bootstrap-admin"


def _rsa_pair() -> tuple[str, dict[str, Any], str]:
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
def signing(tmp_path_factory):
    """Reuse one RSA pair across tests in this file — generation is slow."""
    pem, jwk, kid = _rsa_pair()
    return pem, jwk, kid


@pytest.fixture()
def client(temp_db_url, signing):
    pem, jwk, kid = signing
    issuers_json = json.dumps(
        [
            {
                "issuer": ISSUER,
                "audience": AUDIENCE,
                "scope_claim": "scope",
                "scope_separator": " ",
                "tenant_claim": "tenant_id",
            }
        ]
    )
    override_settings(
        Settings(
            database_url=temp_db_url,
            api_keys=(ADMIN_KEY,),
            log_level="WARNING",
            oauth_resource_issuers_json=issuers_json,
        )
    )
    reset_engine()
    from authz_service.main import create_app

    app = create_app()
    # Force the resolver's JWKS cache so it never hits the network.
    from authz_service.dependencies import get_jwt_resolver, get_settings, get_signing_key_service
    from authzkit.storage.sqlalchemy import SqlAlchemyStore

    settings = get_settings()
    from authz_service.dependencies import get_engine

    engine = get_engine(settings)
    store = SqlAlchemyStore(engine)
    sk_svc = get_signing_key_service(store, settings)
    resolver = get_jwt_resolver(settings, sk_svc)
    assert resolver is not None
    resolver._validator._jwks_cache[ISSUER] = (
        {"keys": [jwk]},
        time.monotonic() + 600,
    )
    yield TestClient(app)


def _seed_tenant(client: TestClient) -> tuple[str, str, str]:
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
    client.post(
        f"/v1/applications/{app['id']}/permissions",
        json={"name": "contracts.read"},
        headers={"X-API-Key": ADMIN_KEY},
    )
    role = client.post(
        f"/v1/applications/{app['id']}/roles",
        json={"name": "reader", "scope": "application"},
        headers={"X-API-Key": ADMIN_KEY},
    ).json()
    client.put(
        f"/v1/roles/{role['id']}/permissions",
        json={"permissions": ["contracts.read"]},
        headers={"X-API-Key": ADMIN_KEY},
    )
    return tenant["id"], app["id"], role["id"]


def _make_token(pem: str, kid: str, **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
        "iat": now,
        "sub": "user-1",
        "scope": "runtime",
    }
    claims.update(overrides)
    return pyjwt.encode(claims, pem, algorithm="RS256", headers={"kid": kid})


def test_jwt_bearer_passes_runtime_endpoint(client, signing):
    pem, _jwk, kid = signing
    tenant_id, _app, _ = _seed_tenant(client)
    token = _make_token(pem, kid)
    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant_id,
            "application_id": "contracts",
            "subject": {"type": "user", "user_id": "u"},
            "resource": "contracts",
            "action": "read",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    # No membership exists yet so the engine denies — but reaching the engine
    # at all proves the bearer was accepted.
    assert response.status_code == 200


def test_bearer_with_wrong_audience_is_rejected(client, signing):
    pem, _jwk, kid = signing
    token = _make_token(pem, kid, aud="api://other")
    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": "any",
            "application_id": "x",
            "subject": {"type": "user", "user_id": "u"},
            "resource": "r",
            "action": "a",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert "Bearer" in response.headers["WWW-Authenticate"]


def test_bearer_with_unknown_issuer_returns_401(client, signing):
    pem, _jwk, kid = signing
    token = _make_token(pem, kid, iss="https://stranger.example")
    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": "any",
            "application_id": "x",
            "subject": {"type": "user", "user_id": "u"},
            "resource": "r",
            "action": "a",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


def test_tenant_claim_mismatch_rejects_with_403(client, signing):
    """Token bound to tenant A must not be accepted for tenant B."""
    pem, _jwk, kid = signing
    tenant_id, _app, _ = _seed_tenant(client)
    token = _make_token(pem, kid, scope="", tenant_id="other-tenant")
    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant_id,
            "application_id": "contracts",
            "subject": {"type": "user", "user_id": "u"},
            "resource": "contracts",
            "action": "read",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    body = response.json()
    assert body["detail"]["error"] == "tenant_scope_mismatch"


def test_x_api_key_wins_over_bearer_jwt(client, signing):
    """When both headers are present, X-API-Key takes precedence."""
    pem, _jwk, kid = signing
    tenant_id, _app, _ = _seed_tenant(client)
    # Bogus JWT but valid X-API-Key — should succeed via the API-key path.
    response = client.post(
        "/v1/authorize",
        json={
            "tenant_id": tenant_id,
            "application_id": "contracts",
            "subject": {"type": "user", "user_id": "u"},
            "resource": "contracts",
            "action": "read",
        },
        headers={
            "X-API-Key": ADMIN_KEY,
            "Authorization": "Bearer not-a-real-jwt.it.fails",
        },
    )
    assert response.status_code == 200


def test_admin_scope_jwt_can_reach_admin_endpoints(client, signing):
    pem, _jwk, kid = signing
    token = _make_token(pem, kid, scope="admin")
    response = client.get(
        "/v1/api-keys",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
