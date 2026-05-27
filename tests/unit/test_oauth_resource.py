"""Unit tests for the OAuth Resource-Server JWT resolver.

Verifies claim → internal-scope mapping, multi-issuer dispatch, tenant
extraction, and the unknown-issuer / wrong-audience failure modes. No live
network — the validator's ``_get_jwks`` is monkey-patched with a stub
that returns a deterministic JWK so signature verification stays offline.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from authzkit.identity.jwt_validation import JWTValidationError, JWTValidator
from authzkit.security.oauth_resource import IssuerConfig, JwtResolver, _map_scopes


def _rsa_pair() -> tuple[str, dict[str, Any], str]:
    """Return ``(pem, public_jwk, kid)`` — same shape SigningKeyService produces."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    import hashlib

    from authzkit.security.signing_keys import _b64url_uint

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


def _make_validator_with_jwks(issuer: str, audience: str, jwks: dict) -> JWTValidator:
    """Build a JWTValidator and pre-seed its JWKS cache so it never hits the network."""
    from authzkit.identity.jwt_validation import JWTValidatorConfig

    validator = JWTValidator(
        [JWTValidatorConfig(issuer=issuer, audience=audience)],
    )
    validator._jwks_cache[issuer] = (jwks, time.monotonic() + 600)
    return validator


def _issue(pem: str, kid: str, claims: dict) -> str:
    return pyjwt.encode(claims, pem, algorithm="RS256", headers={"kid": kid})


def test_scope_mapping_space_separated_string():
    """Default OIDC ``scope`` claim: space-separated string, no mapping."""
    cfg = IssuerConfig(issuer="https://i", audience="api")
    scopes = _map_scopes({"scope": "runtime tenant:acme"}, cfg)
    assert scopes == ("runtime", "tenant:acme")


def test_scope_mapping_list_claim():
    """Entra-style ``scp`` claim that is already a list."""
    cfg = IssuerConfig(
        issuer="https://i",
        audience="api",
        scope_claim="scp",
        scope_separator=None,
    )
    scopes = _map_scopes({"scp": ["admin"]}, cfg)
    assert scopes == ("admin",)


def test_scope_mapping_external_to_internal_via_map():
    """External names are translated through ``scope_map`` then filtered."""
    cfg = IssuerConfig(
        issuer="https://i",
        audience="api",
        scope_map={"AuthZ.Admin": "admin", "AuthZ.Runtime": "runtime"},
    )
    scopes = _map_scopes({"scope": "AuthZ.Admin Other.Stuff"}, cfg)
    assert scopes == ("admin",)


def test_scope_mapping_drops_unknown_internal_surfaces():
    """Anything other than admin/runtime/tenant:* is silently dropped."""
    cfg = IssuerConfig(issuer="https://i", audience="api")
    scopes = _map_scopes({"scope": "admin bogus.thing tenant:x"}, cfg)
    assert scopes == ("admin", "tenant:x")


def test_scope_mapping_missing_claim_returns_empty():
    cfg = IssuerConfig(issuer="https://i", audience="api")
    assert _map_scopes({}, cfg) == ()


def test_resolve_happy_path_with_external_issuer():
    pem, jwk, kid = _rsa_pair()
    issuer = "https://idp.example/"
    audience = "api://authz"
    cfg = IssuerConfig(
        issuer=issuer,
        audience=audience,
        scope_claim="scp",
        scope_separator=None,
    )
    validator = _make_validator_with_jwks(issuer, audience, {"keys": [jwk]})
    resolver = JwtResolver([cfg], validator=validator)
    now = int(time.time())
    token = _issue(
        pem,
        kid,
        {
            "iss": issuer,
            "aud": audience,
            "exp": now + 3600,
            "iat": now,
            "sub": "user-1",
            "scp": ["runtime"],
            "tid": "ext-tenant-1",
            "azp": "client-x",
        },
    )
    principal = resolver.resolve(token)
    assert principal.issuer == issuer
    assert principal.subject == "user-1"
    assert principal.scopes == ("runtime",)
    assert principal.tenant_id == "ext-tenant-1"
    assert principal.client_id == "client-x"


def test_resolve_implicit_tenant_scope_when_no_other_scopes():
    """A pure tenant-bound token gets an implicit tenant:<id> scope."""
    pem, jwk, kid = _rsa_pair()
    issuer = "https://idp.example/"
    audience = "api"
    cfg = IssuerConfig(issuer=issuer, audience=audience)
    validator = _make_validator_with_jwks(issuer, audience, {"keys": [jwk]})
    resolver = JwtResolver([cfg], validator=validator)
    now = int(time.time())
    token = _issue(
        pem,
        kid,
        {
            "iss": issuer,
            "aud": audience,
            "exp": now + 3600,
            "iat": now,
            "sub": "user-2",
            "tid": "acme-uuid",
        },
    )
    principal = resolver.resolve(token)
    assert principal.scopes == ("tenant:acme-uuid",)
    assert principal.tenant_id == "acme-uuid"


def test_resolve_unknown_issuer_raises():
    cfg = IssuerConfig(issuer="https://known", audience="api")
    resolver = JwtResolver(
        [cfg],
        validator=_make_validator_with_jwks("https://known", "api", {"keys": []}),
    )
    pem, _jwk, kid = _rsa_pair()
    token = _issue(
        pem,
        kid,
        {
            "iss": "https://stranger",
            "aud": "api",
            "exp": int(time.time()) + 3600,
            "sub": "x",
        },
    )
    with pytest.raises(JWTValidationError, match="unknown issuer"):
        resolver.resolve(token)


def test_resolve_multi_issuer_routes_by_iss_claim():
    pem_a, jwk_a, kid_a = _rsa_pair()
    pem_b, jwk_b, kid_b = _rsa_pair()
    cfg_a = IssuerConfig(issuer="https://a", audience="api")
    cfg_b = IssuerConfig(issuer="https://b", audience="api")
    val = _make_validator_with_jwks("https://a", "api", {"keys": [jwk_a]})
    val._jwks_cache["https://b"] = ({"keys": [jwk_b]}, time.monotonic() + 600)
    # Register both configs on the validator so it knows about both audiences.
    from authzkit.identity.jwt_validation import JWTValidatorConfig

    val._configs["https://b"] = JWTValidatorConfig(issuer="https://b", audience="api")
    resolver = JwtResolver([cfg_a, cfg_b], validator=val)
    now = int(time.time())
    token_b = _issue(
        pem_b,
        kid_b,
        {"iss": "https://b", "aud": "api", "exp": now + 3600, "sub": "u", "scope": "admin"},
    )
    principal = resolver.resolve(token_b)
    assert principal.issuer == "https://b"
    assert principal.scopes == ("admin",)


def test_resolve_wrong_audience_raises():
    pem, jwk, kid = _rsa_pair()
    issuer = "https://i"
    cfg = IssuerConfig(issuer=issuer, audience="api://expected")
    val = _make_validator_with_jwks(issuer, "api://expected", {"keys": [jwk]})
    resolver = JwtResolver([cfg], validator=val)
    token = _issue(
        pem,
        kid,
        {
            "iss": issuer,
            "aud": "api://other",
            "exp": int(time.time()) + 3600,
            "sub": "u",
        },
    )
    with pytest.raises(JWTValidationError):
        resolver.resolve(token)
