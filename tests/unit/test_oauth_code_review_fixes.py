"""Regression tests for the 2026-05 code-review fixes.

Each test names the finding it pins. Failures here mean a fix regressed.
Unit-level (no FastAPI app) — see ``tests/integration/test_oauth_code_review_fixes.py``
for the end-to-end equivalents.
"""

from __future__ import annotations

import logging

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")


# ---------------------------------------------------------------------------
# #1 — Bearer / Basic trailing-space crash
# ---------------------------------------------------------------------------


def test_extract_credential_handles_bare_bearer_keyword():
    """`Authorization: Bearer ` (trailing space, no token) must not crash."""
    from authz_service.dependencies import _extract_credential

    assert _extract_credential("Bearer ", None) is None
    assert _extract_credential("bearer\t", None) is None  # tab only
    assert _extract_credential("Bearer", None) is None  # no separator at all


def test_parse_basic_auth_handles_bare_basic_keyword():
    from authz_service.api.oauth import _parse_basic_auth

    assert _parse_basic_auth("Basic ") is None
    assert _parse_basic_auth("Basic") is None
    assert _parse_basic_auth("basic\t") is None


# ---------------------------------------------------------------------------
# #11 — scope_map dropping mapped values that aren't in vocabulary
# ---------------------------------------------------------------------------


def test_scope_map_warns_when_mapped_target_is_unknown(caplog):
    """Operator's explicit scope_map target outside vocab should log a warning."""
    from authzkit.security.oauth_resource import IssuerConfig, _map_scopes

    cfg = IssuerConfig(
        issuer="https://idp",
        audience="api",
        scope_map={"AuthZ.Reader": "reader"},  # 'reader' is not internal
    )
    with caplog.at_level(logging.WARNING, logger="authz.oauth_resource"):
        scopes = _map_scopes({"scope": "AuthZ.Reader"}, cfg)
    assert scopes == ()
    assert any("not a recognised internal scope" in r.message for r in caplog.records)


def test_scope_map_does_not_warn_for_unmapped_unknown_scopes():
    """Unmapped unknown scopes (e.g. random extra claim values) are silently dropped."""
    from authzkit.security.oauth_resource import IssuerConfig, _map_scopes

    cfg = IssuerConfig(issuer="https://idp", audience="api")
    # 'random-thing' isn't mapped and isn't internal — drop silently, no log.
    assert _map_scopes({"scope": "admin random-thing"}, cfg) == ("admin",)


def test_extract_tenant_rejects_non_string_claim(caplog):
    """tenant_claim that resolves to a list / dict must yield None, not f-string garbage."""
    from authzkit.security.oauth_resource import IssuerConfig, _extract_tenant

    cfg = IssuerConfig(issuer="https://idp", audience="api", tenant_claim="tid")
    with caplog.at_level(logging.WARNING, logger="authz.oauth_resource"):
        assert _extract_tenant({"tid": ["a", "b"]}, cfg) is None
        assert _extract_tenant({"tid": {"complex": "object"}}, cfg) is None
    # Integers are accepted (some IdPs emit numeric tenant ids).
    assert _extract_tenant({"tid": 42}, cfg) == "42"


# ---------------------------------------------------------------------------
# #12 — self-issuer / external-issuer collision
# ---------------------------------------------------------------------------


def test_self_issuer_collision_with_external_config_raises():
    """JwtResolver __init__ must refuse a duplicate config for the self issuer."""
    from authzkit.security.oauth_resource import IssuerConfig, JwtResolver

    external = IssuerConfig(
        issuer="https://authz.local",
        audience="api",
        scope_claim="scp",  # non-default — operator intends a real mapping
        tenant_claim="custom_tid",
    )
    with pytest.raises(ValueError, match="self-issuer"):
        JwtResolver(
            [external],
            self_issuer="https://authz.local",
            self_jwks_provider=lambda: {"keys": []},
        )


def test_self_issuer_with_default_config_is_accepted():
    """Auto-injected self config (defaults) must not trigger the collision guard."""
    from authzkit.security.oauth_resource import IssuerConfig, JwtResolver

    # This is the exact shape dependencies.py auto-injects.
    auto = IssuerConfig(
        issuer="https://authz.local",
        audience="https://authz.local",
        scope_claim="scope",
        tenant_claim="tenant_id",
    )
    resolver = JwtResolver(
        [auto],
        self_issuer="https://authz.local",
        self_jwks_provider=lambda: {"keys": []},
    )
    assert "https://authz.local" in resolver.issuers


# ---------------------------------------------------------------------------
# #13 — multi-audience config
# ---------------------------------------------------------------------------


def test_multi_audience_token_accepts_any_listed_audience():
    """Token with aud='api://secondary' validates when audience=['primary','secondary']."""
    import hashlib
    import time

    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from authzkit.identity.jwt_validation import JWTValidator
    from authzkit.security.oauth_resource import IssuerConfig, JwtResolver
    from authzkit.security.signing_keys import _b64url_uint

    # Build a keypair + JWK.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
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

    cfg = IssuerConfig(
        issuer="https://idp",
        audience=("api://primary", "api://secondary"),
    )
    # Build a validator with the JWKS pre-seeded so no HTTP fires.
    from authzkit.identity.jwt_validation import JWTValidatorConfig

    validator = JWTValidator(
        [
            JWTValidatorConfig(
                issuer="https://idp",
                audience=cfg.audience,
            )
        ]
    )
    validator._jwks_cache["https://idp"] = ({"keys": [jwk]}, time.monotonic() + 600)
    resolver = JwtResolver([cfg], validator=validator)
    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": "https://idp",
            "aud": "api://secondary",  # the *second* audience — previously rejected
            "exp": now + 3600,
            "iat": now,
            "sub": "u",
            "scope": "runtime",
        },
        pem,
        algorithm="RS256",
        headers={"kid": kid},
    )
    principal = resolver.resolve(token)
    assert principal.scopes == ("runtime",)


# ---------------------------------------------------------------------------
# #14 — tz coercion on SQLite roundtrip
# ---------------------------------------------------------------------------


def test_lookup_session_returns_aware_datetimes():
    """SQLite naive timestamps must be coerced before they leave the service."""
    from datetime import UTC, datetime

    from authzkit.security.sessions import AdminSessionService
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url, init_schema

    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    init_schema(engine)
    store = SqlAlchemyStore(engine)
    svc = AdminSessionService(store)
    s = svc.create_session(
        subject="alice",
        email=None,
        issuer="https://i",
        scopes=("admin",),
        raw_claims={},
    )
    fetched = svc.lookup_session(s.id)
    assert fetched is not None
    # All three datetime fields must be aware so comparisons against
    # datetime.now(UTC) don't TypeError.
    assert fetched.expires_at.tzinfo is not None
    assert fetched.created_at.tzinfo is not None
    assert fetched.last_seen_at is not None and fetched.last_seen_at.tzinfo is not None
    # Sanity: comparison works.
    assert fetched.expires_at > datetime.now(UTC)


def test_oauth_client_record_returns_aware_datetimes():
    from datetime import UTC, datetime, timedelta

    from authzkit.security.oauth_clients import OAuthClientService
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url, init_schema

    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    init_schema(engine)
    store = SqlAlchemyStore(engine)
    svc = OAuthClientService(store)
    credentials = svc.issue(
        name="demo",
        scopes=["runtime"],
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    # Authenticate once to populate last_used_at.
    svc.authenticate(credentials.record.client_id, credentials.client_secret)
    rec = svc.get(credentials.record.client_id)
    assert rec is not None
    assert rec.created_at is not None and rec.created_at.tzinfo is not None
    assert rec.expires_at is not None and rec.expires_at.tzinfo is not None
    assert rec.last_used_at is not None and rec.last_used_at.tzinfo is not None
    # Comparison against tz-aware now doesn't crash.
    assert rec.expires_at > datetime.now(UTC)


# ---------------------------------------------------------------------------
# #8 — signing-key rotate concurrency + partial unique index
# ---------------------------------------------------------------------------


def test_signing_key_partial_unique_index_blocks_second_active_insert():
    """Defence in depth — even if the row lock is bypassed, the index catches it."""
    from sqlalchemy.exc import IntegrityError

    from authzkit.security.signing_keys import _generate_rsa_keypair
    from authzkit.storage import orm
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url, init_schema

    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    init_schema(engine)
    store = SqlAlchemyStore(engine)
    # First active insert succeeds.
    pem1, jwk1 = _generate_rsa_keypair()
    with store.session() as s:
        s.add(
            orm.OAuthSigningKey(
                kid=jwk1["kid"],
                alg="RS256",
                public_jwk=jwk1,
                private_pem=pem1,
                status="active",
            )
        )
        s.commit()
    # Second active insert must fail at the DB level.
    pem2, jwk2 = _generate_rsa_keypair()
    with pytest.raises(IntegrityError), store.session() as s:
        s.add(
            orm.OAuthSigningKey(
                kid=jwk2["kid"],
                alg="RS256",
                public_jwk=jwk2,
                private_pem=pem2,
                status="active",
            )
        )
        s.commit()


def test_signing_key_rotate_keeps_one_active_under_partial_index():
    """The supported rotate path must still work — flush() ordering matters."""
    from sqlalchemy import select

    from authzkit.security.signing_keys import SigningKeyService
    from authzkit.storage import orm
    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url, init_schema

    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    init_schema(engine)
    store = SqlAlchemyStore(engine)
    svc = SigningKeyService(
        store, dev_mode=True, database_url="sqlite+pysqlite:///:memory:"
    )
    _first = svc.active_signing_key()
    second = svc.rotate()
    third = svc.rotate()
    # After two rotations there must be exactly one active row.
    with store.session() as s:
        active = s.scalars(
            select(orm.OAuthSigningKey).where(orm.OAuthSigningKey.status == "active")
        ).all()
        assert len(active) == 1
        assert active[0].kid == third.kid
        # And the previous two are retiring.
        retiring = s.scalars(
            select(orm.OAuthSigningKey).where(
                orm.OAuthSigningKey.status == "retiring"
            )
        ).all()
        assert len(retiring) == 2
        assert second.kid in {r.kid for r in retiring}
