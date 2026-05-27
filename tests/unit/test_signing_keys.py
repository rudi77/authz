"""Unit tests for SigningKeyService."""

from __future__ import annotations

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

import jwt as pyjwt

from authzkit.security.signing_keys import SigningKeyError, SigningKeyService, _generate_rsa_keypair
from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url, init_schema


@pytest.fixture()
def store() -> SqlAlchemyStore:
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    init_schema(engine)
    return SqlAlchemyStore(engine)


def test_env_supplied_pem_is_used_and_kid_is_stable(store):
    """Two services constructed with the same PEM must agree on the kid."""
    pem, _jwk = _generate_rsa_keypair()
    svc_a = SigningKeyService(store, env_pem=pem)
    svc_b = SigningKeyService(store, env_pem=pem)
    assert svc_a.active_signing_key().kid == svc_b.active_signing_key().kid


def test_env_supplied_signing_roundtrip(store):
    pem, _jwk = _generate_rsa_keypair()
    service = SigningKeyService(store, env_pem=pem)
    token = service.sign({"iss": "self", "sub": "x", "scope": "admin"})
    public_jwk = service.active_signing_key().public_jwk
    public_key = pyjwt.PyJWK(public_jwk).key
    claims = pyjwt.decode(token, public_key, algorithms=["RS256"], options={"verify_aud": False})
    assert claims["sub"] == "x"


def test_dev_sqlite_generates_ephemeral_key(store):
    """No PEM, no DB key, dev mode + SQLite ⇒ key auto-generated."""
    service = SigningKeyService(
        store, dev_mode=True, database_url="sqlite+pysqlite:///:memory:"
    )
    key = service.active_signing_key()
    assert key.status == "active"
    assert key.alg == "RS256"
    # Persisted: a fresh service against the same store sees the key.
    fresh = SigningKeyService(store)
    assert fresh.active_signing_key().kid == key.kid


def test_no_key_and_non_dev_mode_raises(store):
    service = SigningKeyService(store, dev_mode=False)
    with pytest.raises(SigningKeyError, match="No OAuth signing key"):
        service.active_signing_key()


def test_no_key_dev_mode_but_postgres_dsn_raises(store):
    """Postgres DSN must never trigger ephemeral key generation."""
    service = SigningKeyService(
        store,
        dev_mode=True,
        database_url="postgresql://localhost/authz",
    )
    with pytest.raises(SigningKeyError, match="No OAuth signing key"):
        service.active_signing_key()


def test_rotation_demotes_current_active_and_serves_both_jwks(store):
    service = SigningKeyService(
        store, dev_mode=True, database_url="sqlite+pysqlite:///:memory:"
    )
    first = service.active_signing_key()
    second = service.rotate()
    assert second.kid != first.kid
    jwks = service.all_public_jwks()
    kids = {k["kid"] for k in jwks["keys"]}
    assert first.kid in kids
    assert second.kid in kids


def test_rotation_with_env_pem_refuses(store):
    pem, _ = _generate_rsa_keypair()
    service = SigningKeyService(store, env_pem=pem)
    with pytest.raises(SigningKeyError, match="deploying a new value"):
        service.rotate()


def test_signed_token_validates_against_published_jwks(store):
    """JWKS export uses the same public material the signer holds."""
    service = SigningKeyService(
        store, dev_mode=True, database_url="sqlite+pysqlite:///:memory:"
    )
    token = service.sign({"iss": "self", "sub": "x", "scope": "runtime"})
    header = pyjwt.get_unverified_header(token)
    jwks = service.all_public_jwks()
    matching = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    claims = pyjwt.decode(
        token,
        pyjwt.PyJWK(matching).key,
        algorithms=["RS256"],
        options={"verify_aud": False},
    )
    assert claims["sub"] == "x"
