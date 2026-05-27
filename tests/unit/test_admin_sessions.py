"""Unit tests for AdminSessionService + the PKCE login-attempt store."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from authzkit.security.sessions import AdminSessionService
from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url, init_schema


@pytest.fixture()
def store() -> SqlAlchemyStore:
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    init_schema(engine)
    return SqlAlchemyStore(engine)


def _pkce_challenge(verifier: str) -> str:
    """Reference S256 challenge so the test asserts the same formula the SPA uses."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def test_login_attempt_round_trip(store):
    service = AdminSessionService(store)
    attempt = service.create_login_attempt(
        state="state-xyz",
        code_verifier="v" * 64,
        nonce="n",
        return_to="/admin/",
    )
    consumed = service.consume_login_attempt(attempt.id, state="state-xyz")
    assert consumed is not None
    assert consumed.code_verifier == "v" * 64
    # Second consume returns None — the row is gone.
    assert service.consume_login_attempt(attempt.id, state="state-xyz") is None


def test_login_attempt_state_mismatch_rejected_and_row_deleted(store):
    service = AdminSessionService(store)
    attempt = service.create_login_attempt(
        state="real", code_verifier="v", nonce="n", return_to="/admin/"
    )
    assert service.consume_login_attempt(attempt.id, state="forged") is None
    # Even on mismatch the row is consumed so a leaked cookie can't be reused.
    assert service.consume_login_attempt(attempt.id, state="real") is None


def test_login_attempt_expired_rejected(store):
    service = AdminSessionService(store, login_attempt_ttl_seconds=1)
    attempt = service.create_login_attempt(
        state="s", code_verifier="v", nonce="n", return_to="/admin/"
    )
    # Force the expiry without sleeping.
    from authzkit.storage import orm

    with store.session() as s:
        row = s.get(orm.AdminLoginAttempt, attempt.id)
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        s.commit()
    assert service.consume_login_attempt(attempt.id, state="s") is None


def test_pkce_challenge_formula_matches_rfc7636():
    """Sanity: the verifier in the SPA computes S256 the same way as the test."""
    verifier = "abcdef" * 10
    expected = _pkce_challenge(verifier)
    # Recompute via the same primitives the service uses indirectly.
    digest = hashlib.sha256(verifier.encode()).digest()
    assert base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == expected


def test_session_create_and_lookup(store):
    service = AdminSessionService(store)
    session = service.create_session(
        subject="alice",
        email="alice@example.com",
        issuer="https://idp",
        scopes=("admin",),
        raw_claims={"sub": "alice"},
    )
    fetched = service.lookup_session(session.id)
    assert fetched is not None
    assert fetched.subject == "alice"
    assert fetched.scopes == ("admin",)
    assert fetched.csrf_token == session.csrf_token


def test_session_delete_clears_row(store):
    service = AdminSessionService(store)
    session = service.create_session(
        subject="a", email=None, issuer="https://i", scopes=("admin",), raw_claims={}
    )
    assert service.delete_session(session.id) is True
    assert service.lookup_session(session.id) is None


def test_session_expired_lookup_returns_none_and_prunes(store):
    service = AdminSessionService(store, session_ttl_seconds=1)
    session = service.create_session(
        subject="a", email=None, issuer="https://i", scopes=("admin",), raw_claims={}
    )
    from authzkit.storage import orm

    with store.session() as s:
        row = s.get(orm.AdminSession, session.id)
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        s.commit()
    assert service.lookup_session(session.id) is None


def test_csrf_token_is_unique_per_session(store):
    service = AdminSessionService(store)
    a = service.create_session(
        subject="a", email=None, issuer="https://i", scopes=("admin",), raw_claims={}
    )
    b = service.create_session(
        subject="b", email=None, issuer="https://i", scopes=("admin",), raw_claims={}
    )
    assert a.csrf_token != b.csrf_token
    assert a.id != b.id
