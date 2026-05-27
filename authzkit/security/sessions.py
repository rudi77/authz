"""Server-side admin sessions for the OIDC login flow.

Two tables back this module:

- ``admin_login_attempts`` — short-lived rows holding the PKCE
  ``code_verifier``, the ``state``, and the ``nonce`` between the
  authorization redirect and the callback. Looked up by the
  ``authz_login_id`` cookie so the verifier never travels through the
  browser.
- ``admin_sessions`` — the actual session row keyed by the random cookie
  value; carries the CSRF token and the resolved admin scopes.

Both share a janitor sweep (:meth:`AdminSessionService.prune_expired`) so
expired rows don't accumulate.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from authzkit.security.principal import SessionPrincipal


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    """Coerce a SQLite-roundtripped naive datetime to tz-aware UTC.

    SQLite has no native tz storage; SQLAlchemy returns naive datetimes
    even when the column was written aware. Mixing aware ``expires_at``
    with naive ``created_at`` on the same dataclass raises TypeError on
    any comparison.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _new_token(num_bytes: int = 32) -> str:
    return secrets.token_urlsafe(num_bytes)


@dataclass(frozen=True)
class LoginAttempt:
    """The verifier/state/nonce triple stashed across the IdP round trip."""

    id: str            # cookie value
    state: str
    code_verifier: str
    nonce: str
    return_to: str
    expires_at: datetime


@dataclass(frozen=True)
class AdminSession:
    """Persisted admin browser session."""

    id: str
    subject: str
    email: str | None
    issuer: str
    scopes: tuple[str, ...]
    raw_claims: dict[str, Any]
    csrf_token: str
    created_at: datetime
    expires_at: datetime
    last_seen_at: datetime | None


class AdminSessionService:
    """Persist and look up pending logins + active sessions."""

    def __init__(
        self,
        store: Any,
        *,
        session_ttl_seconds: int = 28800,
        login_attempt_ttl_seconds: int = 600,
    ) -> None:
        self.store = store
        self._session_ttl = session_ttl_seconds
        self._attempt_ttl = login_attempt_ttl_seconds

    # ----- login attempts --------------------------------------------------

    def create_login_attempt(
        self,
        *,
        state: str,
        code_verifier: str,
        nonce: str,
        return_to: str,
    ) -> LoginAttempt:
        """Persist the in-flight PKCE state, return the row + its cookie id."""
        from authzkit.storage import orm

        cookie_id = _new_token()
        expires = _now() + timedelta(seconds=self._attempt_ttl)
        with self.store.session() as s:
            row = orm.AdminLoginAttempt(
                id=cookie_id,
                state=state,
                code_verifier=code_verifier,
                nonce=nonce,
                return_to=return_to,
                expires_at=expires,
            )
            s.add(row)
            s.commit()
        return LoginAttempt(
            id=cookie_id,
            state=state,
            code_verifier=code_verifier,
            nonce=nonce,
            return_to=return_to,
            expires_at=expires,
        )

    def consume_login_attempt(self, cookie_id: str, *, state: str) -> LoginAttempt | None:
        """Look up + delete the attempt; reject on state mismatch or expiry.

        Deletion is part of consumption — even a state-mismatched attempt
        gets removed so a leaked cookie can't be replayed against the right
        state value later.

        Concurrency: ``SELECT ... FOR UPDATE`` ensures that two parallel
        ``/oauth/callback`` requests for the same cookie serialize and
        only one wins. Without the lock, Postgres READ COMMITTED would let
        both transactions read the same row and both proceed to mint a
        session — turning a single-use PKCE attempt into two sessions.
        SQLite ignores the lock hint and serializes via its db-level
        write lock, which is equivalent in the single-writer case.
        """
        from sqlalchemy import select

        from authzkit.storage import orm

        with self.store.session() as s:
            row = s.scalars(
                select(orm.AdminLoginAttempt)
                .where(orm.AdminLoginAttempt.id == cookie_id)
                .with_for_update()
            ).first()
            if row is None:
                return None
            s.delete(row)
            s.commit()
            if row.state != state:
                return None
            expires = _aware(row.expires_at)
            assert expires is not None
            if expires < _now():
                return None
            return LoginAttempt(
                id=row.id,
                state=row.state,
                code_verifier=row.code_verifier,
                nonce=row.nonce,
                return_to=row.return_to,
                expires_at=expires,
            )

    # ----- active sessions -------------------------------------------------

    def create_session(
        self,
        *,
        subject: str,
        email: str | None,
        issuer: str,
        scopes: tuple[str, ...],
        raw_claims: dict[str, Any],
    ) -> AdminSession:
        """Mint a session row and return it (the ``id`` is the cookie value)."""
        from authzkit.storage import orm

        sid = _new_token()
        csrf = _new_token(24)
        created = _now()
        expires = created + timedelta(seconds=self._session_ttl)
        with self.store.session() as s:
            row = orm.AdminSession(
                id=sid,
                subject=subject,
                email=email,
                issuer=issuer,
                scopes=",".join(scopes),
                raw_claims=raw_claims,
                csrf_token=csrf,
                expires_at=expires,
            )
            s.add(row)
            s.commit()
        return AdminSession(
            id=sid,
            subject=subject,
            email=email,
            issuer=issuer,
            scopes=scopes,
            raw_claims=raw_claims,
            csrf_token=csrf,
            created_at=created,
            expires_at=expires,
            last_seen_at=None,
        )

    def lookup_session(self, session_id: str) -> AdminSession | None:
        """Return the live session, updating ``last_seen_at``."""
        from authzkit.storage import orm

        with self.store.session() as s:
            row = s.get(orm.AdminSession, session_id)
            if row is None:
                return None
            expires = _aware(row.expires_at)
            assert expires is not None
            if expires < _now():
                s.delete(row)
                s.commit()
                return None
            row.last_seen_at = _now()
            s.commit()
            # ``s`` is the SQLAlchemy session; shadow with ``scope`` to
            # avoid name confusion in the generator-expression below.
            scopes = tuple(
                scope.strip()
                for scope in (row.scopes or "").split(",")
                if scope.strip()
            )
            return AdminSession(
                id=row.id,
                subject=row.subject,
                email=row.email,
                issuer=row.issuer,
                scopes=scopes,
                raw_claims=dict(row.raw_claims),
                csrf_token=row.csrf_token,
                # Coerce every datetime field so downstream comparisons
                # don't mix aware and naive on the SQLite path.
                created_at=_aware(row.created_at) or _now(),
                expires_at=expires,
                last_seen_at=_aware(row.last_seen_at),
            )

    def delete_session(self, session_id: str) -> bool:
        from authzkit.storage import orm

        with self.store.session() as s:
            row = s.get(orm.AdminSession, session_id)
            if row is None:
                return False
            s.delete(row)
            s.commit()
            return True

    # ----- helpers ---------------------------------------------------------

    def to_principal(self, session: AdminSession) -> SessionPrincipal:
        return SessionPrincipal(
            subject=session.subject,
            email=session.email,
            scopes=session.scopes,
            session_id=session.id,
            csrf_token=session.csrf_token,
            issuer=session.issuer,
        )

    def prune_expired(self) -> int:
        """Delete expired session + login-attempt rows. Returns count removed."""
        from sqlalchemy import delete

        from authzkit.storage import orm

        now = _now()
        removed = 0
        with self.store.session() as s:
            result = s.execute(
                delete(orm.AdminSession).where(orm.AdminSession.expires_at < now)
            )
            removed += result.rowcount or 0
            result = s.execute(
                delete(orm.AdminLoginAttempt).where(
                    orm.AdminLoginAttempt.expires_at < now
                )
            )
            removed += result.rowcount or 0
            s.commit()
        return removed
