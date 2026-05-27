"""OAuth 2.0 ``client_credentials`` client registry.

Distinct from :mod:`authzkit.security.api_keys` even though both store a
hashed long-lived secret and a scope tuple. Rationale:

- **Lifecycle** — an API key is presented on every request; an OAuth client
  secret is presented once at ``POST /oauth/token`` and is replaced on the
  wire by a short-lived JWT for subsequent calls.
- **Admin surface** — the audit log and admin UI conflate badly if both
  kinds share one table; keeping them apart lets each grow its own schema.
- **Crypto helpers** — :func:`~authzkit.security.api_keys._hash` and
  :func:`~authzkit.security.api_keys._constant_time_eq` are reused so the
  hashing/comparison properties stay identical across both kinds.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from authzkit.security.api_keys import (
    _constant_time_eq,
    _hash,
    parse_scopes,
    serialize_scopes,
)


def _aware(value: datetime | None) -> datetime | None:
    """Coerce SQLite-roundtripped naive datetimes to tz-aware UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


@dataclass(frozen=True)
class OAuthClientRecord:
    """The non-sensitive view of an OAuth client."""

    id: str
    client_id: str
    name: str
    scopes: tuple[str, ...]
    tenant_id: str | None
    status: str
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime | None


@dataclass(frozen=True)
class OAuthClientCredentials:
    """The plaintext secret returned exactly once at issuance/rotation."""

    record: OAuthClientRecord
    client_secret: str


def _generate_client_id() -> str:
    """``oc_<urlsafe-22>`` — predictable prefix so operators can grep logs."""
    return f"oc_{secrets.token_urlsafe(16)}"


def _generate_client_secret() -> str:
    """``ocs_<urlsafe-32>`` — high-entropy, prefix-grep-friendly."""
    return f"ocs_{secrets.token_urlsafe(32)}"


class OAuthClientService:
    """Manage OAuth ``client_credentials`` clients in the DB."""

    def __init__(self, store: Any) -> None:
        self.store = store

    # ----- issuance --------------------------------------------------------

    def issue(
        self,
        *,
        name: str,
        scopes: Iterable[str],
        tenant_id: str | None = None,
        expires_at: datetime | None = None,
        client_id: str | None = None,
    ) -> OAuthClientCredentials:
        from sqlalchemy import select

        from authzkit.storage import orm

        cid = client_id or _generate_client_id()
        secret = _generate_client_secret()
        secret_hash = _hash(secret)
        scopes_str = serialize_scopes(scopes)
        with self.store.session() as s:
            row = orm.OAuthClient(
                client_id=cid,
                secret_hash=secret_hash,
                name=name,
                scopes=scopes_str,
                tenant_id=tenant_id,
                expires_at=expires_at,
            )
            s.add(row)
            s.commit()
            stored = s.scalar(
                select(orm.OAuthClient).where(orm.OAuthClient.id == row.id)
            )
            assert stored is not None
            record = self._to_record(stored)
        return OAuthClientCredentials(record=record, client_secret=secret)

    # ----- authentication --------------------------------------------------

    def authenticate(self, client_id: str, client_secret: str) -> OAuthClientRecord | None:
        """Look up a client by ID, verify the secret in constant time.

        Always touches the DB and runs the hash even on miss so timing
        doesn't disclose whether a given ``client_id`` exists.
        """
        from sqlalchemy import select

        from authzkit.storage import orm

        candidate_hash = _hash(client_secret)
        with self.store.session() as s:
            row = s.scalar(
                select(orm.OAuthClient).where(orm.OAuthClient.client_id == client_id)
            )
            # Constant-time noop comparison to keep the timing flat on miss.
            if row is None:
                _constant_time_eq(candidate_hash, candidate_hash)
                return None
            if not _constant_time_eq(row.secret_hash, candidate_hash):
                return None
            if row.status != "active":
                return None
            if row.expires_at is not None:
                expires = row.expires_at
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=UTC)
                if expires < datetime.now(UTC):
                    return None
            row.last_used_at = datetime.now(UTC)
            s.commit()
            return self._to_record(row)

    # ----- management ------------------------------------------------------

    def list_clients(self) -> list[OAuthClientRecord]:
        from sqlalchemy import select

        from authzkit.storage import orm

        with self.store.session() as s:
            rows = s.scalars(select(orm.OAuthClient)).all()
            return [self._to_record(r) for r in rows]

    def get(self, client_id: str) -> OAuthClientRecord | None:
        from sqlalchemy import select

        from authzkit.storage import orm

        with self.store.session() as s:
            row = s.scalar(
                select(orm.OAuthClient).where(orm.OAuthClient.client_id == client_id)
            )
            return self._to_record(row) if row else None

    def revoke(self, client_id: str) -> bool:
        from sqlalchemy import select

        from authzkit.storage import orm

        with self.store.session() as s:
            row = s.scalar(
                select(orm.OAuthClient).where(orm.OAuthClient.client_id == client_id)
            )
            if row is None:
                return False
            row.status = "revoked"
            s.commit()
            return True

    def rotate_secret(self, client_id: str) -> OAuthClientCredentials | None:
        """Generate a new secret for an existing client; old hash is discarded."""
        from sqlalchemy import select

        from authzkit.storage import orm

        with self.store.session() as s:
            row = s.scalar(
                select(orm.OAuthClient).where(orm.OAuthClient.client_id == client_id)
            )
            if row is None:
                return None
            secret = _generate_client_secret()
            row.secret_hash = _hash(secret)
            s.commit()
            record = self._to_record(row)
        return OAuthClientCredentials(record=record, client_secret=secret)

    # ----- helpers ---------------------------------------------------------

    @staticmethod
    def _to_record(row: Any) -> OAuthClientRecord:
        return OAuthClientRecord(
            id=row.id,
            client_id=row.client_id,
            name=row.name,
            scopes=parse_scopes(row.scopes),
            tenant_id=row.tenant_id,
            status=row.status,
            # Coerce every datetime so callers can safely compare against
            # tz-aware ``datetime.now(UTC)`` regardless of backend.
            expires_at=_aware(row.expires_at),
            last_used_at=_aware(row.last_used_at),
            created_at=_aware(row.created_at),
        )
