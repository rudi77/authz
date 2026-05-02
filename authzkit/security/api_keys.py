"""Scoped API key service.

Stored hashed, compared with constant-time semantics, scoped to either a
surface (``admin`` / ``runtime``) or a tenant (``tenant:<id>``).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

SCOPE_ADMIN = "admin"
SCOPE_RUNTIME = "runtime"


@dataclass(frozen=True)
class ApiKeyRecord:
    id: str
    name: str
    key_prefix: str
    scopes: tuple[str, ...]
    tenant_id: str | None
    status: str
    expires_at: datetime | None
    last_used_at: datetime | None
    rotates: str | None


@dataclass(frozen=True)
class ApiKeyMaterial:
    """The plaintext returned exactly once at creation."""

    record: ApiKeyRecord
    plaintext: str


def _hash(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def generate_api_key(prefix: str = "azk") -> tuple[str, str, str]:
    """Generate (plaintext, hash, prefix) for a new key.

    The plaintext format is ``<prefix>_<random>``. Keeping a fixed prefix in
    front of every key makes log scrubbing tractable: ops can grep for it.
    """
    raw = secrets.token_urlsafe(32)
    plaintext = f"{prefix}_{raw}"
    return plaintext, _hash(plaintext), plaintext[: len(prefix) + 7]


def parse_scopes(value: str) -> tuple[str, ...]:
    return tuple(s.strip() for s in value.split(",") if s.strip())


def serialize_scopes(scopes: Iterable[str]) -> str:
    return ",".join(sorted(set(s for s in scopes if s)))


class ApiKeyService:
    """Find/issue/revoke API keys against the SqlAlchemy store.

    Held outside the request handler so the service surface stays small.
    """

    def __init__(self, store) -> None:
        self.store = store

    # ---- issuance ----------------------------------------------------------

    def issue(
        self,
        *,
        name: str,
        scopes: Iterable[str],
        tenant_id: str | None = None,
        expires_at: datetime | None = None,
        rotates: str | None = None,
    ) -> ApiKeyMaterial:
        from sqlalchemy import select

        from authzkit.storage import orm

        plaintext, key_hash, prefix = generate_api_key()
        scopes_str = serialize_scopes(scopes)
        with self.store.session() as s:
            row = orm.ApiKey(
                name=name,
                key_hash=key_hash,
                key_prefix=prefix,
                scopes=scopes_str,
                tenant_id=tenant_id,
                expires_at=expires_at,
                rotates=rotates,
            )
            s.add(row)
            s.commit()
            stored = s.scalar(select(orm.ApiKey).where(orm.ApiKey.id == row.id))
            assert stored is not None
            record = self._to_record(stored)
        return ApiKeyMaterial(record=record, plaintext=plaintext)

    # ---- authentication ----------------------------------------------------

    def find_active(self, plaintext: str) -> ApiKeyRecord | None:
        """Look up an active key by plaintext using a single hash lookup.

        Constant-time comparison guards against timing attacks: even though
        the lookup itself is by hash (not by string equality), the final
        equality check is done with hmac.compare_digest.
        """
        from sqlalchemy import select

        from authzkit.storage import orm

        candidate_hash = _hash(plaintext)
        with self.store.session() as s:
            row = s.scalar(
                select(orm.ApiKey).where(orm.ApiKey.key_hash == candidate_hash)
            )
            if row is None:
                return None
            if not _constant_time_eq(row.key_hash, candidate_hash):
                return None
            if row.status != "active":
                return None
            if row.expires_at is not None:
                # SQLite drops tzinfo on round-trip; treat naive as UTC.
                expires = row.expires_at
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=UTC)
                if expires < datetime.now(UTC):
                    return None
            row.last_used_at = datetime.now(UTC)
            s.commit()
            return self._to_record(row)

    # ---- management --------------------------------------------------------

    def list_keys(self) -> list[ApiKeyRecord]:
        from sqlalchemy import select

        from authzkit.storage import orm

        with self.store.session() as s:
            rows = s.scalars(select(orm.ApiKey)).all()
            return [self._to_record(r) for r in rows]

    def revoke(self, key_id: str) -> bool:
        from authzkit.storage import orm

        with self.store.session() as s:
            row = s.get(orm.ApiKey, key_id)
            if row is None:
                return False
            row.status = "revoked"
            s.commit()
            return True

    def rotate(
        self,
        old_key_id: str,
        *,
        name: str | None = None,
    ) -> ApiKeyMaterial:
        """Issue a new key inheriting the scopes of the old one.

        Both keys remain active until the operator revokes the old one. The
        new record's ``rotates`` field links back to the predecessor for
        audit trail.
        """
        from authzkit.storage import orm

        with self.store.session() as s:
            old = s.get(orm.ApiKey, old_key_id)
            if old is None:
                raise ValueError(f"unknown api key: {old_key_id}")
            scopes = parse_scopes(old.scopes)
            tenant_id = old.tenant_id
            new_name = name or f"{old.name} (rotated)"
        return self.issue(
            name=new_name, scopes=scopes, tenant_id=tenant_id, rotates=old_key_id
        )

    # ---- helpers -----------------------------------------------------------

    @staticmethod
    def _to_record(row) -> ApiKeyRecord:
        return ApiKeyRecord(
            id=row.id,
            name=row.name,
            key_prefix=row.key_prefix,
            scopes=parse_scopes(row.scopes),
            tenant_id=row.tenant_id,
            status=row.status,
            expires_at=row.expires_at,
            last_used_at=row.last_used_at,
            rotates=row.rotates,
        )


def scope_allows(
    scopes: Iterable[str],
    *,
    surface: str,
    tenant_id: str | None = None,
) -> bool:
    """Return True if any of the granted scopes covers the requested action.

    ``surface`` is one of ``admin`` / ``runtime``. Admins have full access;
    runtime keys are restricted to the four PEP endpoints; tenant-scoped
    keys (``tenant:<id>``) imply runtime + management for that tenant only.
    """
    scopes_set = set(scopes)
    if SCOPE_ADMIN in scopes_set:
        return True
    if surface == "runtime" and SCOPE_RUNTIME in scopes_set:
        return True
    return bool(tenant_id is not None and f"tenant:{tenant_id}" in scopes_set)
