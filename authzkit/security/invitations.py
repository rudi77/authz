"""Invitation tokens that turn into Memberships when accepted.

Tokens are stored hashed; the application is expected to deliver the
plaintext out-of-band (signed email, chat link, etc.). On accept the
service:

  1. Verifies the token matches an active, non-expired invite.
  2. Resolves the accepting user via :class:`IdentityPrincipal` (so the
     same auth path that a logged-in user uses also accepts the invite).
  3. Creates / activates the corresponding Membership and marks the
     invite ``accepted``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass(frozen=True)
class InvitationRecord:
    id: str
    tenant_id: str
    application_id: str | None
    email: str
    roles: tuple[str, ...]
    status: str
    expires_at: datetime
    invited_by_user_id: str | None
    accepted_at: datetime | None
    accepted_by_user_id: str | None


@dataclass(frozen=True)
class InvitationToken:
    record: InvitationRecord
    plaintext: str


def _hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _to_aware(dt: datetime) -> datetime:
    """SQLite drops tzinfo on round-trip — treat naive datetimes as UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


class InvitationService:
    """Create + accept invitations against the SqlAlchemy store."""

    def __init__(self, store) -> None:
        self.store = store

    def create(
        self,
        *,
        tenant_id: str,
        application_id: str | None,
        email: str,
        roles: Iterable[str],
        invited_by_user_id: str | None = None,
        ttl: timedelta = timedelta(days=7),
    ) -> InvitationToken:
        from authzkit.storage import orm

        plaintext = secrets.token_urlsafe(32)
        token_hash = _hash_token(plaintext)
        expires_at = datetime.now(UTC) + ttl
        with self.store.session() as s:
            row = orm.Invitation(
                tenant_id=tenant_id,
                application_id=application_id,
                email=email.lower().strip(),
                token_hash=token_hash,
                roles=",".join(sorted(set(r.strip() for r in roles if r.strip()))),
                status="pending",
                invited_by_user_id=invited_by_user_id,
                expires_at=expires_at,
            )
            s.add(row)
            s.commit()
            return InvitationToken(record=self._to_record(row), plaintext=plaintext)

    def accept(
        self,
        plaintext: str,
        *,
        accepting_user_id: str,
    ) -> InvitationRecord:
        from sqlalchemy import select

        from authzkit.storage import orm

        token_hash = _hash_token(plaintext)
        with self.store.session() as s:
            row = s.scalar(
                select(orm.Invitation).where(orm.Invitation.token_hash == token_hash)
            )
            if row is None or not hmac.compare_digest(row.token_hash, token_hash):
                raise InvitationError("invalid_token")
            if row.status != "pending":
                raise InvitationError("invitation_not_pending")
            if _to_aware(row.expires_at) < datetime.now(UTC):
                row.status = "expired"
                s.commit()
                raise InvitationError("invitation_expired")

            roles = [r for r in row.roles.split(",") if r]
            tenant_id = row.tenant_id
            application_id = row.application_id

        # Create membership outside the invitation session so the existing
        # store helper handles role lookup & link-table inserts.
        self.store.create_membership(
            tenant_id=tenant_id,
            application_id=application_id,
            user_id=accepting_user_id,
            roles=set(roles) or None,
        )

        with self.store.session() as s:
            row = s.scalar(
                select(orm.Invitation).where(orm.Invitation.token_hash == token_hash)
            )
            assert row is not None
            row.status = "accepted"
            row.accepted_at = datetime.now(UTC)
            row.accepted_by_user_id = accepting_user_id
            s.commit()
            return self._to_record(row)

    def list_for_tenant(self, tenant_id: str) -> list[InvitationRecord]:
        from sqlalchemy import select

        from authzkit.storage import orm

        with self.store.session() as s:
            rows = s.scalars(
                select(orm.Invitation)
                .where(orm.Invitation.tenant_id == tenant_id)
                .order_by(orm.Invitation.created_at.desc())
            ).all()
            return [self._to_record(r) for r in rows]

    def revoke(self, invitation_id: str) -> bool:
        from authzkit.storage import orm

        with self.store.session() as s:
            row = s.get(orm.Invitation, invitation_id)
            if row is None:
                return False
            row.status = "revoked"
            s.commit()
            return True

    @staticmethod
    def _to_record(row) -> InvitationRecord:
        return InvitationRecord(
            id=row.id,
            tenant_id=row.tenant_id,
            application_id=row.application_id,
            email=row.email,
            roles=tuple(r for r in (row.roles or "").split(",") if r),
            status=row.status,
            expires_at=row.expires_at,
            invited_by_user_id=row.invited_by_user_id,
            accepted_at=row.accepted_at,
            accepted_by_user_id=row.accepted_by_user_id,
        )


class InvitationError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)
