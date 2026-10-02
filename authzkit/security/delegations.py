"""Delegation grants — a user's time-boxed hand-off of a permission subset to an agent.

A grant answers "which part of *my* access may *this* agent use, for *this*
task, until *when*?". It is issued as an RS256 JWT shaped after RFC 8693
(token exchange) delegation semantics:

- ``sub``  — the user on whose behalf the agent acts
- ``act``  — ``{"sub": <agent_id>}``, the acting party
- ``jti``  — the grant id (revocation handle, row in ``delegation_grants``)
- ``authz`` — tenant, application, delegated permissions, purpose

Decisions made with a grant use ``user ∩ agent ∩ tenant-mask ∩ grant``, with
the first three resolved *live*, so revoking a user's role still takes effect
before the grant expires.

Confusion hardening: grants are signed with the same keys as Authorization
Server access tokens, so they carry a distinct ``typ`` header and audience
and no ``scope`` / ``tenant_id`` claims. :class:`~authzkit.security.oauth_resource.JwtResolver`
additionally refuses the delegation ``typ`` outright — a grant can never be
replayed as an API bearer token.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from authzkit.security.signing_keys import SigningKeyService

DELEGATION_TOKEN_TYPE = "authz-delegation+jwt"
DELEGATION_AUDIENCE = "urn:authz:delegation"
DEFAULT_ISSUER = "urn:authz"

# Deny / error reasons surfaced to callers.
REASON_INVALID = "delegation_invalid"
REASON_EXPIRED = "delegation_expired"
REASON_REVOKED = "delegation_revoked"
REASON_MISMATCH = "delegation_mismatch"
REASON_REQUIRED = "delegation_required"


class DelegationError(Exception):
    """Token could not be accepted; ``reason`` is the machine-readable code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class DelegationGrant:
    id: str
    tenant_id: str
    application_id: str
    user_id: str
    agent_id: str
    permissions: frozenset[str]
    purpose: str | None
    issued_by: str | None
    status: str
    expires_at: datetime
    revoked_at: datetime | None
    created_at: datetime | None

    @property
    def active(self) -> bool:
        return self.status == "active" and _aware(self.expires_at) > datetime.now(UTC)


@dataclass(frozen=True)
class IssuedDelegation:
    grant: DelegationGrant
    token: str


def _aware(value: datetime) -> datetime:
    # SQLite hands back naive datetimes even for timezone=True columns.
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _to_grant(row: Any) -> DelegationGrant:
    return DelegationGrant(
        id=row.id,
        tenant_id=row.tenant_id,
        application_id=row.application_id,
        user_id=row.user_id,
        agent_id=row.agent_id,
        permissions=frozenset(row.permissions or ()),
        purpose=row.purpose,
        issued_by=row.issued_by,
        status=row.status,
        expires_at=_aware(row.expires_at),
        revoked_at=_aware(row.revoked_at) if row.revoked_at else None,
        created_at=_aware(row.created_at) if row.created_at else None,
    )


class DelegationService:
    """Issue, verify, list and revoke delegation grants."""

    def __init__(
        self,
        store: Any,
        signing_keys: SigningKeyService,
        *,
        issuer: str = "",
        leeway_seconds: int = 30,
    ) -> None:
        self.store = store
        self.signing_keys = signing_keys
        self.issuer = issuer or DEFAULT_ISSUER
        self.leeway_seconds = leeway_seconds

    # ----- issue -------------------------------------------------------------

    def issue(
        self,
        *,
        tenant_id: str,
        application_id: str,
        user_id: str,
        agent_id: str,
        permissions: Iterable[str],
        ttl: timedelta,
        purpose: str | None = None,
        issued_by: str | None = None,
    ) -> IssuedDelegation:
        """Persist a grant and sign its JWT.

        ``permissions`` must already be validated by the caller against the
        subject's current effective set — this method only records + signs.
        """
        from authzkit.storage import orm

        now = datetime.now(UTC).replace(microsecond=0)
        expires_at = now + ttl
        grant_id = str(uuid.uuid4())
        perms = sorted(set(permissions))
        # Sign first: if no signing key is available we must not leave an
        # orphan row behind.
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": DELEGATION_AUDIENCE,
            "sub": user_id,
            "act": {"sub": agent_id},
            "jti": grant_id,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "authz": {
                "tenant_id": tenant_id,
                "application_id": application_id,
                "permissions": perms,
                **({"purpose": purpose} if purpose else {}),
            },
        }
        token = self._sign(claims)
        with self.store.session() as s:
            row = orm.DelegationGrant(
                id=grant_id,
                tenant_id=tenant_id,
                application_id=application_id,
                user_id=user_id,
                agent_id=agent_id,
                permissions=perms,
                purpose=purpose,
                issued_by=issued_by,
                status="active",
                expires_at=expires_at,
                created_at=now,
            )
            s.add(row)
            s.commit()
            return IssuedDelegation(grant=_to_grant(row), token=token)

    def _sign(self, claims: dict[str, Any]) -> str:
        import jwt

        key = self.signing_keys.active_signing_key()
        return jwt.encode(
            claims,
            key.private_pem,
            algorithm=key.alg,
            headers={"kid": key.kid, "typ": DELEGATION_TOKEN_TYPE},
        )

    # ----- verify ------------------------------------------------------------

    def verify(self, token: str) -> DelegationGrant:
        """Check signature, type, audience, issuer, expiry and revocation.

        Raises :class:`DelegationError` with one of the ``REASON_*`` codes.
        The returned grant reflects the stored row (source of truth).
        """
        import jwt

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise DelegationError(REASON_INVALID, f"malformed token: {exc}") from exc
        if header.get("typ") != DELEGATION_TOKEN_TYPE:
            raise DelegationError(REASON_INVALID, "not a delegation token")
        jwk = next(
            (
                k
                for k in self.signing_keys.all_public_jwks().get("keys", [])
                if k.get("kid") == header.get("kid")
            ),
            None,
        )
        if jwk is None:
            raise DelegationError(REASON_INVALID, "unknown signing key")
        try:
            claims = jwt.decode(
                token,
                key=jwt.PyJWK(jwk).key,
                algorithms=["RS256"],
                audience=DELEGATION_AUDIENCE,
                issuer=self.issuer,
                leeway=self.leeway_seconds,
                options={"require": ["exp", "jti", "sub", "aud", "iss"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise DelegationError(REASON_EXPIRED, "grant expired") from exc
        except jwt.PyJWTError as exc:
            raise DelegationError(REASON_INVALID, str(exc)) from exc

        grant = self.get(str(claims["jti"]))
        if grant is None:
            raise DelegationError(REASON_INVALID, "unknown grant")
        if grant.status == "revoked":
            raise DelegationError(REASON_REVOKED, "grant revoked")
        if grant.expires_at <= datetime.now(UTC):
            raise DelegationError(REASON_EXPIRED, "grant expired")
        # The signed claims must agree with the stored row; a mismatch means
        # tampering with the DB or a jti collision — refuse either way.
        act = claims.get("act") or {}
        body = claims.get("authz") or {}
        if (
            claims.get("sub") != grant.user_id
            or act.get("sub") != grant.agent_id
            or body.get("tenant_id") != grant.tenant_id
            or body.get("application_id") != grant.application_id
            or frozenset(body.get("permissions") or ()) != grant.permissions
        ):
            raise DelegationError(REASON_INVALID, "token does not match stored grant")
        return grant

    # ----- read / revoke -----------------------------------------------------

    def get(self, grant_id: str) -> DelegationGrant | None:
        from authzkit.storage import orm

        with self.store.session() as s:
            row = s.get(orm.DelegationGrant, grant_id)
            return _to_grant(row) if row is not None else None

    def list(
        self,
        *,
        tenant_id: str | None = None,
        user_id: str | None = None,
        agent_id: str | None = None,
        active_only: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> list[DelegationGrant]:
        from sqlalchemy import select

        from authzkit.storage import orm

        stmt = select(orm.DelegationGrant).order_by(orm.DelegationGrant.created_at.desc())
        if tenant_id:
            stmt = stmt.where(orm.DelegationGrant.tenant_id == tenant_id)
        if user_id:
            stmt = stmt.where(orm.DelegationGrant.user_id == user_id)
        if agent_id:
            stmt = stmt.where(orm.DelegationGrant.agent_id == agent_id)
        if active_only:
            stmt = stmt.where(
                orm.DelegationGrant.status == "active",
                orm.DelegationGrant.expires_at > datetime.now(UTC),
            )
        with self.store.session() as s:
            rows = s.scalars(stmt.offset(offset).limit(limit)).all()
            return [_to_grant(r) for r in rows]

    def revoke(self, grant_id: str) -> DelegationGrant | None:
        """Revoke one grant. Idempotent; returns ``None`` if it doesn't exist."""
        from authzkit.storage import orm

        with self.store.session() as s:
            row = s.get(orm.DelegationGrant, grant_id)
            if row is None:
                return None
            if row.status != "revoked":
                row.status = "revoked"
                row.revoked_at = datetime.now(UTC)
                s.commit()
            return _to_grant(row)

    def revoke_matching(
        self, *, tenant_id: str, user_id: str | None = None, agent_id: str | None = None
    ) -> int:
        """Kill switch: revoke every active grant of a tenant, user and/or agent."""
        from sqlalchemy import update

        from authzkit.storage import orm

        stmt = (
            update(orm.DelegationGrant)
            .where(
                orm.DelegationGrant.tenant_id == tenant_id,
                orm.DelegationGrant.status == "active",
            )
            .values(status="revoked", revoked_at=datetime.now(UTC))
        )
        if user_id:
            stmt = stmt.where(orm.DelegationGrant.user_id == user_id)
        if agent_id:
            stmt = stmt.where(orm.DelegationGrant.agent_id == agent_id)
        with self.store.session() as s:
            result = s.execute(stmt)
            s.commit()
            return int(result.rowcount or 0)
