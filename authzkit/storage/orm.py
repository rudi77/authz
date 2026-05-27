"""SQLAlchemy ORM mappings matching the schema in spec section 9."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Table,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


# Use JSONB on Postgres but fall back to JSON on SQLite for tests.
JSONType = JSON().with_variant(JSONB(), "postgresql")
UUIDType = String(36).with_variant(UUID(as_uuid=False), "postgresql")


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    slug: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


class Application(Base):
    __tablename__ = "applications"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    slug: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


class ExternalIdentity(Base):
    __tablename__ = "external_identities"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    external_tenant_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    __table_args__ = (UniqueConstraint("provider", "issuer", "subject"),)


class TenantIdentityMapping(Base):
    __tablename__ = "tenant_identity_mappings"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        UUIDType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    external_tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (UniqueConstraint("provider", "issuer", "external_tenant_id"),)


class Membership(Base):
    __tablename__ = "memberships"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        UUIDType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    application_id: Mapped[str | None] = mapped_column(
        UUIDType, ForeignKey("applications.id", ondelete="CASCADE"), nullable=True
    )
    user_id: Mapped[str] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    __table_args__ = (UniqueConstraint("tenant_id", "application_id", "user_id"),)


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    tenant_id: Mapped[str | None] = mapped_column(
        UUIDType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    application_id: Mapped[str | None] = mapped_column(
        UUIDType, ForeignKey("applications.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    __table_args__ = (UniqueConstraint("tenant_id", "application_id", "name"),)


membership_roles = Table(
    "membership_roles",
    Base.metadata,
    Column(
        "membership_id",
        UUIDType,
        ForeignKey("memberships.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "role_id",
        UUIDType,
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("created_at", DateTime(timezone=True), default=_now),
)


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    application_id: Mapped[str | None] = mapped_column(
        UUIDType, ForeignKey("applications.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (
        UniqueConstraint("application_id", "name"),
        UniqueConstraint("application_id", "resource", "action"),
    )


role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", UUIDType, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "permission_id",
        UUIDType,
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("created_at", DateTime(timezone=True), default=_now),
)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        UUIDType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    application_id: Mapped[str] = mapped_column(
        UUIDType, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    role_label: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_by_user_id: Mapped[str | None] = mapped_column(
        UUIDType, ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


agent_roles = Table(
    "agent_roles",
    Base.metadata,
    Column("agent_id", UUIDType, ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", UUIDType, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("created_at", DateTime(timezone=True), default=_now),
)


class TenantFeatureFlag(Base):
    __tablename__ = "tenant_feature_flags"
    tenant_id: Mapped[str] = mapped_column(
        UUIDType, ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True
    )
    application_id: Mapped[str | None] = mapped_column(
        UUIDType, ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True, nullable=True
    )
    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONType, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


class TenantPermissionMask(Base):
    """Stores tenant-level permission whitelist used as an intersection mask.

    Decoupled from feature flags: a flag like ``github_mcp_enabled=false``
    expands at policy-bind time into a removal of the matching permission
    names from this mask. Empty mask = unrestricted.
    """

    __tablename__ = "tenant_permission_masks"
    tenant_id: Mapped[str] = mapped_column(
        UUIDType, ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True
    )
    application_id: Mapped[str] = mapped_column(
        UUIDType, ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True
    )
    permission_name: Mapped[str] = mapped_column(String(255), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    tenant_id: Mapped[str | None] = mapped_column(
        UUIDType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    application_id: Mapped[str | None] = mapped_column(
        UUIDType, ForeignKey("applications.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    effect: Mapped[str] = mapped_column(String(16), nullable=False)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    condition: Mapped[dict | None] = mapped_column(JSONType, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    tenant_id: Mapped[str | None] = mapped_column(UUIDType, nullable=True)
    application_id: Mapped[str | None] = mapped_column(UUIDType, nullable=True)
    user_id: Mapped[str | None] = mapped_column(UUIDType, nullable=True)
    agent_id: Mapped[str | None] = mapped_column(UUIDType, nullable=True)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    request: Mapped[dict] = mapped_column(JSONType, nullable=False)
    response: Mapped[dict] = mapped_column(JSONType, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, server_default=func.now()
    )


class ApiKey(Base):
    """Scoped API key for service-to-service authentication.

    Keys are stored hashed (SHA-256). The plaintext is shown to admins
    exactly once at creation time. Scopes are a small enum:

    - ``admin``       — full read/write on management APIs
    - ``runtime``     — only the four runtime endpoints (resolve-context,
                        authorize, bulk-authorize, effective-permissions)
    - ``tenant:<id>`` — same as runtime + management restricted to one tenant

    Rotation: create a new key with ``rotates`` pointing at the old key id;
    keep both active during rollout, then revoke the old one.
    """

    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    scopes: Mapped[str] = mapped_column(String(512), nullable=False, default="admin")
    tenant_id: Mapped[str | None] = mapped_column(
        UUIDType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rotates: Mapped[str | None] = mapped_column(UUIDType, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


class OAuthClient(Base):
    """OAuth 2.0 client for the ``client_credentials`` grant (RFC 6749 §4.4).

    Distinct from :class:`ApiKey`: an API key is a long-lived bearer secret
    callers present directly on every request; an OAuth client trades its
    secret at ``POST /oauth/token`` for a short-lived JWT and the secret
    never travels on the PEP-facing requests after that. Shared crypto
    helpers (``_hash``, ``_constant_time_eq``) live in
    :mod:`authzkit.security.api_keys`.
    """

    __tablename__ = "oauth_clients"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    client_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    secret_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # CSV of *granted-max* scopes (same vocabulary as ApiKey.scopes). A token
    # request can ask for a subset via the OAuth ``scope`` form param.
    scopes: Mapped[str] = mapped_column(String(512), nullable=False, default="runtime")
    tenant_id: Mapped[str | None] = mapped_column(
        UUIDType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


class OAuthSigningKey(Base):
    """RSA signing key for the Authorization-Server-issued JWTs.

    At most one row has ``status='active'`` at any time; that's the key
    used for new tokens. Rotation moves the old row to ``status='retiring'``
    so its public JWK keeps appearing in ``/.well-known/jwks.json`` long
    enough for previously-issued tokens to validate until they expire.
    A janitor (analogous to :class:`AuditRetentionWorker`) demotes
    ``retiring`` to ``revoked`` after ``2 * max_token_ttl``.

    The private PEM is stored here only as a *fallback* — operators are
    expected to set ``AUTHZ_OAUTH_SIGNING_KEY_PEM`` and mount it as a
    Kubernetes / docker secret. See SECURITY.md.
    """

    __tablename__ = "oauth_signing_keys"
    kid: Mapped[str] = mapped_column(String(64), primary_key=True)
    alg: Mapped[str] = mapped_column(String(16), nullable=False, default="RS256")
    public_jwk: Mapped[dict] = mapped_column(JSONType, nullable=False)
    private_pem: Mapped[str] = mapped_column(String(8192), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Partial unique index: at most one row carries status='active' at a
    # time. Defence in depth against a botched rotation (the rotate()
    # path also takes a row-level lock).
    __table_args__ = (
        Index(
            "uq_oauth_signing_keys_active",
            "status",
            unique=True,
            sqlite_where=text("status = 'active'"),
            postgresql_where=text("status = 'active'"),
        ),
    )


class AdminSession(Base):
    """Server-side session for an admin who logged in via OIDC.

    The cookie value is the primary key (random 256-bit token); ``raw_claims``
    keeps the verified id_token payload for audit. Janitor sweeps expired
    rows hourly.
    """

    __tablename__ = "admin_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    # CSV of internal-mapped scopes — usually just "admin".
    scopes: Mapped[str] = mapped_column(String(512), nullable=False, default="admin")
    raw_claims: Mapped[dict] = mapped_column(JSONType, nullable=False)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AdminLoginAttempt(Base):
    """In-flight OIDC login state (PKCE verifier + state + nonce).

    Lives only between ``GET /oauth/login`` and ``GET /oauth/callback``;
    a row's lifetime is typically seconds. Looked up by the
    ``authz_login_id`` cookie so the verifier is never disclosed to the
    browser. Rows older than ``expires_at`` are rejected and pruned by
    the session janitor.
    """

    __tablename__ = "admin_login_attempts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    state: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    code_verifier: Mapped[str] = mapped_column(String(255), nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    return_to: Mapped[str] = mapped_column(String(512), nullable=False, default="/admin/")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Invitation(Base):
    """Pending invitation for a user to join a tenant.

    Tokens are stored hashed; the plaintext is delivered out-of-band (email,
    chat, etc.) by the integrating application. Accepting an invite creates
    a Membership and marks the invite ``accepted``.
    """

    __tablename__ = "invitations"
    id: Mapped[str] = mapped_column(UUIDType, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        UUIDType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    application_id: Mapped[str | None] = mapped_column(
        UUIDType, ForeignKey("applications.id", ondelete="CASCADE"), nullable=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    roles: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    invited_by_user_id: Mapped[str | None] = mapped_column(
        UUIDType, ForeignKey("users.id"), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_by_user_id: Mapped[str | None] = mapped_column(UUIDType, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )
