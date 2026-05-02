"""SQLAlchemy ORM mappings matching the schema in spec section 9."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    String,
    Table,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


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
