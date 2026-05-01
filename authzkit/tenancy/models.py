"""Core tenancy domain models."""

from __future__ import annotations

from dataclasses import dataclass, field

TENANT_STATUS_ACTIVE = "active"
TENANT_STATUS_SUSPENDED = "suspended"
TENANT_STATUS_DELETED = "deleted"

USER_STATUS_ACTIVE = "active"
USER_STATUS_DISABLED = "disabled"

MEMBERSHIP_STATUS_ACTIVE = "active"
MEMBERSHIP_STATUS_INVITED = "invited"
MEMBERSHIP_STATUS_SUSPENDED = "suspended"
MEMBERSHIP_STATUS_REMOVED = "removed"


@dataclass(frozen=True)
class Tenant:
    """A fachliche organization, customer, workspace, or isolation unit."""

    id: str
    slug: str
    name: str
    status: str = TENANT_STATUS_ACTIVE


@dataclass(frozen=True)
class Application:
    """A concrete product or project that consumes the AuthZ service."""

    id: str
    slug: str
    name: str
    status: str = "active"


@dataclass(frozen=True)
class User:
    """Internal representation of an externally authenticated identity."""

    id: str
    display_name: str | None = None
    email: str | None = None
    status: str = USER_STATUS_ACTIVE


@dataclass(frozen=True)
class ExternalIdentity:
    """A binding between a User and a specific external Identity Provider record."""

    id: str
    user_id: str
    provider: str
    issuer: str
    subject: str
    external_tenant_id: str | None = None
    email: str | None = None


@dataclass(frozen=True)
class Membership:
    """Connects a user to a tenant, optionally scoped to an application."""

    id: str
    tenant_id: str
    user_id: str
    application_id: str | None
    roles: frozenset[str] = field(default_factory=frozenset)
    status: str = MEMBERSHIP_STATUS_ACTIVE


@dataclass(frozen=True)
class TenantIdentityMapping:
    """Maps an external IdP tenant id to an internal tenant."""

    id: str
    tenant_id: str
    provider: str
    issuer: str
    external_tenant_id: str
