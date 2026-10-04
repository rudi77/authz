"""Declarative provisioning: desired-state types for the application catalog
and per-tenant state.

A caller that owns an application (``managed_by``) writes its *complete*
desired state; the store applies it atomically or not at all. Validation
problems are collected and reported together instead of being dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field

STATUS_ACTIVE = "active"
STATUS_DISABLED = "disabled"
DESIRED_STATUSES = frozenset({STATUS_ACTIVE, STATUS_DISABLED})


def agent_role_name(agent_name: str) -> str:
    """Name of the internal role carrying a provisioned agent's permissions."""
    return f"agent:{agent_name}"


@dataclass(frozen=True)
class ProvisioningIssue:
    path: str  # e.g. ``members[0].roles[1]``
    code: str  # e.g. ``unknown_role``
    message: str


class ProvisioningError(Exception):
    """The desired state is invalid; nothing was applied."""

    def __init__(self, errors: list[ProvisioningIssue]) -> None:
        super().__init__(f"{len(errors)} provisioning error(s)")
        self.errors = errors


# ---- Application catalog ----------------------------------------------------


@dataclass(frozen=True)
class CatalogPermission:
    name: str
    description: str | None = None
    critical: bool = False


@dataclass(frozen=True)
class CatalogRole:
    name: str
    description: str | None = None
    permissions: tuple[str, ...] = ()


@dataclass(frozen=True)
class CatalogResult:
    application_id: str
    permissions_created: int
    permissions_deprecated: int
    roles_created: int
    roles_updated: int


# ---- Tenant state -----------------------------------------------------------


@dataclass(frozen=True)
class UserRef:
    """A user's identity at its identity provider, e.g. ``(dtm, urn:dtm:prod, <id>)``."""

    provider: str
    issuer: str
    subject: str


@dataclass(frozen=True)
class DesiredMember:
    user_ref: UserRef
    roles: tuple[str, ...] = ()
    display_name: str | None = None
    email: str | None = None
    status: str = STATUS_ACTIVE


@dataclass(frozen=True)
class DesiredAgent:
    name: str
    permissions: tuple[str, ...] = ()
    display_name: str | None = None
    status: str = STATUS_ACTIVE


@dataclass(frozen=True)
class TenantState:
    name: str
    status: str = STATUS_ACTIVE
    members: tuple[DesiredMember, ...] = ()
    agents: tuple[DesiredAgent, ...] = ()


@dataclass
class ChangeCounts:
    created: int = 0
    updated: int = 0
    disabled: int = 0


@dataclass(frozen=True)
class TenantRoleView:
    """A default role as one tenant sees it (``source`` = ``tenant`` if overridden)."""

    name: str
    source: str
    permissions: list[str]
    default_permissions: list[str]


@dataclass(frozen=True)
class TenantStateResult:
    tenant_id: str
    members: ChangeCounts = field(default_factory=ChangeCounts)
    agents: ChangeCounts = field(default_factory=ChangeCounts)
