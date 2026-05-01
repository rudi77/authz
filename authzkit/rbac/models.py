"""Roles, Permissions, and scope enumerations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RoleScope(StrEnum):
    PLATFORM = "platform"
    APPLICATION = "application"
    TENANT = "tenant"
    AGENT = "agent"


@dataclass(frozen=True)
class Permission:
    """A permission encodes an allowed action on a resource.

    Permission name format: ``<resource>.<action>`` (or
    ``<namespace>.<resource>.<action>`` for namespaced ones like
    ``mcp.github.create_issue``).
    """

    id: str
    name: str
    resource: str
    action: str
    application_id: str | None = None
    description: str | None = None

    @classmethod
    def from_name(
        cls,
        name: str,
        *,
        id: str | None = None,
        application_id: str | None = None,
    ) -> "Permission":
        if "." not in name:
            raise ValueError(f"permission name must contain '.': {name}")
        # The action is always the trailing segment; everything to its left is
        # the (possibly multi-part) resource. Keeps mcp.github.create_issue
        # and contracts.review parsing under one rule.
        resource, _, action = name.rpartition(".")
        return cls(
            id=id or name,
            name=name,
            resource=resource,
            action=action,
            application_id=application_id,
        )


@dataclass(frozen=True)
class Role:
    """A named bundle of permissions."""

    id: str
    name: str
    scope: RoleScope
    tenant_id: str | None = None
    application_id: str | None = None
    description: str | None = None
    is_system: bool = False
