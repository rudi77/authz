"""Repository protocol for RBAC + agent + tenant-policy data access."""

from __future__ import annotations

from typing import Any, Protocol

from authzkit.rbac.models import Permission, Role


class RBACRepository(Protocol):
    """Read-side repository for the AuthorizationEngine.

    Concrete implementations must be cheap to call (resolver is hit per
    decision in the worst case). Implementations are free to memoize.
    """

    # Roles & Permissions
    def get_role(self, role_id: str) -> Role | None: ...
    def get_role_by_name(
        self, *, application_id: str | None, tenant_id: str | None, name: str
    ) -> Role | None: ...
    def list_role_permissions(self, role_id: str) -> list[Permission]: ...
    def list_application_permissions(self, application_id: str) -> list[Permission]: ...

    # Membership-driven permission resolution
    def resolve_user_permissions(
        self, *, tenant_id: str, application_id: str, user_id: str
    ) -> set[str]: ...

    # Agent-driven permission resolution
    def resolve_agent_permissions(
        self, *, tenant_id: str, application_id: str, agent_id: str
    ) -> set[str]: ...

    # Tenant-level permission limit (intersection mask)
    def resolve_tenant_permissions(
        self, *, tenant_id: str, application_id: str
    ) -> set[str]: ...

    # Tenant feature flags (subset of policy decisions)
    def get_tenant_feature_flags(
        self, tenant_id: str, application_id: str | None
    ) -> dict[str, Any]: ...

    # Activity status checks
    def is_tenant_active(self, tenant_id: str) -> bool: ...
    def is_application_active(self, application_id: str) -> bool: ...
    def is_user_membership_active(
        self, *, tenant_id: str, application_id: str, user_id: str
    ) -> bool: ...
    def is_agent_active(
        self, *, tenant_id: str, application_id: str, agent_id: str
    ) -> bool: ...
