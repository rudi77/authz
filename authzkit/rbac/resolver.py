"""Resolves a Membership or Agent into the set of effective permission names."""

from __future__ import annotations

from authzkit.rbac.repository import RBACRepository
from authzkit.tenancy.models import Membership


class PermissionResolver:
    """Façade over RBACRepository that returns string permission sets."""

    def __init__(self, repository: RBACRepository) -> None:
        self.repository = repository

    def resolve_membership_permissions(self, membership: Membership) -> set[str]:
        """Permissions granted to the user *because of* this membership."""
        if membership.application_id is None:
            return set()
        return self.repository.resolve_user_permissions(
            tenant_id=membership.tenant_id,
            application_id=membership.application_id,
            user_id=membership.user_id,
        )

    def resolve_user_permissions(
        self, *, tenant_id: str, application_id: str, user_id: str
    ) -> set[str]:
        return self.repository.resolve_user_permissions(
            tenant_id=tenant_id,
            application_id=application_id,
            user_id=user_id,
        )

    def resolve_agent_permissions(
        self, *, tenant_id: str, application_id: str, agent_id: str
    ) -> set[str]:
        return self.repository.resolve_agent_permissions(
            tenant_id=tenant_id,
            application_id=application_id,
            agent_id=agent_id,
        )

    def resolve_tenant_permissions(
        self, *, tenant_id: str, application_id: str
    ) -> set[str]:
        return self.repository.resolve_tenant_permissions(
            tenant_id=tenant_id, application_id=application_id
        )
