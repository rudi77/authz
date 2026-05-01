"""Builds an AgentContext from a (user_id, agent_id) pair."""

from __future__ import annotations

from authzkit.agents.models import Agent, AgentContext
from authzkit.exceptions import (
    AgentNotActiveError,
    AgentNotFoundError,
    NoActiveMembershipError,
    TenantNotActiveError,
)
from authzkit.rbac.repository import RBACRepository


class AgentRepository:
    """Marker protocol; concrete implementations live in storage."""

    def get_agent(
        self, *, tenant_id: str, application_id: str, agent_id: str
    ) -> Agent | None: ...


class AgentContextResolver:
    """Builds an AgentContext used as the live policy snapshot for a run.

    The resolver is intentionally thin — it just orchestrates calls into the
    repositories and intersects the permission sets. The interesting policy
    logic lives in :class:`AuthorizationEngine`.
    """

    def __init__(
        self,
        rbac_repository: RBACRepository,
        agent_repository: AgentRepository,
    ) -> None:
        self.rbac = rbac_repository
        self.agents = agent_repository

    def resolve(
        self,
        *,
        tenant_id: str,
        application_id: str,
        user_id: str,
        agent_id: str,
    ) -> AgentContext:
        if not self.rbac.is_tenant_active(tenant_id):
            raise TenantNotActiveError(tenant_id)
        if not self.rbac.is_user_membership_active(
            tenant_id=tenant_id, application_id=application_id, user_id=user_id
        ):
            raise NoActiveMembershipError(user_id)
        agent = self.agents.get_agent(
            tenant_id=tenant_id, application_id=application_id, agent_id=agent_id
        )
        if agent is None:
            raise AgentNotFoundError(agent_id)
        if agent.status != "active":
            raise AgentNotActiveError(agent_id)

        user_perms = self.rbac.resolve_user_permissions(
            tenant_id=tenant_id, application_id=application_id, user_id=user_id
        )
        agent_perms = self.rbac.resolve_agent_permissions(
            tenant_id=tenant_id, application_id=application_id, agent_id=agent_id
        )
        tenant_perms = self.rbac.resolve_tenant_permissions(
            tenant_id=tenant_id, application_id=application_id
        )
        effective = user_perms & agent_perms
        if tenant_perms:
            effective = effective & tenant_perms

        return AgentContext(
            tenant_id=tenant_id,
            application_id=application_id,
            user_id=user_id,
            user_roles=frozenset(),  # populated by callers that need it
            user_permissions=frozenset(user_perms),
            agent_id=agent_id,
            agent_role=agent.role,
            agent_permissions=frozenset(agent_perms),
            effective_permissions=frozenset(effective),
        )
