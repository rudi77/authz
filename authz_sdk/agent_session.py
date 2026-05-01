"""Convenience helpers for agent runs.

Bundles ``effective_permissions`` preload + AgentGuard creation so an agent
runtime can spin up a guard with one call (spec section 12).
"""

from __future__ import annotations

from collections.abc import Iterable

from authzkit.agents.guard import AgentGuard
from authzkit.agents.models import AgentContext
from authz_sdk.client import AuthzClient, Subject


def start_agent_session(
    client: AuthzClient,
    *,
    tenant_id: str,
    application_id: str,
    user_id: str,
    agent_id: str,
    agent_role: str = "",
    critical_actions: Iterable[str] | None = None,
) -> AgentGuard:
    """Preload effective permissions and return an AgentGuard for the run.

    Critical actions opt in to remote revalidation: when a critical permission
    is required, the guard re-asks the service rather than trusting the
    snapshot. See spec section 14.3.
    """
    subject = Subject(type="agent", user_id=user_id, agent_id=agent_id)
    permissions = client.get_effective_permissions(
        tenant_id=tenant_id, application_id=application_id, subject=subject
    )
    context = AgentContext(
        tenant_id=tenant_id,
        application_id=application_id,
        user_id=user_id,
        user_roles=frozenset(),
        user_permissions=frozenset(),
        agent_id=agent_id,
        agent_role=agent_role,
        agent_permissions=frozenset(),
        effective_permissions=frozenset(permissions),
    )

    def revalidate(_ctx: AgentContext, resource: str, action: str) -> bool:
        return client.authorize(
            tenant_id=tenant_id,
            application_id=application_id,
            subject=subject,
            resource=resource,
            action=action,
        )

    return AgentGuard(
        context,
        critical_actions=critical_actions or [],
        revalidate=revalidate,
    )
