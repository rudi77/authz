"""Convenience helpers for agent runs.

Bundles ``effective_permissions`` preload + AgentGuard creation so an agent
runtime can spin up a guard with one call (spec section 12).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from authz_sdk.client import AuthzClient, Subject
from authzkit.agents.guard import AgentGuard
from authzkit.agents.models import AgentContext


def start_agent_session(
    client: AuthzClient,
    *,
    tenant_id: str,
    application_id: str,
    user_id: str,
    agent_id: str,
    agent_role: str = "",
    critical_actions: Iterable[str] | None = None,
    delegation_token: str | None = None,
) -> AgentGuard:
    """Preload effective permissions and return an AgentGuard for the run.

    Critical actions opt in to remote revalidation: when a critical permission
    is required, the guard re-asks the service rather than trusting the
    snapshot. See spec section 14.3.
    """
    subject = Subject(type="agent", user_id=user_id, agent_id=agent_id)
    permissions = client.get_effective_permissions(
        tenant_id=tenant_id,
        application_id=application_id,
        subject=subject,
        delegation_token=delegation_token,
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
            delegation_token=delegation_token,
        )

    return AgentGuard(
        context,
        critical_actions=critical_actions or [],
        revalidate=revalidate,
    )


def delegation_claims(token: str) -> dict[str, Any]:
    """Read a grant's routing claims *without* verifying it.

    Only for picking tenant / application / user / agent ids; the service
    verifies the signature and revocation on every call that carries it.
    """
    import jwt

    claims = jwt.decode(token, options={"verify_signature": False})
    body = claims.get("authz") or {}
    return {
        "delegation_id": claims.get("jti"),
        "tenant_id": body.get("tenant_id"),
        "application_id": body.get("application_id"),
        "user_id": claims.get("sub"),
        "agent_id": (claims.get("act") or {}).get("sub"),
        "permissions": list(body.get("permissions") or ()),
        "purpose": body.get("purpose"),
        "expires_at": claims.get("exp"),
    }


def start_delegated_agent_session(
    client: AuthzClient,
    delegation_token: str,
    *,
    agent_role: str = "",
    critical_actions: Iterable[str] | None = None,
) -> AgentGuard:
    """Start an agent run from nothing but a delegation grant.

    The agent runtime only needs its grant (plus a runtime credential for
    the service); tenant, application, user and agent come from the token.
    """
    c = delegation_claims(delegation_token)
    return start_agent_session(
        client,
        tenant_id=c["tenant_id"],
        application_id=c["application_id"],
        user_id=c["user_id"],
        agent_id=c["agent_id"],
        agent_role=agent_role,
        critical_actions=critical_actions,
        delegation_token=delegation_token,
    )
