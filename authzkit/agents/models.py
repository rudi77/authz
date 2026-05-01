"""Agent data models and AgentContext."""

from __future__ import annotations

from dataclasses import dataclass, field

AGENT_STATUS_ACTIVE = "active"
AGENT_STATUS_DISABLED = "disabled"
AGENT_STATUS_DELETED = "deleted"


@dataclass(frozen=True)
class Agent:
    """An executable AI unit scoped to a (tenant, application) pair."""

    id: str
    tenant_id: str
    application_id: str
    name: str
    role: str = ""  # primary role label; full role list lives in agent_roles
    status: str = AGENT_STATUS_ACTIVE
    created_by_user_id: str | None = None


@dataclass(frozen=True)
class AgentContext:
    """The materialized authorization context used during an agent run."""

    tenant_id: str
    application_id: str
    user_id: str
    user_roles: frozenset[str]
    user_permissions: frozenset[str]
    agent_id: str
    agent_role: str
    agent_permissions: frozenset[str]
    effective_permissions: frozenset[str] = field(default_factory=frozenset)
