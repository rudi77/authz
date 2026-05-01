"""authzkit — Multi-Tenant Authorization Core Library.

Reusable building blocks for identity normalization, tenant context resolution,
RBAC checks, and agent/tool/MCP authorization. Used directly in Python projects
and as the foundation of the Authorization Service.
"""

from authzkit.agents.guard import AgentGuard
from authzkit.agents.models import Agent, AgentContext
from authzkit.exceptions import (
    AgentNotActiveError,
    AgentNotFoundError,
    AuthzError,
    InvalidRequestError,
    InvalidSubjectError,
    NoActiveMembershipError,
    PermissionDeniedError,
    PolicyConditionFailedError,
    TenantFeatureDisabledError,
    TenantNotActiveError,
)
from authzkit.identity.base import IdentityPrincipal, normalize_principal
from authzkit.mcp.guard import MCPGuard
from authzkit.rbac.checker import AuthorizationEngine, AuthorizeDecision, AuthorizeRequest, Subject
from authzkit.rbac.models import Permission, Role
from authzkit.tenancy.models import Application, Membership, Tenant, User
from authzkit.tools.guard import ToolGuard

__all__ = [
    "Agent",
    "AgentContext",
    "AgentGuard",
    "AgentNotActiveError",
    "AgentNotFoundError",
    "Application",
    "AuthorizationEngine",
    "AuthorizeDecision",
    "AuthorizeRequest",
    "AuthzError",
    "IdentityPrincipal",
    "InvalidRequestError",
    "InvalidSubjectError",
    "MCPGuard",
    "Membership",
    "NoActiveMembershipError",
    "Permission",
    "PermissionDeniedError",
    "PolicyConditionFailedError",
    "Role",
    "Subject",
    "Tenant",
    "TenantFeatureDisabledError",
    "TenantNotActiveError",
    "ToolGuard",
    "User",
    "normalize_principal",
]

__version__ = "0.1.0"
