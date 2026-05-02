"""Python SDK for the AuthZ Service.

Re-exports :class:`ToolGuard` / :class:`MCPGuard` from authzkit so applications
that already depend on the SDK get them without importing the core library.
"""

from authz_sdk.admin import (
    Agent,
    ApiKey,
    Application,
    AuthzAdminClient,
    Invitation,
    Membership,
    Permission,
    Role,
    Tenant,
)
from authz_sdk.client import (
    AuthzClient,
    AuthzClientError,
    AuthzServiceError,
    BulkCheck,
    BulkCheckResult,
    ResolvedContext,
    Subject,
)
from authzkit.agents.guard import AgentGuard
from authzkit.exceptions import PermissionDeniedError
from authzkit.mcp.guard import MCPGuard
from authzkit.tools.guard import ToolGuard

__all__ = [
    "Agent",
    "AgentGuard",
    "ApiKey",
    "Application",
    "AuthzAdminClient",
    "AuthzClient",
    "AuthzClientError",
    "AuthzServiceError",
    "BulkCheck",
    "BulkCheckResult",
    "Invitation",
    "MCPGuard",
    "Membership",
    "Permission",
    "PermissionDeniedError",
    "ResolvedContext",
    "Role",
    "Subject",
    "Tenant",
    "ToolGuard",
]
