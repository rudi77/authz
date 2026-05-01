"""Python SDK for the AuthZ Service.

Re-exports :class:`ToolGuard` / :class:`MCPGuard` from authzkit so applications
that already depend on the SDK get them without importing the core library.
"""

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
    "AgentGuard",
    "AuthzClient",
    "AuthzClientError",
    "AuthzServiceError",
    "BulkCheck",
    "BulkCheckResult",
    "MCPGuard",
    "PermissionDeniedError",
    "ResolvedContext",
    "Subject",
    "ToolGuard",
]
