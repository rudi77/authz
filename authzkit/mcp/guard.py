"""MCPGuard — Policy Enforcement Point for MCP tool calls."""

from __future__ import annotations

from collections.abc import Iterable

from authzkit.exceptions import PermissionDeniedError
from authzkit.mcp.models import MCP_NAMESPACE


class MCPGuard:
    """Permission gate for MCP tool calls.

    Mirrors :class:`ToolGuard` but folds the ``mcp.`` namespace into the
    check so callers can pass plain (server, action) pairs.
    """

    def __init__(self, permissions: Iterable[str]) -> None:
        self.permissions: set[str] = set(permissions)

    def is_allowed(self, server: str, action: str) -> bool:
        return f"{MCP_NAMESPACE}.{server}.{action}" in self.permissions

    def require(self, server: str, action: str) -> None:
        permission = f"{MCP_NAMESPACE}.{server}.{action}"
        if permission not in self.permissions:
            raise PermissionDeniedError(permission)

    def allowed_tools(self, server: str) -> list[str]:
        prefix = f"{MCP_NAMESPACE}.{server}."
        return [p[len(prefix):] for p in self.permissions if p.startswith(prefix)]
