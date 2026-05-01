"""MCP server / tool descriptor models."""

from __future__ import annotations

from dataclasses import dataclass, field

MCP_NAMESPACE = "mcp"


@dataclass(frozen=True)
class MCPTool:
    """A single MCP tool exposed by an MCP server.

    Permission name format: ``mcp.<server>.<action>``. The server is the
    discriminator; the action is the trailing segment that maps onto an
    MCP server's exposed methods (e.g. ``read_repo``, ``create_issue``).
    """

    server: str
    action: str
    description: str | None = None

    @property
    def permission(self) -> str:
        return f"{MCP_NAMESPACE}.{self.server}.{self.action}"


@dataclass(frozen=True)
class MCPServer:
    name: str
    tools: frozenset[MCPTool] = field(default_factory=frozenset)
    description: str | None = None

    def permissions(self) -> set[str]:
        return {t.permission for t in self.tools}
