"""ToolDescriptor + ToolRegistry — declarative metadata for tool calls."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolDescriptor:
    """Metadata for a tool that an agent might call.

    A descriptor declares which (resource, action) pairs map to which tool
    method names. ToolGuard uses this to translate a tool call into a
    permission check without hard-coding the mapping.
    """

    name: str
    namespace: str
    actions: frozenset[str] = field(default_factory=frozenset)
    description: str | None = None

    def permission_for(self, action: str) -> str:
        return f"{self.namespace}.{self.name}.{action}"


class ToolRegistry:
    """In-memory registry mapping tool names to descriptors."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDescriptor] = {}

    def register(self, descriptor: ToolDescriptor) -> None:
        key = f"{descriptor.namespace}.{descriptor.name}"
        self._tools[key] = descriptor

    def get(self, namespace: str, name: str) -> ToolDescriptor | None:
        return self._tools.get(f"{namespace}.{name}")

    def all(self) -> list[ToolDescriptor]:
        return list(self._tools.values())
