"""ToolGuard — local Policy Enforcement Point for tool calls."""

from __future__ import annotations

from collections.abc import Iterable

from authzkit.exceptions import PermissionDeniedError


class ToolGuard:
    """Lightweight permission check used at tool invocation sites.

    Matches the spec example in section 12.2 — a small, in-process,
    embeddable guard whose only job is to refuse calls when the precomputed
    effective permissions set doesn't contain the required permission.
    """

    def __init__(self, permissions: Iterable[str]) -> None:
        self.permissions: set[str] = set(permissions)

    def is_allowed(self, resource: str, action: str) -> bool:
        return f"{resource}.{action}" in self.permissions

    def require(self, resource: str, action: str) -> None:
        permission = f"{resource}.{action}"
        if permission not in self.permissions:
            raise PermissionDeniedError(permission)

    def filter_allowed(self, checks: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
        return [(r, a) for r, a in checks if f"{r}.{a}" in self.permissions]
