"""AgentGuard — Policy Enforcement Point used inside an agent run."""

from __future__ import annotations

from collections.abc import Iterable

from authzkit.agents.models import AgentContext
from authzkit.exceptions import PermissionDeniedError


class AgentGuard:
    """Local in-process guard that enforces decisions during an agent run.

    Holds the precomputed effective permissions set so each tool call is a
    set membership check rather than a remote round-trip. For "critical"
    actions, callers may pass ``critical=True`` to opt into a remote
    revalidation hook (the hook is configured by the SDK layer).
    """

    def __init__(
        self,
        context: AgentContext,
        *,
        critical_actions: Iterable[str] | None = None,
        revalidate=None,
    ) -> None:
        self.context = context
        self.permissions = set(context.effective_permissions)
        self.critical_actions = set(critical_actions or [])
        self._revalidate = revalidate

    def is_allowed(self, resource: str, action: str) -> bool:
        return f"{resource}.{action}" in self.permissions

    def require(self, resource: str, action: str, *, critical: bool = False) -> None:
        permission = f"{resource}.{action}"
        if permission not in self.permissions:
            raise PermissionDeniedError(permission)
        if (critical or permission in self.critical_actions) and self._revalidate is not None:
            allowed = self._revalidate(self.context, resource, action)
            if not allowed:
                raise PermissionDeniedError(permission, "revalidation denied")
