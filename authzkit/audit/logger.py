"""AuditEntry + pluggable AuditLogger interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol


@dataclass(frozen=True)
class AuditEntry:
    decision: str
    reason: str
    resource: str
    action: str
    tenant_id: str | None = None
    application_id: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    request_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AuditLogger(Protocol):
    """Sink for authorization decision audit records."""

    def write(self, entry: AuditEntry) -> None: ...


class NullAuditLogger:
    """No-op logger for tests and minimal embedded use cases."""

    def write(self, entry: AuditEntry) -> None:  # noqa: D401 - protocol impl
        return None
