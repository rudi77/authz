"""Audit log retention.

Two pieces:

- :func:`prune_audit_log` — synchronous helper that deletes audit rows
  older than the configured retention window. Idempotent and safe to
  invoke from a CLI cron job.
- :class:`AuditRetentionWorker` — optional background thread that calls
  the helper on a fixed interval. Spawned at app startup when retention
  is enabled.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import delete

from authzkit.storage import orm
from authzkit.storage.sqlalchemy import SqlAlchemyStore


_log = logging.getLogger("authz.retention")


def prune_audit_log(store: SqlAlchemyStore, *, retention_days: int) -> int:
    """Delete audit rows older than ``retention_days``. Returns row count.

    Implemented as a single ``DELETE WHERE created_at < cutoff`` because
    Postgres handles that efficiently and the audit table doesn't fan out
    via foreign keys.
    """
    if retention_days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    with store.session() as s:
        result = s.execute(
            delete(orm.AuditLog).where(orm.AuditLog.created_at < cutoff)
        )
        s.commit()
        return result.rowcount or 0


class AuditRetentionWorker:
    """Background thread that prunes the audit log on a fixed interval.

    Instantiate at app startup; call ``start()`` to spin up the daemon
    thread and ``stop()`` to ask for graceful shutdown. Errors are logged
    and absorbed — a transient DB blip should not crash the process.
    """

    def __init__(
        self,
        store: SqlAlchemyStore,
        *,
        retention_days: int,
        interval_seconds: int = 3600,
    ) -> None:
        self.store = store
        self.retention_days = retention_days
        self.interval_seconds = max(60, interval_seconds)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._slog = structlog.get_logger("authz.retention")

    def start(self) -> None:
        if self.retention_days <= 0:
            self._slog.info(
                "audit retention disabled (AUTHZ_AUDIT_RETENTION_DAYS<=0); worker not started"
            )
            return
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="audit-retention", daemon=True
        )
        self._thread.start()
        self._slog.info(
            "audit retention worker started",
            retention_days=self.retention_days,
            interval_seconds=self.interval_seconds,
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _run(self) -> None:
        # Run once at startup so a freshly deployed instance honors retention
        # without waiting an entire interval.
        self._tick()
        while not self._stop.wait(self.interval_seconds):
            self._tick()

    def _tick(self) -> None:
        try:
            deleted = prune_audit_log(
                self.store, retention_days=self.retention_days
            )
            if deleted:
                self._slog.info("audit log pruned", deleted=deleted)
        except Exception as e:  # pragma: no cover - defensive
            self._slog.warning("audit prune failed", error=str(e))
