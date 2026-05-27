"""Background workers for OAuth-related housekeeping.

Two thin janitors that mirror :class:`~authz_service.audit_retention.AuditRetentionWorker`:

- :class:`AdminSessionJanitor` — prunes expired admin sessions and
  expired in-flight login attempts (the PKCE/state holding rows).
- :class:`SigningKeyJanitor` — demotes ``retiring`` signing keys to
  ``revoked`` once the grace period has elapsed.

Both are no-ops when their feature is disabled, so the FastAPI startup
hook can wire them up unconditionally.
"""

from __future__ import annotations

import logging
import threading

import structlog

from authzkit.security.sessions import AdminSessionService
from authzkit.security.signing_keys import SigningKeyService

_log = logging.getLogger("authz.oauth_janitor")


class _IntervalThreadBase:
    """Shared start/stop scaffolding for daemon-thread janitors."""

    def __init__(self, *, name: str, interval_seconds: int) -> None:
        self._name = name
        self._interval = max(60, interval_seconds)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._slog = structlog.get_logger(name)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=self._name, daemon=True)
        self._thread.start()
        self._slog.info(f"{self._name} worker started", interval_seconds=self._interval)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _run(self) -> None:
        self._tick()
        while not self._stop.wait(self._interval):
            self._tick()

    def _tick(self) -> None:  # pragma: no cover - subclassed
        raise NotImplementedError


class AdminSessionJanitor(_IntervalThreadBase):
    """Periodically delete expired admin sessions + stale login attempts."""

    def __init__(
        self, sessions: AdminSessionService, *, interval_seconds: int = 3600
    ) -> None:
        super().__init__(name="authz.admin_sessions", interval_seconds=interval_seconds)
        self._sessions = sessions

    def _tick(self) -> None:
        try:
            removed = self._sessions.prune_expired()
            if removed:
                self._slog.info("expired admin sessions pruned", removed=removed)
        except Exception as exc:  # pragma: no cover - defensive
            self._slog.warning("admin-session prune failed", error=str(exc))


class SigningKeyJanitor(_IntervalThreadBase):
    """Periodically demote retiring signing keys to revoked."""

    def __init__(
        self,
        signing_keys: SigningKeyService,
        *,
        max_token_ttl_seconds: int,
        interval_seconds: int = 3600,
    ) -> None:
        super().__init__(name="authz.signing_keys", interval_seconds=interval_seconds)
        self._signing_keys = signing_keys
        self._max_token_ttl = max_token_ttl_seconds

    def _tick(self) -> None:
        try:
            revoked = self._signing_keys.prune_retiring(
                max_token_ttl_seconds=self._max_token_ttl
            )
            if revoked:
                self._slog.info("retiring signing keys revoked", revoked=revoked)
        except Exception as exc:  # pragma: no cover - defensive
            self._slog.warning("signing-key prune failed", error=str(exc))
