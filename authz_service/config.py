"""Service configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _csv_env(key: str, default: str = "") -> tuple[str, ...]:
    raw = os.environ.get(key, default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "AUTHZ_DATABASE_URL", "sqlite+pysqlite:///./authz.db"
        )
    )
    api_keys: tuple[str, ...] = field(default_factory=lambda: _csv_env("AUTHZ_API_KEYS"))
    log_level: str = field(default_factory=lambda: os.environ.get("AUTHZ_LOG_LEVEL", "INFO"))
    audit_all_decisions: bool = field(
        default_factory=lambda: os.environ.get("AUTHZ_AUDIT_ALL", "false").lower() == "true"
    )
    auto_provision_user: bool = field(
        default_factory=lambda: os.environ.get("AUTHZ_AUTO_PROVISION_USER", "true").lower()
        == "true"
    )
    auto_provision_tenant: bool = field(
        default_factory=lambda: os.environ.get("AUTHZ_AUTO_PROVISION_TENANT", "false").lower()
        == "true"
    )
    # Default empty: production must opt-in to specific origins. The legacy
    # `*` default was permissive in a way that surprises operators promoting
    # a dev image to production. `*` is still allowed but only when paired
    # with AUTHZ_DEV_MODE=true (enforced at app startup).
    cors_allow_origins: tuple[str, ...] = field(
        default_factory=lambda: _csv_env("AUTHZ_CORS_ORIGINS", "")
    )
    # Explicit opt-in for permissive behaviour (no API keys → accept any
    # caller, CORS=* allowed). Without this flag the service is fail-closed.
    # The parser is intentionally strict (only literal ``true`` enables
    # dev mode) so a typo like ``AUTHZ_DEV_MODE=enabled`` falls back to
    # the safe default.
    dev_mode: bool = field(
        default_factory=lambda: os.environ.get("AUTHZ_DEV_MODE", "false").lower()
        == "true"
    )
    rate_limit_per_minute: int = field(
        default_factory=lambda: int(os.environ.get("AUTHZ_RATE_LIMIT_PER_MINUTE", "0"))
    )
    redis_url: str | None = field(
        default_factory=lambda: os.environ.get("AUTHZ_REDIS_URL") or None
    )
    audit_retention_days: int = field(
        default_factory=lambda: int(os.environ.get("AUTHZ_AUDIT_RETENTION_DAYS", "0"))
    )
    audit_prune_interval_seconds: int = field(
        default_factory=lambda: int(
            os.environ.get("AUTHZ_AUDIT_PRUNE_INTERVAL_SECONDS", "3600")
        )
    )
    auto_create_schema: bool = field(
        default_factory=lambda: os.environ.get(
            "AUTHZ_AUTO_CREATE_SCHEMA",
            # Default: yes for SQLite (dev/test), no for everything else (prod
            # must use Alembic — single source of truth).
            "auto",
        ).lower()
        in ("true", "1", "yes")
    )


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def override_settings(settings: Settings) -> None:
    """Test hook to swap settings."""
    global _settings
    _settings = settings


def should_auto_create_schema(settings: Settings) -> bool:
    """Resolve the auto-create-schema decision.

    Explicit env override wins. Otherwise: SQLite (in-memory or file) gets
    auto-create because Alembic isn't typically used there; everything else
    defers to Alembic and refuses to silently mutate the schema.
    """
    raw = os.environ.get("AUTHZ_AUTO_CREATE_SCHEMA", "auto").lower()
    if raw in ("true", "1", "yes"):
        return True
    if raw in ("false", "0", "no"):
        return False
    return settings.database_url.startswith("sqlite")
