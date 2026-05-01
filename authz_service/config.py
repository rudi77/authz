"""Service configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "AUTHZ_DATABASE_URL", "sqlite+pysqlite:///./authz.db"
        )
    )
    api_keys: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            k for k in os.environ.get("AUTHZ_API_KEYS", "").split(",") if k
        )
    )
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
