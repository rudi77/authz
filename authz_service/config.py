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

    # ------------------------------------------------------------------
    # OAuth 2.0 — Resource Server (accept JWT-Bearer from external IdPs)
    # ------------------------------------------------------------------
    # Auto-enabled when issuers are configured. Set explicitly to false to
    # disable even if issuers are present (useful for staged rollout).
    oauth_resource_enabled: str = field(
        default_factory=lambda: os.environ.get("AUTHZ_OAUTH_RESOURCE_ENABLED", "auto").lower()
    )
    # Primary configuration: JSON array (see authz_service/oauth_config.py).
    # Tolerant to whitespace; empty string == no issuers.
    oauth_resource_issuers_json: str = field(
        default_factory=lambda: os.environ.get("AUTHZ_OAUTH_RESOURCE_ISSUERS", "")
    )
    # Alternative: load the same JSON from a file (for long configs / Kubernetes ConfigMap).
    oauth_resource_issuers_file: str | None = field(
        default_factory=lambda: os.environ.get("AUTHZ_OAUTH_RESOURCE_ISSUERS_FILE") or None
    )
    oauth_jwks_cache_ttl_seconds: int = field(
        default_factory=lambda: int(
            os.environ.get("AUTHZ_OAUTH_JWKS_CACHE_TTL_SECONDS", "600")
        )
    )

    # ------------------------------------------------------------------
    # OAuth 2.0 — Authorization Server (issue tokens via client_credentials)
    # ------------------------------------------------------------------
    oauth_as_enabled: bool = field(
        default_factory=lambda: os.environ.get("AUTHZ_OAUTH_AS_ENABLED", "false").lower()
        == "true"
    )
    oauth_issuer: str = field(
        default_factory=lambda: os.environ.get("AUTHZ_OAUTH_ISSUER", "")
    )
    # Default audience = issuer. CSV for multi-audience tokens.
    oauth_audience: str = field(
        default_factory=lambda: os.environ.get("AUTHZ_OAUTH_AUDIENCE", "")
    )
    oauth_access_token_ttl_seconds: int = field(
        default_factory=lambda: int(
            os.environ.get("AUTHZ_OAUTH_ACCESS_TOKEN_TTL_SECONDS", "3600")
        )
    )
    # PEM-encoded RSA private key. When set, this is the signing key.
    # When unset, the SigningKeyService falls back to the DB-backed table
    # and, in dev-mode + SQLite, will auto-generate an ephemeral key.
    oauth_signing_key_pem: str = field(
        default_factory=lambda: os.environ.get("AUTHZ_OAUTH_SIGNING_KEY_PEM", "")
    )
    oauth_signing_key_rotation_days: int = field(
        default_factory=lambda: int(
            os.environ.get("AUTHZ_OAUTH_SIGNING_KEY_ROTATION_DAYS", "90")
        )
    )

    # ------------------------------------------------------------------
    # OIDC login for /admin (Authorization Code + PKCE)
    # ------------------------------------------------------------------
    admin_oidc_enabled: str = field(
        default_factory=lambda: os.environ.get("AUTHZ_ADMIN_OIDC_ENABLED", "auto").lower()
    )
    admin_oidc_issuer: str = field(
        default_factory=lambda: os.environ.get("AUTHZ_ADMIN_OIDC_ISSUER", "")
    )
    admin_oidc_client_id: str = field(
        default_factory=lambda: os.environ.get("AUTHZ_ADMIN_OIDC_CLIENT_ID", "")
    )
    admin_oidc_client_secret: str = field(
        default_factory=lambda: os.environ.get("AUTHZ_ADMIN_OIDC_CLIENT_SECRET", "")
    )
    admin_oidc_redirect_uri: str = field(
        default_factory=lambda: os.environ.get("AUTHZ_ADMIN_OIDC_REDIRECT_URI", "")
    )
    admin_oidc_scopes: str = field(
        default_factory=lambda: os.environ.get(
            "AUTHZ_ADMIN_OIDC_SCOPES", "openid email profile"
        )
    )
    admin_oidc_groups_claim: str = field(
        default_factory=lambda: os.environ.get("AUTHZ_ADMIN_OIDC_GROUPS_CLAIM", "groups")
    )
    admin_oidc_admin_groups: tuple[str, ...] = field(
        default_factory=lambda: _csv_env("AUTHZ_ADMIN_OIDC_ADMIN_GROUPS")
    )
    admin_oidc_email_allowlist: tuple[str, ...] = field(
        default_factory=lambda: _csv_env("AUTHZ_ADMIN_OIDC_EMAIL_ALLOWLIST")
    )
    admin_oidc_session_ttl_seconds: int = field(
        default_factory=lambda: int(
            os.environ.get("AUTHZ_ADMIN_OIDC_SESSION_TTL_SECONDS", "28800")
        )
    )


def oauth_resource_is_enabled(settings: Settings) -> bool:
    """Resolve the OAuth Resource-Server enable flag.

    ``true`` / ``false`` force; ``auto`` (default) is on iff issuers are
    configured. We intentionally do not enable RS without issuers — the
    request would just 401 every Bearer-JWT call with no clear reason.
    """
    raw = settings.oauth_resource_enabled.lower()
    if raw == "true":
        return True
    if raw == "false":
        return False
    return bool(settings.oauth_resource_issuers_json.strip()) or bool(
        settings.oauth_resource_issuers_file
    )


def admin_oidc_is_enabled(settings: Settings) -> bool:
    """Resolve the Admin-UI OIDC enable flag (analogous to oauth_resource)."""
    raw = settings.admin_oidc_enabled.lower()
    if raw == "true":
        return True
    if raw == "false":
        return False
    return bool(settings.admin_oidc_issuer and settings.admin_oidc_client_id)


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
