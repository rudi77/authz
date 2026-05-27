"""FastAPI app factory and uvicorn entry point."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import structlog
from fastapi import Depends, FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Engine, text

if TYPE_CHECKING:
    from structlog.stdlib import BoundLogger

    from authz_service.config import Settings

from authz_service.api.agents import router as agents_router
from authz_service.api.api_keys import router as api_keys_router
from authz_service.api.applications import router as applications_router
from authz_service.api.authorize import router as authorize_router
from authz_service.api.context import router as context_router
from authz_service.api.invitations import router as invitations_router
from authz_service.api.oauth import admin_router as oauth_admin_router
from authz_service.api.oauth import as_router as oauth_as_router
from authz_service.api.oauth_clients import router as oauth_clients_router
from authz_service.api.permissions import router as permissions_router
from authz_service.api.policies import router as memberships_router
from authz_service.api.roles import router as roles_router
from authz_service.api.tenants import router as tenants_router
from authz_service.audit_retention import AuditRetentionWorker
from authz_service.config import (
    admin_oidc_is_enabled,
    get_settings,
    oauth_resource_is_enabled,
)
from authz_service.dependencies import get_engine
from authz_service.middleware import (
    IdempotencyMiddleware,
    RateLimitMiddleware,
    build_idempotency_store,
    build_rate_limiter,
)
from authz_service.oauth_janitor import AdminSessionJanitor, SigningKeyJanitor
from authz_service.observability import (
    RequestContextMiddleware,
    configure_logging,
    init_tracing,
    instrument_fastapi,
    render_metrics,
)

_ADMIN_UI_DIR = Path(__file__).parent / "ui"


def _enforce_startup_safety(settings: Settings, log: BoundLogger) -> None:
    """Fail-closed startup checks for dangerous configurations.

    Three production-hostile shapes are blocked here:

    1. ``CORS=*`` outside dev mode.
    2. Dev mode with no keys *and* no OAuth issuers — accepts every caller;
       logged loudly because it cannot be missed in container logs.
    3. AS enabled with no signing key configured and no DB fallback path —
       loaded lazily so the failure surfaces on first ``/oauth/token`` call,
       but we log a warning at startup so operators see it before traffic.
    """
    cors = settings.cors_allow_origins
    cors_is_wildcard = "*" in cors
    if cors_is_wildcard and not settings.dev_mode:
        raise RuntimeError(
            "AUTHZ_CORS_ORIGINS contains '*' but AUTHZ_DEV_MODE is not enabled. "
            "Refusing to start with permissive CORS in non-dev mode. "
            "Set explicit origins (e.g. 'https://admin.example.com') or "
            "set AUTHZ_DEV_MODE=true for local development."
        )
    if settings.dev_mode:
        log.warning(
            "AUTHZ_DEV_MODE=true — service will accept any caller when no "
            "API keys are configured. NEVER set this in production.",
        )
        if not settings.api_keys and not oauth_resource_is_enabled(settings):
            log.warning(
                "AUTHZ_API_KEYS is empty, no OAuth issuers configured, and "
                "AUTHZ_DEV_MODE=true — every request will be authenticated "
                "as 'dev-mode' admin until a real credential is provisioned "
                "(which auto-locks the service).",
            )

    if settings.oauth_as_enabled:
        if not settings.oauth_issuer:
            raise RuntimeError(
                "AUTHZ_OAUTH_AS_ENABLED=true but AUTHZ_OAUTH_ISSUER is empty. "
                "Set the public issuer URL (e.g. https://authz.example.com)."
            )
        if not settings.oauth_signing_key_pem and not settings.dev_mode:
            log.warning(
                "AUTHZ_OAUTH_AS_ENABLED=true but no AUTHZ_OAUTH_SIGNING_KEY_PEM "
                "set; signing key will be loaded from the DB. Run "
                "`authz oauth signing-key generate` if no key exists yet.",
            )

    if admin_oidc_is_enabled(settings):
        missing = [
            name
            for name, value in (
                ("AUTHZ_ADMIN_OIDC_ISSUER", settings.admin_oidc_issuer),
                ("AUTHZ_ADMIN_OIDC_CLIENT_ID", settings.admin_oidc_client_id),
                ("AUTHZ_ADMIN_OIDC_CLIENT_SECRET", settings.admin_oidc_client_secret),
                ("AUTHZ_ADMIN_OIDC_REDIRECT_URI", settings.admin_oidc_redirect_uri),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(
                "Admin OIDC enabled but missing: " + ", ".join(missing)
            )


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    log = structlog.get_logger("authz")

    if os.environ.get("AUTHZ_OTEL_ENABLED", "false").lower() == "true":
        init_tracing()

    _enforce_startup_safety(settings, log)

    app = FastAPI(
        title="AuthZ Service",
        description=(
            "Multi-tenant authorization decision service for apps, agents, and MCP tools."
        ),
        version="0.2.0",
    )

    rate_limiter = build_rate_limiter(settings.rate_limit_per_minute, settings.redis_url)
    idempotency_store = build_idempotency_store(settings.redis_url)
    # Stash the shared limiter so the /oauth/token route can reuse it for
    # per-client_id buckets without having to peek the request body in the
    # global middleware (which would consume the form for the route handler).
    app.state.rate_limiter = rate_limiter

    # Middleware execution order is reverse of registration. Runtime order:
    # request-context (innermost) -> rate-limit -> idempotency -> CORS (outer).
    # Note: starlette runs middleware in reverse-add order, so the *last*
    # registered middleware is the outermost wrapper.
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        limit_per_minute=settings.rate_limit_per_minute,
        limiter=rate_limiter,
    )
    app.add_middleware(IdempotencyMiddleware, store=idempotency_store)
    # CORS: dev mode keeps the wildcard surface for convenience. Outside
    # dev mode we restrict to the methods and headers the service actually
    # serves; arbitrary cross-origin TRACE / X-Custom-* requests are
    # rejected at the preflight.
    if settings.dev_mode:
        cors_methods: list[str] = ["*"]
        cors_headers: list[str] = ["*"]
    else:
        cors_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        cors_headers = [
            "Authorization",
            "Content-Type",
            "Idempotency-Key",
            "X-API-Key",
            "X-CSRF-Token",
            "X-Request-Id",
        ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_methods=cors_methods,
        allow_headers=cors_headers,
        allow_credentials=admin_oidc_is_enabled(settings),
    )

    app.include_router(authorize_router)
    app.include_router(context_router)
    app.include_router(tenants_router)
    app.include_router(applications_router)
    app.include_router(memberships_router)
    app.include_router(roles_router)
    app.include_router(permissions_router)
    app.include_router(agents_router)
    app.include_router(api_keys_router)
    app.include_router(invitations_router)

    # OAuth: each half toggles independently.
    if settings.oauth_as_enabled:
        app.include_router(oauth_as_router)
        app.include_router(oauth_clients_router)
    if admin_oidc_is_enabled(settings):
        app.include_router(oauth_admin_router)

    @app.get("/healthz", tags=["meta"])
    def healthz(engine: Annotated[Engine, Depends(get_engine)]) -> JSONResponse:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return JSONResponse({"status": "ok", "database": "ok"})
        except Exception as e:
            # JSONResponse handles escaping; an exception message containing
            # quotes or braces no longer corrupts the body.
            return JSONResponse(
                status_code=503,
                content={"status": "degraded", "database": f"error: {e!s}"},
            )

    @app.get("/readyz", tags=["meta"])
    def readyz(engine: Annotated[Engine, Depends(get_engine)]) -> dict:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ready"}

    @app.get("/metrics", tags=["meta"], include_in_schema=False)
    def metrics() -> Response:
        body, content_type = render_metrics()
        return Response(content=body, media_type=content_type)

    @app.get("/", tags=["meta"])
    def root() -> dict:
        endpoints = [
            "/v1/resolve-context",
            "/v1/authorize",
            "/v1/bulk-authorize",
            "/v1/effective-permissions",
            "/healthz",
            "/readyz",
            "/metrics",
            "/admin",
        ]
        if settings.oauth_as_enabled:
            endpoints.extend(
                [
                    "/oauth/token",
                    "/.well-known/oauth-authorization-server",
                    "/.well-known/jwks.json",
                ]
            )
        if admin_oidc_is_enabled(settings):
            endpoints.extend(
                ["/oauth/login", "/oauth/callback", "/oauth/logout", "/admin/session"]
            )
        return {
            "service": "authz",
            "version": app.version,
            "endpoints": endpoints,
        }

    # Static admin UI — served only when the asset directory exists.
    if _ADMIN_UI_DIR.exists():
        app.mount("/admin", StaticFiles(directory=str(_ADMIN_UI_DIR), html=True), name="admin")

    instrument_fastapi(app)

    # Background workers managed by FastAPI lifecycle hooks.
    retention_worker: AuditRetentionWorker | None = None
    session_janitor: AdminSessionJanitor | None = None
    signing_key_janitor: SigningKeyJanitor | None = None

    @app.on_event("startup")
    def _startup() -> None:
        nonlocal retention_worker, session_janitor, signing_key_janitor
        engine = get_engine(settings)
        from authzkit.storage.sqlalchemy import SqlAlchemyStore

        store = SqlAlchemyStore(engine)
        if settings.audit_retention_days > 0:
            retention_worker = AuditRetentionWorker(
                store,
                retention_days=settings.audit_retention_days,
                interval_seconds=settings.audit_prune_interval_seconds,
            )
            retention_worker.start()
        if admin_oidc_is_enabled(settings):
            from authzkit.security.sessions import AdminSessionService

            session_janitor = AdminSessionJanitor(
                AdminSessionService(
                    store, session_ttl_seconds=settings.admin_oidc_session_ttl_seconds
                )
            )
            session_janitor.start()
        if settings.oauth_as_enabled:
            from authzkit.security.signing_keys import SigningKeyService

            signing_key_janitor = SigningKeyJanitor(
                SigningKeyService(
                    store,
                    env_pem=settings.oauth_signing_key_pem,
                    dev_mode=settings.dev_mode,
                    database_url=settings.database_url,
                ),
                max_token_ttl_seconds=settings.oauth_access_token_ttl_seconds,
            )
            signing_key_janitor.start()

    @app.on_event("shutdown")
    def _shutdown() -> None:
        if retention_worker is not None:
            retention_worker.stop()
        if session_janitor is not None:
            session_janitor.stop()
        if signing_key_janitor is not None:
            signing_key_janitor.stop()

    return app


app = create_app()


def run() -> None:
    """Console-script entry point used by ``authz-service``."""
    import uvicorn

    uvicorn.run("authz_service.main:app", host="0.0.0.0", port=8080, reload=False)


if __name__ == "__main__":
    run()
