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
from authz_service.api.permissions import router as permissions_router
from authz_service.api.policies import router as memberships_router
from authz_service.api.roles import router as roles_router
from authz_service.api.tenants import router as tenants_router
from authz_service.audit_retention import AuditRetentionWorker
from authz_service.config import get_settings
from authz_service.dependencies import get_engine
from authz_service.middleware import (
    IdempotencyMiddleware,
    RateLimitMiddleware,
    build_idempotency_store,
    build_rate_limiter,
)
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

    Two production-hostile defaults from earlier versions are blocked here:

    1. CORS=*: only allowed when AUTHZ_DEV_MODE=true. Otherwise startup
       refuses, because a permissive CORS policy on an admin/runtime
       service is almost never what an operator intended.
    2. Dev mode without keys: when AUTHZ_DEV_MODE=true and no API keys
       exist, the service accepts every caller — log this loudly so it
       cannot be missed in container logs.
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
        if not settings.api_keys:
            log.warning(
                "AUTHZ_API_KEYS is empty and AUTHZ_DEV_MODE=true — every "
                "request will be authenticated as 'dev-mode' admin until a "
                "DB-backed key is provisioned (which auto-locks the service).",
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
            "X-Request-Id",
        ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_methods=cors_methods,
        allow_headers=cors_headers,
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
        return {
            "service": "authz",
            "version": app.version,
            "endpoints": [
                "/v1/resolve-context",
                "/v1/authorize",
                "/v1/bulk-authorize",
                "/v1/effective-permissions",
                "/healthz",
                "/readyz",
                "/metrics",
                "/admin",
            ],
        }

    # Static admin UI — served only when the asset directory exists.
    if _ADMIN_UI_DIR.exists():
        app.mount("/admin", StaticFiles(directory=str(_ADMIN_UI_DIR), html=True), name="admin")

    instrument_fastapi(app)

    # Background workers managed by FastAPI lifecycle hooks.
    retention_worker: AuditRetentionWorker | None = None

    @app.on_event("startup")
    def _startup() -> None:
        nonlocal retention_worker
        if settings.audit_retention_days > 0:
            engine = get_engine(settings)
            from authzkit.storage.sqlalchemy import SqlAlchemyStore

            store = SqlAlchemyStore(engine)
            retention_worker = AuditRetentionWorker(
                store,
                retention_days=settings.audit_retention_days,
                interval_seconds=settings.audit_prune_interval_seconds,
            )
            retention_worker.start()

    @app.on_event("shutdown")
    def _shutdown() -> None:
        if retention_worker is not None:
            retention_worker.stop()

    return app


app = create_app()


def run() -> None:
    """Console-script entry point used by ``authz-service``."""
    import uvicorn

    uvicorn.run("authz_service.main:app", host="0.0.0.0", port=8080, reload=False)


if __name__ == "__main__":
    run()
