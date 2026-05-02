"""FastAPI app factory and uvicorn entry point."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import structlog
from fastapi import Depends, FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Engine, text

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


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    log = structlog.get_logger("authz")

    if os.environ.get("AUTHZ_OTEL_ENABLED", "false").lower() == "true":
        init_tracing()

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
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        limit_per_minute=settings.rate_limit_per_minute,
        limiter=rate_limiter,
    )
    app.add_middleware(IdempotencyMiddleware, store=idempotency_store)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if not settings.api_keys:
        log.warning(
            "AUTHZ_API_KEYS is empty; service starts in dev mode and will accept "
            "any caller until at least one DB-backed API key is provisioned."
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
    def healthz(engine: Annotated[Engine, Depends(get_engine)]) -> dict:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return {"status": "ok", "database": "ok"}
        except Exception as e:
            return Response(  # type: ignore[return-value]
                status_code=503,
                content=f'{{"status":"degraded","database":"error: {e!s}"}}',
                media_type="application/json",
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
