"""FastAPI app factory and uvicorn entry point."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from authz_service.api.agents import router as agents_router
from authz_service.api.applications import router as applications_router
from authz_service.api.authorize import router as authorize_router
from authz_service.api.context import router as context_router
from authz_service.api.permissions import router as permissions_router
from authz_service.api.policies import router as memberships_router
from authz_service.api.roles import router as roles_router
from authz_service.api.tenants import router as tenants_router
from authz_service.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)
    log = logging.getLogger("authz")

    app = FastAPI(
        title="AuthZ Service",
        description=(
            "Multi-tenant authorization decision service for apps, agents, and MCP tools."
        ),
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if not settings.api_keys:
        log.warning(
            "AUTHZ_API_KEYS is empty; service is running in development mode "
            "and will accept any caller. Configure API keys in production."
        )

    app.include_router(authorize_router)
    app.include_router(context_router)
    app.include_router(tenants_router)
    app.include_router(applications_router)
    app.include_router(memberships_router)
    app.include_router(roles_router)
    app.include_router(permissions_router)
    app.include_router(agents_router)

    @app.get("/healthz", tags=["meta"])
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/", tags=["meta"])
    def root() -> dict:
        return {
            "service": "authz",
            "version": "0.1.0",
            "endpoints": [
                "/v1/resolve-context",
                "/v1/authorize",
                "/v1/bulk-authorize",
                "/v1/effective-permissions",
            ],
        }

    return app


app = create_app()


def run() -> None:
    """Console-script entry point used by ``authz-service``."""
    import uvicorn

    uvicorn.run("authz_service.main:app", host="0.0.0.0", port=8080, reload=False)


if __name__ == "__main__":
    run()
