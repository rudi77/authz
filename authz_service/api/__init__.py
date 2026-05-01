"""FastAPI routers for the Authorization Service."""

from authz_service.api import (
    agents as agents_router,
    applications as applications_router,
    authorize as authorize_router,
    context as context_router,
    permissions as permissions_router,
    policies as policies_router,
    roles as roles_router,
    tenants as tenants_router,
)

__all__ = [
    "agents_router",
    "applications_router",
    "authorize_router",
    "context_router",
    "permissions_router",
    "policies_router",
    "roles_router",
    "tenants_router",
]
