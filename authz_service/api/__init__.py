"""FastAPI routers for the Authorization Service."""

from authz_service.api import (
    agents as agents_router,
)
from authz_service.api import (
    applications as applications_router,
)
from authz_service.api import (
    authorize as authorize_router,
)
from authz_service.api import (
    context as context_router,
)
from authz_service.api import (
    permissions as permissions_router,
)
from authz_service.api import (
    policies as policies_router,
)
from authz_service.api import (
    roles as roles_router,
)
from authz_service.api import (
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
