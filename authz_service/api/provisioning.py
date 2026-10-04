"""Declarative provisioning for a managed application.

PUT    /v1/applications/{app_slug}/catalog                              — permissions + default roles (admin)
PUT    /v1/applications/{app_slug}/tenants/{tenant_slug}/state          — members + agents of one tenant (manager)
GET    /v1/applications/{app_slug}/tenants/{tenant_slug}/roles          — default roles with tenant overrides (runtime)
PUT    /v1/applications/{app_slug}/tenants/{tenant_slug}/roles/{name}   — override a default role (manager)
DELETE /v1/applications/{app_slug}/tenants/{tenant_slug}/roles/{name}   — back to the default (manager)

The catalog call creates the application on first use and makes the caller
its manager (``managed_by``); see :mod:`authz_service.management`.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from authz_service.dependencies import (
    enforce_tenant_scope_binding,
    get_store,
    require_runtime,
)
from authz_service.management import Guard, catalog_application, manager_application
from authz_service.references import require_application, require_tenant
from authzkit.provisioning import (
    CatalogPermission,
    CatalogRole,
    DesiredAgent,
    DesiredMember,
    ProvisioningError,
    TenantState,
    UserRef,
)
from authzkit.security.principal import Principal
from authzkit.storage.sqlalchemy import SqlAlchemyStore
from authzkit.tenancy.models import Application

router = APIRouter(prefix="/v1/applications", tags=["provisioning"])


class CatalogPermissionIn(BaseModel):
    name: str
    description: str | None = None
    critical: bool = False


class CatalogRoleIn(BaseModel):
    name: str = Field(min_length=1)
    description: str | None = None
    permissions: list[str] = []


class CatalogIn(BaseModel):
    name: str = Field(min_length=1)
    permissions: list[CatalogPermissionIn]
    default_roles: list[CatalogRoleIn] = []


class UserRefIn(BaseModel):
    provider: str = Field(min_length=1)
    issuer: str = Field(min_length=1)
    subject: str = Field(min_length=1)


class MemberIn(BaseModel):
    user_ref: UserRefIn
    display_name: str | None = None
    email: str | None = None
    roles: list[str] = []
    status: str = "active"


class AgentStateIn(BaseModel):
    name: str = Field(min_length=1)
    display_name: str | None = None
    permissions: list[str] = []
    status: str = "active"


class TenantStateIn(BaseModel):
    name: str = Field(min_length=1)
    status: str = "active"
    members: list[MemberIn] = []
    agents: list[AgentStateIn] = []


class TenantRoleOut(BaseModel):
    name: str
    source: str
    permissions: list[str]
    default_permissions: list[str]


class TenantRolePermissionsIn(BaseModel):
    permissions: list[str]


def _invalid(error: str, exc: ProvisioningError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={"error": error, "errors": [asdict(e) for e in exc.errors]},
    )


@router.put("/{app_slug}/catalog")
def put_catalog(
    app_slug: str,
    body: CatalogIn,
    app: Annotated[Application | None, Depends(catalog_application)],
    guard: Guard,
) -> dict:
    try:
        result = guard.store.apply_application_catalog(
            slug=app.slug if app else app_slug,
            name=body.name,
            permissions=[
                CatalogPermission(name=p.name, description=p.description, critical=p.critical)
                for p in body.permissions
            ],
            default_roles=[
                CatalogRole(name=r.name, description=r.description, permissions=tuple(r.permissions))
                for r in body.default_roles
            ],
            managed_by=guard.caller,
        )
    except ProvisioningError as exc:
        raise _invalid("invalid_catalog", exc) from exc
    return {
        "application_id": result.application_id,
        "permissions": {
            "created": result.permissions_created,
            "deprecated": result.permissions_deprecated,
        },
        "roles": {"created": result.roles_created, "updated": result.roles_updated},
    }


@router.put("/{app_slug}/tenants/{tenant_slug}/state")
def put_tenant_state(
    tenant_slug: str,
    body: TenantStateIn,
    app: Annotated[Application, Depends(manager_application)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> dict:
    state = TenantState(
        name=body.name,
        status=body.status,
        members=tuple(
            DesiredMember(
                user_ref=UserRef(m.user_ref.provider, m.user_ref.issuer, m.user_ref.subject),
                roles=tuple(m.roles),
                display_name=m.display_name,
                email=m.email,
                status=m.status,
            )
            for m in body.members
        ),
        agents=tuple(
            DesiredAgent(
                name=a.name,
                permissions=tuple(a.permissions),
                display_name=a.display_name,
                status=a.status,
            )
            for a in body.agents
        ),
    )
    try:
        result = store.apply_tenant_state(
            application_id=app.id, tenant_slug=tenant_slug, state=state
        )
    except ProvisioningError as exc:
        raise _invalid("invalid_state", exc) from exc
    return {
        "tenant_id": result.tenant_id,
        "members": asdict(result.members),
        "agents": asdict(result.agents),
    }


@router.get("/{app_slug}/tenants/{tenant_slug}/roles", response_model=list[TenantRoleOut])
def list_tenant_roles(
    app_slug: str,
    tenant_slug: str,
    principal: Annotated[Principal, Depends(require_runtime)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> list[TenantRoleOut]:
    app = require_application(store, app_slug)
    tenant = require_tenant(store, tenant_slug)
    enforce_tenant_scope_binding(principal, tenant.id)
    return [
        TenantRoleOut(**asdict(v))
        for v in store.list_tenant_roles(tenant_id=tenant.id, application_id=app.id)
    ]


def _default_role_or_404(store: SqlAlchemyStore, app: Application, name: str) -> None:
    role = store.get_role_by_name(application_id=app.id, tenant_id=None, name=name)
    if role is None or role.agent_id is not None:
        raise HTTPException(status_code=404, detail={"reason": "role_not_found"})


@router.put(
    "/{app_slug}/tenants/{tenant_slug}/roles/{name}", response_model=TenantRoleOut
)
def put_tenant_role(
    tenant_slug: str,
    name: str,
    body: TenantRolePermissionsIn,
    app: Annotated[Application, Depends(manager_application)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> TenantRoleOut:
    tenant = require_tenant(store, tenant_slug)
    _default_role_or_404(store, app, name)
    known = {p.name for p in store.list_application_permissions(app.id) if not p.deprecated}
    unknown = sorted(set(body.permissions) - known)
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "unknown_permission", "permissions": unknown},
        )
    store.set_tenant_role_override(
        tenant_id=tenant.id, application_id=app.id, name=name, permissions=set(body.permissions)
    )
    view = next(
        v
        for v in store.list_tenant_roles(tenant_id=tenant.id, application_id=app.id)
        if v.name == name
    )
    return TenantRoleOut(**asdict(view))


@router.delete(
    "/{app_slug}/tenants/{tenant_slug}/roles/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def delete_tenant_role(
    tenant_slug: str,
    name: str,
    app: Annotated[Application, Depends(manager_application)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> Response:
    tenant = require_tenant(store, tenant_slug)
    _default_role_or_404(store, app, name)
    store.delete_tenant_role_override(tenant_id=tenant.id, application_id=app.id, name=name)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
