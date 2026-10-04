"""Role management endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from authz_service.config import Settings, get_settings
from authz_service.dependencies import get_store, require_admin
from authz_service.management import enforce_managed_by
from authzkit.rbac.models import RoleScope
from authzkit.security.principal import Principal
from authzkit.storage.sqlalchemy import SqlAlchemyStore

router = APIRouter(prefix="/v1", tags=["roles"])


class RoleIn(BaseModel):
    name: str
    scope: str = "application"
    description: str | None = None
    tenant_id: str | None = None


class RoleOut(BaseModel):
    id: str
    name: str
    scope: str
    application_id: str | None
    tenant_id: str | None
    description: str | None
    is_system: bool


class RolePermissionsIn(BaseModel):
    permissions: list[str]


def _resolve_application(application_id: str, store: SqlAlchemyStore):
    app = store.get_application(application_id) or store.get_application_by_slug(application_id)
    if app is None:
        raise HTTPException(status_code=404, detail={"reason": "application_not_found"})
    return app


@router.post(
    "/applications/{application_id}/roles",
    response_model=RoleOut,
    status_code=status.HTTP_201_CREATED,
)
def create_role(
    application_id: str,
    body: RoleIn,
    principal: Annotated[Principal, Depends(require_admin)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> RoleOut:
    app = _resolve_application(application_id, store)
    enforce_managed_by(app, principal, settings)
    try:
        scope = RoleScope(body.scope)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "invalid_scope"}
        ) from exc
    role = store.create_role(
        name=body.name,
        scope=scope,
        application_id=app.id,
        tenant_id=body.tenant_id,
        description=body.description,
    )
    return RoleOut(
        id=role.id,
        name=role.name,
        scope=role.scope.value,
        application_id=role.application_id,
        tenant_id=role.tenant_id,
        description=role.description,
        is_system=role.is_system,
    )


@router.get(
    "/applications/{application_id}/roles",
    response_model=list[RoleOut],
    dependencies=[Depends(require_admin)],
)
def list_roles(
    application_id: str, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> list[RoleOut]:
    app = _resolve_application(application_id, store)
    return [
        RoleOut(
            id=r.id,
            name=r.name,
            scope=r.scope.value,
            application_id=r.application_id,
            tenant_id=r.tenant_id,
            description=r.description,
            is_system=r.is_system,
        )
        for r in store.list_roles_for_application(app.id)
    ]


@router.put("/roles/{role_id}/permissions")
def set_role_permissions(
    role_id: str,
    body: RolePermissionsIn,
    principal: Annotated[Principal, Depends(require_admin)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    role = store.get_role(role_id)
    if role is None:
        raise HTTPException(status_code=404, detail={"reason": "role_not_found"})
    if role.application_id is not None:
        app = store.get_application(role.application_id)
        if app is not None:
            enforce_managed_by(app, principal, settings)
    known = {
        p.name
        for p in store.list_application_permissions(role.application_id)
        if not p.deprecated
    }
    unknown = sorted(set(body.permissions) - known)
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "unknown_permission", "permissions": unknown},
        )
    store.set_role_permissions(role_id, set(body.permissions))
    permissions = store.list_role_permissions(role_id)
    return {"role_id": role_id, "permissions": sorted(p.name for p in permissions)}


@router.get(
    "/roles/{role_id}/permissions",
    dependencies=[Depends(require_admin)],
)
def get_role_permissions(
    role_id: str, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> dict:
    role = store.get_role(role_id)
    if role is None:
        raise HTTPException(status_code=404, detail={"reason": "role_not_found"})
    permissions = store.list_role_permissions(role_id)
    return {"role_id": role_id, "permissions": sorted(p.name for p in permissions)}
