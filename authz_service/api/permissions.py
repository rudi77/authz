"""Permission catalog endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from authzkit.storage.sqlalchemy import SqlAlchemyStore
from authz_service.dependencies import get_store, require_api_key
from authz_service.api.roles import _resolve_application


router = APIRouter(prefix="/v1/applications", tags=["permissions"])


class PermissionIn(BaseModel):
    name: str
    description: str | None = None


class PermissionOut(BaseModel):
    id: str
    name: str
    resource: str
    action: str
    application_id: str | None
    description: str | None


@router.post(
    "/{application_id}/permissions",
    response_model=PermissionOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
def create_permission(
    application_id: str,
    body: PermissionIn,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> PermissionOut:
    app = _resolve_application(application_id, store)
    permission = store.create_permission(
        name=body.name, application_id=app.id, description=body.description
    )
    return PermissionOut(
        id=permission.id,
        name=permission.name,
        resource=permission.resource,
        action=permission.action,
        application_id=permission.application_id,
        description=permission.description,
    )


@router.get(
    "/{application_id}/permissions",
    response_model=list[PermissionOut],
    dependencies=[Depends(require_api_key)],
)
def list_permissions(
    application_id: str, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> list[PermissionOut]:
    app = _resolve_application(application_id, store)
    return [
        PermissionOut(
            id=p.id,
            name=p.name,
            resource=p.resource,
            action=p.action,
            application_id=p.application_id,
            description=p.description,
        )
        for p in store.list_application_permissions(app.id)
    ]
