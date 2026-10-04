"""Permission catalog endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from authz_service.dependencies import get_store, require_admin
from authz_service.management import managed_application
from authz_service.references import require_application
from authzkit.storage.sqlalchemy import SqlAlchemyStore
from authzkit.tenancy.models import Application

router = APIRouter(prefix="/v1/applications", tags=["permissions"])


class PermissionIn(BaseModel):
    name: str
    description: str | None = None


class PermissionOut(BaseModel):
    """Served with ``response_model_exclude_defaults`` so the new flags only
    appear when set and older SDKs (strict dataclasses) keep working."""

    id: str
    name: str
    resource: str
    action: str
    application_id: str | None
    description: str | None
    deprecated: bool = False
    critical: bool = False


@router.post(
    "/{application_id}/permissions",
    response_model=PermissionOut,
    response_model_exclude_defaults=True,
    status_code=status.HTTP_201_CREATED,
)
def create_permission(
    body: PermissionIn,
    app: Annotated[Application, Depends(managed_application)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> PermissionOut:
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
    response_model_exclude_defaults=True,
    dependencies=[Depends(require_admin)],
)
def list_permissions(
    application_id: str, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> list[PermissionOut]:
    app = require_application(store, application_id)
    return [
        PermissionOut(
            id=p.id,
            name=p.name,
            resource=p.resource,
            action=p.action,
            application_id=p.application_id,
            description=p.description,
            deprecated=p.deprecated,
            critical=p.critical,
        )
        for p in store.list_application_permissions(app.id)
    ]
