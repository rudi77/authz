"""Tenant + tenant-mapping management endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from authzkit.storage.sqlalchemy import SqlAlchemyStore
from authz_service.dependencies import get_store, require_admin_scope


router = APIRouter(prefix="/v1/tenants", tags=["tenants"])


class TenantIn(BaseModel):
    slug: str
    name: str
    status: str = "active"


class TenantOut(BaseModel):
    id: str
    slug: str
    name: str
    status: str


class TenantPatch(BaseModel):
    name: str | None = None
    status: str | None = None


class TenantMappingIn(BaseModel):
    provider: str
    issuer: str
    external_tenant_id: str


class FeatureFlagIn(BaseModel):
    application_id: str | None = None
    key: str
    value: object


@router.post(
    "",
    response_model=TenantOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin_scope)],
)
def create_tenant(
    body: TenantIn, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> TenantOut:
    tenant = store.create_tenant(slug=body.slug, name=body.name, status=body.status)
    return TenantOut(id=tenant.id, slug=tenant.slug, name=tenant.name, status=tenant.status)


@router.get(
    "/{tenant_id}", response_model=TenantOut, dependencies=[Depends(require_admin_scope)]
)
def get_tenant(
    tenant_id: str, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> TenantOut:
    tenant = store.get_tenant(tenant_id) or store.get_tenant_by_slug(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail={"reason": "tenant_not_found"})
    return TenantOut(id=tenant.id, slug=tenant.slug, name=tenant.name, status=tenant.status)


@router.post(
    "/{tenant_id}/mappings",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin_scope)],
)
def create_tenant_mapping(
    tenant_id: str,
    body: TenantMappingIn,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> dict:
    tenant = store.get_tenant(tenant_id) or store.get_tenant_by_slug(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail={"reason": "tenant_not_found"})
    mapping = store.create_tenant_identity_mapping(
        tenant_id=tenant.id,
        provider=body.provider,
        issuer=body.issuer,
        external_tenant_id=body.external_tenant_id,
    )
    return {
        "id": mapping.id,
        "tenant_id": mapping.tenant_id,
        "provider": mapping.provider,
        "issuer": mapping.issuer,
        "external_tenant_id": mapping.external_tenant_id,
    }


@router.put(
    "/{tenant_id}/feature-flags",
    dependencies=[Depends(require_admin_scope)],
)
def set_feature_flag(
    tenant_id: str,
    body: FeatureFlagIn,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> dict:
    tenant = store.get_tenant(tenant_id) or store.get_tenant_by_slug(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail={"reason": "tenant_not_found"})
    application_id = None
    if body.application_id:
        app = store.get_application(body.application_id) or store.get_application_by_slug(
            body.application_id
        )
        if app is None:
            raise HTTPException(status_code=404, detail={"reason": "application_not_found"})
        application_id = app.id
    store.set_tenant_feature_flag(tenant.id, application_id, body.key, body.value)
    return {"ok": True}
