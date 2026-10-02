"""Tenant + tenant-mapping management endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from authz_service.dependencies import get_store, require_admin
from authzkit.storage import orm
from authzkit.storage.sqlalchemy import SqlAlchemyStore

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


class PermissionMaskIn(BaseModel):
    permissions: list[str]


def _resolve_tenant(tenant_id: str, store: SqlAlchemyStore):
    tenant = store.get_tenant(tenant_id) or store.get_tenant_by_slug(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail={"reason": "tenant_not_found"})
    return tenant


def _resolve_application(application_id: str, store: SqlAlchemyStore):
    app = store.get_application(application_id) or store.get_application_by_slug(application_id)
    if app is None:
        raise HTTPException(status_code=404, detail={"reason": "application_not_found"})
    return app


class FeatureFlagIn(BaseModel):
    application_id: str | None = None
    key: str
    value: object


@router.post(
    "",
    response_model=TenantOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def create_tenant(
    body: TenantIn, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> TenantOut:
    tenant = store.create_tenant(slug=body.slug, name=body.name, status=body.status)
    return TenantOut(id=tenant.id, slug=tenant.slug, name=tenant.name, status=tenant.status)


@router.get("", response_model=list[TenantOut], dependencies=[Depends(require_admin)])
def list_tenants(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    page: int = 1,
    page_size: int = 100,
) -> list[TenantOut]:
    from authz_service.middleware import paginate_params

    offset, limit = paginate_params(page, page_size)
    with store.session() as s:
        rows = s.scalars(
            select(orm.Tenant).order_by(orm.Tenant.slug).offset(offset).limit(limit)
        ).all()
        return [TenantOut(id=r.id, slug=r.slug, name=r.name, status=r.status) for r in rows]


@router.get(
    "/{tenant_id}", response_model=TenantOut, dependencies=[Depends(require_admin)]
)
def get_tenant(
    tenant_id: str, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> TenantOut:
    tenant = store.get_tenant(tenant_id) or store.get_tenant_by_slug(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail={"reason": "tenant_not_found"})
    return TenantOut(id=tenant.id, slug=tenant.slug, name=tenant.name, status=tenant.status)


@router.patch(
    "/{tenant_id}", response_model=TenantOut, dependencies=[Depends(require_admin)]
)
def update_tenant(
    tenant_id: str,
    body: TenantPatch,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> TenantOut:
    tenant = _resolve_tenant(tenant_id, store)
    with store.session() as s:
        row = s.get(orm.Tenant, tenant.id)
        if body.name is not None:
            row.name = body.name
        if body.status is not None:
            row.status = body.status
        s.commit()
        return TenantOut(id=row.id, slug=row.slug, name=row.name, status=row.status)


@router.get("/{tenant_id}/mappings", dependencies=[Depends(require_admin)])
def list_tenant_mappings(
    tenant_id: str, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> list[dict]:
    tenant = _resolve_tenant(tenant_id, store)
    with store.session() as s:
        rows = s.scalars(
            select(orm.TenantIdentityMapping).where(
                orm.TenantIdentityMapping.tenant_id == tenant.id
            )
        ).all()
        return [
            {
                "id": m.id,
                "tenant_id": m.tenant_id,
                "provider": m.provider,
                "issuer": m.issuer,
                "external_tenant_id": m.external_tenant_id,
            }
            for m in rows
        ]


@router.post(
    "/{tenant_id}/mappings",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
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
    dependencies=[Depends(require_admin)],
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


@router.get("/{tenant_id}/feature-flags", dependencies=[Depends(require_admin)])
def list_feature_flags(
    tenant_id: str,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    application_id: str | None = None,
) -> dict:
    tenant = _resolve_tenant(tenant_id, store)
    app_id = _resolve_application(application_id, store).id if application_id else None
    return {
        "tenant_id": tenant.id,
        "application_id": app_id,
        "flags": store.get_tenant_feature_flags(tenant.id, app_id),
    }


@router.get(
    "/{tenant_id}/applications/{application_id}/permission-mask",
    dependencies=[Depends(require_admin)],
)
def get_permission_mask(
    tenant_id: str,
    application_id: str,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> dict:
    """Tenant feature mask. Empty means "no mask" — every permission is allowed."""
    tenant = _resolve_tenant(tenant_id, store)
    app = _resolve_application(application_id, store)
    perms = store.resolve_tenant_permissions(tenant_id=tenant.id, application_id=app.id)
    return {"tenant_id": tenant.id, "application_id": app.id, "permissions": sorted(perms)}


@router.put(
    "/{tenant_id}/applications/{application_id}/permission-mask",
    dependencies=[Depends(require_admin)],
)
def set_permission_mask(
    tenant_id: str,
    application_id: str,
    body: PermissionMaskIn,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> dict:
    tenant = _resolve_tenant(tenant_id, store)
    app = _resolve_application(application_id, store)
    store.set_tenant_permission_mask(
        tenant_id=tenant.id, application_id=app.id, permissions=set(body.permissions)
    )
    return {
        "tenant_id": tenant.id,
        "application_id": app.id,
        "permissions": sorted(set(body.permissions)),
    }
