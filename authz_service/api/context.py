"""POST /v1/resolve-context — IdentityPrincipal -> UserContext."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from authz_service.config import Settings, get_settings
from authz_service.dependencies import get_store, require_api_key
from authzkit.exceptions import (
    InvalidRequestError,
    NoActiveMembershipError,
    TenantNotActiveError,
)
from authzkit.identity.base import IdentityPrincipal
from authzkit.rbac.resolver import PermissionResolver
from authzkit.service.schemas import ResolveContextRequestSchema, ResolveContextResponseSchema
from authzkit.storage.sqlalchemy import SqlAlchemyStore
from authzkit.tenancy.resolver import TenantContextResolver

router = APIRouter(prefix="/v1", tags=["context"])


@router.post(
    "/resolve-context",
    response_model=ResolveContextResponseSchema,
    dependencies=[Depends(require_api_key)],
)
def resolve_context(
    request: ResolveContextRequestSchema,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ResolveContextResponseSchema:
    principal = IdentityPrincipal(
        provider=request.provider,
        issuer=request.issuer,
        subject=request.subject,
        email=request.email,
        external_tenant_id=request.external_tenant_id,
        claims=request.claims,
    )
    resolver = TenantContextResolver(
        repository=store,
        permission_resolver=PermissionResolver(store),
        allow_auto_provision_user=settings.auto_provision_user,
        allow_auto_provision_tenant=settings.auto_provision_tenant,
    )
    try:
        ctx = resolver.resolve(
            principal,
            application_slug=request.application_id,
            explicit_tenant_id=request.explicit_tenant_id,
        )
    except (TenantNotActiveError, NoActiveMembershipError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail={"reason": exc.reason}
        ) from exc
    except InvalidRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"reason": exc.reason, "message": str(exc)},
        ) from exc
    return ResolveContextResponseSchema(
        tenant_id=ctx.tenant_id,
        application_id=ctx.application_id,
        user_id=ctx.user_id,
        roles=sorted(ctx.roles),
        permissions=sorted(ctx.permissions),
    )
