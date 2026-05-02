"""API key management endpoints. Admin-scoped only."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from authzkit.security.api_keys import ApiKeyMaterial, ApiKeyService
from authz_service.dependencies import (
    get_api_key_service,
    require_admin_scope,
)


router = APIRouter(prefix="/v1/api-keys", tags=["api-keys"])


class ApiKeyIn(BaseModel):
    name: str
    scopes: list[str] = ["admin"]
    tenant_id: str | None = None
    expires_at: datetime | None = None


class ApiKeyOut(BaseModel):
    id: str
    name: str
    key_prefix: str
    scopes: list[str]
    tenant_id: str | None
    status: str
    expires_at: datetime | None
    last_used_at: datetime | None
    rotates: str | None


class ApiKeyCreated(ApiKeyOut):
    """Response shown exactly once; ``key`` is the plaintext."""

    key: str


def _to_out(material: ApiKeyMaterial) -> ApiKeyCreated:
    r = material.record
    return ApiKeyCreated(
        id=r.id,
        name=r.name,
        key_prefix=r.key_prefix,
        scopes=list(r.scopes),
        tenant_id=r.tenant_id,
        status=r.status,
        expires_at=r.expires_at,
        last_used_at=r.last_used_at,
        rotates=r.rotates,
        key=material.plaintext,
    )


@router.post(
    "",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin_scope)],
)
def create_api_key(
    body: ApiKeyIn,
    keys: Annotated[ApiKeyService, Depends(get_api_key_service)],
) -> ApiKeyCreated:
    material = keys.issue(
        name=body.name,
        scopes=body.scopes,
        tenant_id=body.tenant_id,
        expires_at=body.expires_at,
    )
    return _to_out(material)


@router.get(
    "",
    response_model=list[ApiKeyOut],
    dependencies=[Depends(require_admin_scope)],
)
def list_api_keys(
    keys: Annotated[ApiKeyService, Depends(get_api_key_service)],
) -> list[ApiKeyOut]:
    return [
        ApiKeyOut(
            id=r.id,
            name=r.name,
            key_prefix=r.key_prefix,
            scopes=list(r.scopes),
            tenant_id=r.tenant_id,
            status=r.status,
            expires_at=r.expires_at,
            last_used_at=r.last_used_at,
            rotates=r.rotates,
        )
        for r in keys.list_keys()
    ]


@router.post(
    "/{key_id}/rotate",
    response_model=ApiKeyCreated,
    dependencies=[Depends(require_admin_scope)],
)
def rotate_api_key(
    key_id: str,
    keys: Annotated[ApiKeyService, Depends(get_api_key_service)],
) -> ApiKeyCreated:
    try:
        material = keys.rotate(key_id)
    except ValueError:
        raise HTTPException(status_code=404, detail={"reason": "api_key_not_found"})
    return _to_out(material)


@router.delete(
    "/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_admin_scope)],
)
def revoke_api_key(
    key_id: str,
    keys: Annotated[ApiKeyService, Depends(get_api_key_service)],
) -> None:
    if not keys.revoke(key_id):
        raise HTTPException(status_code=404, detail={"reason": "api_key_not_found"})
