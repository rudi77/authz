"""Admin CRUD for OAuth ``client_credentials`` clients + signing-key rotation."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from authz_service.dependencies import (
    get_oauth_client_service,
    get_signing_key_service,
    require_admin,
)
from authzkit.security.oauth_clients import (
    OAuthClientCredentials,
    OAuthClientService,
)
from authzkit.security.signing_keys import SigningKeyError, SigningKeyService

router = APIRouter(prefix="/v1/oauth", tags=["oauth-admin"])


class OAuthClientIn(BaseModel):
    name: str
    scopes: list[str] = ["runtime"]
    tenant_id: str | None = None
    expires_at: datetime | None = None


class OAuthClientOut(BaseModel):
    id: str
    client_id: str
    name: str
    scopes: list[str]
    tenant_id: str | None
    status: str
    expires_at: datetime | None
    last_used_at: datetime | None


class OAuthClientCreated(OAuthClientOut):
    """Response shown exactly once at creation/rotation; ``client_secret`` is the plaintext."""

    client_secret: str


def _to_out(credentials: OAuthClientCredentials) -> OAuthClientCreated:
    r = credentials.record
    return OAuthClientCreated(
        id=r.id,
        client_id=r.client_id,
        name=r.name,
        scopes=list(r.scopes),
        tenant_id=r.tenant_id,
        status=r.status,
        expires_at=r.expires_at,
        last_used_at=r.last_used_at,
        client_secret=credentials.client_secret,
    )


@router.post(
    "/clients",
    response_model=OAuthClientCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def create_client(
    body: OAuthClientIn,
    clients: Annotated[OAuthClientService, Depends(get_oauth_client_service)],
) -> OAuthClientCreated:
    credentials = clients.issue(
        name=body.name,
        scopes=body.scopes,
        tenant_id=body.tenant_id,
        expires_at=body.expires_at,
    )
    return _to_out(credentials)


@router.get(
    "/clients",
    response_model=list[OAuthClientOut],
    dependencies=[Depends(require_admin)],
)
def list_clients(
    clients: Annotated[OAuthClientService, Depends(get_oauth_client_service)],
) -> list[OAuthClientOut]:
    return [
        OAuthClientOut(
            id=r.id,
            client_id=r.client_id,
            name=r.name,
            scopes=list(r.scopes),
            tenant_id=r.tenant_id,
            status=r.status,
            expires_at=r.expires_at,
            last_used_at=r.last_used_at,
        )
        for r in clients.list_clients()
    ]


@router.post(
    "/clients/{client_id}/rotate",
    response_model=OAuthClientCreated,
    dependencies=[Depends(require_admin)],
)
def rotate_client_secret(
    client_id: str,
    clients: Annotated[OAuthClientService, Depends(get_oauth_client_service)],
) -> OAuthClientCreated:
    credentials = clients.rotate_secret(client_id)
    if credentials is None:
        raise HTTPException(
            status_code=404, detail={"error": "oauth_client_not_found"}
        )
    return _to_out(credentials)


@router.delete(
    "/clients/{client_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_admin)],
)
def revoke_client(
    client_id: str,
    clients: Annotated[OAuthClientService, Depends(get_oauth_client_service)],
) -> None:
    if not clients.revoke(client_id):
        raise HTTPException(
            status_code=404, detail={"error": "oauth_client_not_found"}
        )


class SigningKeyOut(BaseModel):
    kid: str
    alg: str
    status: str
    created_at: datetime | None


@router.get(
    "/signing-keys",
    response_model=list[SigningKeyOut],
    dependencies=[Depends(require_admin)],
)
def list_signing_keys(
    signing_keys: Annotated[SigningKeyService, Depends(get_signing_key_service)],
) -> list[SigningKeyOut]:
    return [
        SigningKeyOut(
            kid=k.kid, alg=k.alg, status=k.status, created_at=k.created_at
        )
        for k in signing_keys.list_keys()
    ]


@router.post(
    "/signing-keys/rotate",
    response_model=SigningKeyOut,
    dependencies=[Depends(require_admin)],
)
def rotate_signing_key(
    signing_keys: Annotated[SigningKeyService, Depends(get_signing_key_service)],
) -> SigningKeyOut:
    try:
        new = signing_keys.rotate()
    except SigningKeyError as exc:
        raise HTTPException(
            status_code=409, detail={"error": "signing_key_rotation_failed", "reason": str(exc)}
        ) from exc
    return SigningKeyOut(
        kid=new.kid, alg=new.alg, status=new.status, created_at=new.created_at
    )
