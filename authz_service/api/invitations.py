"""Invitation endpoints.

POST /v1/tenants/{tenant_id}/invitations  — admin creates an invite
GET  /v1/tenants/{tenant_id}/invitations  — list pending
POST /v1/invitations/{token}/accept       — user redeems token (auth via principal)
DELETE /v1/invitations/{invitation_id}    — admin revokes
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from authz_service.config import Settings, get_settings
from authz_service.dependencies import (
    get_invitation_service,
    get_store,
    require_admin,
    require_caller,
)
from authz_service.management import Guard
from authz_service.references import require_tenant
from authzkit.security.invitations import InvitationError, InvitationService
from authzkit.storage.sqlalchemy import SqlAlchemyStore
from authzkit.tenancy.models import Application

router = APIRouter(prefix="/v1", tags=["invitations"])


class InvitationIn(BaseModel):
    email: str
    application_id: str | None = None
    roles: list[str] = []
    ttl_days: int = Field(7, ge=1, le=90)


class InvitationOut(BaseModel):
    id: str
    tenant_id: str
    application_id: str | None
    email: str
    roles: list[str]
    status: str
    expires_at: datetime
    accepted_at: datetime | None


class InvitationCreated(InvitationOut):
    """Returned exactly once at creation; ``token`` is the plaintext."""

    token: str


class InvitationAccept(BaseModel):
    """Identity payload mirroring resolve-context.

    The accepting user must authenticate exactly the same way they would
    for any other request — we use that principal to resolve the internal
    user_id which becomes the new membership's owner.
    """

    provider: str
    issuer: str
    subject: str
    email: str | None = None
    external_tenant_id: str | None = None
    claims: dict[str, Any] = Field(default_factory=dict)


def _invitation_application(body: InvitationIn, guard: Guard) -> Application | None:
    return guard.application(body.application_id) if body.application_id else None


@router.post(
    "/tenants/{tenant_id}/invitations",
    response_model=InvitationCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_invitation(
    tenant_id: str,
    body: InvitationIn,
    app: Annotated[Application | None, Depends(_invitation_application)],
    invitations: Annotated[InvitationService, Depends(get_invitation_service)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> InvitationCreated:
    tenant = require_tenant(store, tenant_id)
    token = invitations.create(
        tenant_id=tenant.id,
        application_id=app.id if app else None,
        email=body.email,
        roles=body.roles,
        ttl=timedelta(days=body.ttl_days),
    )
    r = token.record
    return InvitationCreated(
        id=r.id,
        tenant_id=r.tenant_id,
        application_id=r.application_id,
        email=r.email,
        roles=list(r.roles),
        status=r.status,
        expires_at=r.expires_at,
        accepted_at=r.accepted_at,
        token=token.plaintext,
    )


@router.get(
    "/tenants/{tenant_id}/invitations",
    response_model=list[InvitationOut],
    dependencies=[Depends(require_admin)],
)
def list_invitations(
    tenant_id: str,
    invitations: Annotated[InvitationService, Depends(get_invitation_service)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> list[InvitationOut]:
    tenant = require_tenant(store, tenant_id)
    return [
        InvitationOut(
            id=r.id,
            tenant_id=r.tenant_id,
            application_id=r.application_id,
            email=r.email,
            roles=list(r.roles),
            status=r.status,
            expires_at=r.expires_at,
            accepted_at=r.accepted_at,
        )
        for r in invitations.list_for_tenant(tenant.id)
    ]


@router.post(
    "/invitations/{token}/accept",
    response_model=InvitationOut,
    dependencies=[Depends(require_caller)],
)
def accept_invitation(
    token: str,
    body: InvitationAccept,
    invitations: Annotated[InvitationService, Depends(get_invitation_service)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> InvitationOut:
    # Resolve / provision the accepting user from the principal claims.
    user, _ = store.upsert_user_from_identity(
        provider=body.provider,
        issuer=body.issuer,
        subject=body.subject,
        email=body.email,
        external_tenant_id=body.external_tenant_id,
    )
    try:
        record = invitations.accept(token, accepting_user_id=user.id)
    except InvitationError as e:
        raise HTTPException(status_code=400, detail={"reason": e.reason}) from e
    return InvitationOut(
        id=record.id,
        tenant_id=record.tenant_id,
        application_id=record.application_id,
        email=record.email,
        roles=list(record.roles),
        status=record.status,
        expires_at=record.expires_at,
        accepted_at=record.accepted_at,
    )


@router.delete(
    "/invitations/{invitation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_admin)],
)
def revoke_invitation(
    invitation_id: str,
    invitations: Annotated[InvitationService, Depends(get_invitation_service)],
) -> None:
    if not invitations.revoke(invitation_id):
        raise HTTPException(status_code=404, detail={"reason": "invitation_not_found"})
