"""Read-mostly admin endpoints backing the admin UI.

Users (list + pre-provision), audit-log browsing and agent-role lookup. The
runtime surface never needs these; they exist so an operator can drive the
whole service from ``/admin`` without dropping to SQL.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import or_, select

from authz_service.dependencies import get_store, require_admin
from authz_service.middleware import paginate_params
from authzkit.storage import orm
from authzkit.storage.sqlalchemy import SqlAlchemyStore

router = APIRouter(prefix="/v1", tags=["admin"])


class ExternalIdentityOut(BaseModel):
    provider: str
    issuer: str
    subject: str
    external_tenant_id: str | None
    email: str | None


class UserOut(BaseModel):
    id: str
    display_name: str | None
    email: str | None
    status: str
    identities: list[ExternalIdentityOut]


class UserIn(BaseModel):
    """Pre-provision a user by external identity so memberships can be granted
    before their first login. Idempotent on ``(provider, issuer, subject)``."""

    provider: str
    issuer: str
    subject: str
    email: str | None = None
    display_name: str | None = None
    external_tenant_id: str | None = None


class AuditOut(BaseModel):
    id: str
    created_at: datetime | None
    tenant_id: str | None
    application_id: str | None
    user_id: str | None
    agent_id: str | None
    decision: str
    resource: str
    action: str
    reason: str | None
    request_id: str | None
    request: dict[str, Any]
    response: dict[str, Any]


def _user_out(s, row: orm.User) -> UserOut:
    idents = s.scalars(
        select(orm.ExternalIdentity).where(orm.ExternalIdentity.user_id == row.id)
    ).all()
    return UserOut(
        id=row.id,
        display_name=row.display_name,
        email=row.email,
        status=row.status,
        identities=[
            ExternalIdentityOut(
                provider=i.provider,
                issuer=i.issuer,
                subject=i.subject,
                external_tenant_id=i.external_tenant_id,
                email=i.email,
            )
            for i in idents
        ],
    )


@router.get("/users", response_model=list[UserOut], dependencies=[Depends(require_admin)])
def list_users(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    q: str | None = None,
    page: int = 1,
    page_size: int = 100,
) -> list[UserOut]:
    offset, limit = paginate_params(page, page_size)
    stmt = select(orm.User).order_by(orm.User.created_at)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                orm.User.email.ilike(like),
                orm.User.display_name.ilike(like),
                orm.User.id == q,
            )
        )
    with store.session() as s:
        rows = s.scalars(stmt.offset(offset).limit(limit)).all()
        return [_user_out(s, r) for r in rows]


@router.post(
    "/users",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def create_user(
    body: UserIn, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> UserOut:
    user, _ = store.upsert_user_from_identity(
        provider=body.provider,
        issuer=body.issuer,
        subject=body.subject,
        email=body.email,
        external_tenant_id=body.external_tenant_id,
        display_name=body.display_name,
    )
    with store.session() as s:
        return _user_out(s, s.get(orm.User, user.id))


@router.get("/agents/{agent_id}/roles", dependencies=[Depends(require_admin)])
def get_agent_roles(
    agent_id: str, store: Annotated[SqlAlchemyStore, Depends(get_store)]
) -> dict:
    with store.session() as s:
        if s.get(orm.Agent, agent_id) is None:
            raise HTTPException(status_code=404, detail={"reason": "agent_not_found"})
        names = s.scalars(
            select(orm.Role.name)
            .join(orm.agent_roles, orm.agent_roles.c.role_id == orm.Role.id)
            .where(orm.agent_roles.c.agent_id == agent_id)
        ).all()
    return {"agent_id": agent_id, "roles": sorted(names)}


@router.get("/audit", response_model=list[AuditOut], dependencies=[Depends(require_admin)])
def list_audit(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    tenant_id: str | None = None,
    decision: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> list[AuditOut]:
    """Newest-first audit entries. Denies are always recorded; allows only
    when ``AUTHZ_AUDIT_ALL=true``."""
    offset, limit = paginate_params(page, page_size)
    stmt = select(orm.AuditLog).order_by(orm.AuditLog.created_at.desc())
    if tenant_id:
        tenant = store.get_tenant(tenant_id) or store.get_tenant_by_slug(tenant_id)
        if tenant is None:
            raise HTTPException(status_code=404, detail={"reason": "tenant_not_found"})
        stmt = stmt.where(orm.AuditLog.tenant_id == tenant.id)
    if decision:
        stmt = stmt.where(orm.AuditLog.decision == decision)
    with store.session() as s:
        rows = s.scalars(stmt.offset(offset).limit(limit)).all()
        return [
            AuditOut(
                id=r.id,
                created_at=r.created_at,
                tenant_id=r.tenant_id,
                application_id=r.application_id,
                user_id=r.user_id,
                agent_id=r.agent_id,
                decision=r.decision,
                resource=r.resource,
                action=r.action,
                reason=r.reason,
                request_id=r.request_id,
                request=r.request or {},
                response=r.response or {},
            )
            for r in rows
        ]
