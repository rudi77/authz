"""Membership management endpoints (and ABAC policies, scaffolded).

Memberships live here rather than in tenants.py because management of the
user/tenant/role triangle is its own conceptual surface.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from authz_service.dependencies import get_store, require_admin
from authz_service.management import Guard, managed_membership
from authz_service.references import require_tenant
from authzkit.storage.sqlalchemy import SqlAlchemyStore
from authzkit.tenancy.models import Application, Membership

router = APIRouter(prefix="/v1", tags=["memberships"])


class MembershipIn(BaseModel):
    user_id: str
    application_id: str | None = None
    roles: list[str] = []
    status: str = "active"


class MembershipOut(BaseModel):
    id: str
    tenant_id: str
    application_id: str | None
    user_id: str
    roles: list[str]
    status: str


class MembershipPatch(BaseModel):
    roles: list[str] | None = None
    status: str | None = None


def _membership_application(body: MembershipIn, guard: Guard) -> Application | None:
    return guard.application(body.application_id) if body.application_id else None


@router.post(
    "/tenants/{tenant_id}/memberships",
    response_model=MembershipOut,
    status_code=status.HTTP_201_CREATED,
)
def create_membership(
    tenant_id: str,
    body: MembershipIn,
    app: Annotated[Application | None, Depends(_membership_application)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> MembershipOut:
    tenant = require_tenant(store, tenant_id)
    membership = store.create_membership(
        tenant_id=tenant.id,
        application_id=app.id if app else None,
        user_id=body.user_id,
        roles=set(body.roles) or None,
        status=body.status,
    )
    return MembershipOut(
        id=membership.id,
        tenant_id=membership.tenant_id,
        application_id=membership.application_id,
        user_id=membership.user_id,
        roles=sorted(membership.roles),
        status=membership.status,
    )


@router.get(
    "/tenants/{tenant_id}/memberships",
    response_model=list[MembershipOut],
    dependencies=[Depends(require_admin)],
)
def list_memberships(
    tenant_id: str,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    page: int = 1,
    page_size: int = 50,
) -> list[MembershipOut]:
    from sqlalchemy import select

    from authz_service.middleware import paginate_params
    from authzkit.storage import orm

    tenant = require_tenant(store, tenant_id)
    offset, limit = paginate_params(page, page_size)

    with store.session() as s:
        rows = s.scalars(
            select(orm.Membership)
            .where(orm.Membership.tenant_id == tenant.id)
            .order_by(orm.Membership.created_at)
            .offset(offset)
            .limit(limit)
        ).all()
        out: list[MembershipOut] = []
        for r in rows:
            names = store.membership_role_names(s, r.id)
            out.append(
                MembershipOut(
                    id=r.id,
                    tenant_id=r.tenant_id,
                    application_id=r.application_id,
                    user_id=r.user_id,
                    roles=sorted(names),
                    status=r.status,
                )
            )
        return out


@router.patch(
    "/memberships/{membership_id}",
    response_model=MembershipOut,
)
def update_membership(
    membership_id: str,
    body: MembershipPatch,
    _: Annotated[Membership, Depends(managed_membership)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> MembershipOut:

    from authzkit.storage import orm

    with store.session() as s:
        row = s.get_one(orm.Membership, membership_id)
        if body.status is not None:
            row.status = body.status
        s.commit()
    if body.roles is not None:
        store.set_membership_roles(membership_id, set(body.roles))
    with store.session() as s:
        row = s.get_one(orm.Membership, membership_id)
        names = store.membership_role_names(s, row.id)
    return MembershipOut(
        id=row.id,
        tenant_id=row.tenant_id,
        application_id=row.application_id,
        user_id=row.user_id,
        roles=sorted(names),
        status=row.status,
    )
