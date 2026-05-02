"""Agent management endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from authzkit.storage.sqlalchemy import SqlAlchemyStore
from authz_service.dependencies import get_store, require_admin_scope


router = APIRouter(prefix="/v1", tags=["agents"])


class AgentIn(BaseModel):
    name: str
    role: str = ""
    status: str = "active"
    created_by_user_id: str | None = None


class AgentOut(BaseModel):
    id: str
    tenant_id: str
    application_id: str
    name: str
    role: str
    status: str


class AgentRolesIn(BaseModel):
    roles: list[str]


def _resolve_pair(tenant_id: str, application_id: str, store: SqlAlchemyStore):
    tenant = store.get_tenant(tenant_id) or store.get_tenant_by_slug(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail={"reason": "tenant_not_found"})
    app = store.get_application(application_id) or store.get_application_by_slug(application_id)
    if app is None:
        raise HTTPException(status_code=404, detail={"reason": "application_not_found"})
    return tenant, app


@router.post(
    "/tenants/{tenant_id}/applications/{application_id}/agents",
    response_model=AgentOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin_scope)],
)
def create_agent(
    tenant_id: str,
    application_id: str,
    body: AgentIn,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> AgentOut:
    tenant, app = _resolve_pair(tenant_id, application_id, store)
    agent = store.create_agent(
        tenant_id=tenant.id,
        application_id=app.id,
        name=body.name,
        role=body.role,
        status=body.status,
        created_by_user_id=body.created_by_user_id,
    )
    return AgentOut(
        id=agent.id,
        tenant_id=agent.tenant_id,
        application_id=agent.application_id,
        name=agent.name,
        role=agent.role,
        status=agent.status,
    )


@router.get(
    "/tenants/{tenant_id}/applications/{application_id}/agents",
    response_model=list[AgentOut],
    dependencies=[Depends(require_admin_scope)],
)
def list_agents(
    tenant_id: str,
    application_id: str,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> list[AgentOut]:
    tenant, app = _resolve_pair(tenant_id, application_id, store)
    return [
        AgentOut(
            id=a.id,
            tenant_id=a.tenant_id,
            application_id=a.application_id,
            name=a.name,
            role=a.role,
            status=a.status,
        )
        for a in store.list_agents(tenant_id=tenant.id, application_id=app.id)
    ]


@router.put(
    "/agents/{agent_id}/roles",
    dependencies=[Depends(require_admin_scope)],
)
def set_agent_roles(
    agent_id: str,
    body: AgentRolesIn,
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> dict:
    store.set_agent_roles(agent_id, set(body.roles))
    return {"agent_id": agent_id, "roles": sorted(body.roles)}
