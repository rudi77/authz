"""Agent management endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError

from authz_service.config import Settings, get_settings
from authz_service.dependencies import get_store, require_admin
from authz_service.management import enforce_managed_by
from authzkit.security.principal import Principal
from authzkit.storage.sqlalchemy import SqlAlchemyStore

router = APIRouter(prefix="/v1", tags=["agents"])


class AgentIn(BaseModel):
    name: str
    display_name: str | None = None
    role: str = ""
    status: str = "active"
    created_by_user_id: str | None = None


class AgentOut(BaseModel):
    """Served with ``response_model_exclude_defaults`` (see ``ApplicationOut``)."""

    id: str
    tenant_id: str
    application_id: str
    name: str
    role: str
    status: str
    display_name: str | None = None


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
    response_model_exclude_defaults=True,
    status_code=status.HTTP_201_CREATED,
)
def create_agent(
    tenant_id: str,
    application_id: str,
    body: AgentIn,
    principal: Annotated[Principal, Depends(require_admin)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AgentOut:
    tenant, app = _resolve_pair(tenant_id, application_id, store)
    enforce_managed_by(app, principal, settings)
    try:
        agent = store.create_agent(
            tenant_id=tenant.id,
            application_id=app.id,
            name=body.name,
            display_name=body.display_name,
            role=body.role,
            status=body.status,
            created_by_user_id=body.created_by_user_id,
        )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail={"error": "agent_name_taken"}
        ) from exc
    return AgentOut(
        id=agent.id,
        tenant_id=agent.tenant_id,
        application_id=agent.application_id,
        name=agent.name,
        role=agent.role,
        status=agent.status,
        display_name=agent.display_name,
    )


@router.get(
    "/tenants/{tenant_id}/applications/{application_id}/agents",
    response_model=list[AgentOut],
    response_model_exclude_defaults=True,
    dependencies=[Depends(require_admin)],
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
            display_name=a.display_name,
        )
        for a in store.list_agents(tenant_id=tenant.id, application_id=app.id)
    ]


@router.put("/agents/{agent_id}/roles")
def set_agent_roles(
    agent_id: str,
    body: AgentRolesIn,
    principal: Annotated[Principal, Depends(require_admin)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    agent = store.get_agent_by_id(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail={"reason": "agent_not_found"})
    app = store.get_application(agent.application_id)
    if app is not None:
        enforce_managed_by(app, principal, settings)
    found = store.find_assignable_roles(
        tenant_id=agent.tenant_id, application_id=agent.application_id, names=body.roles
    )
    unknown = sorted(set(body.roles) - set(found))
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "unknown_role", "roles": unknown},
        )
    store.set_agent_roles(agent_id, set(body.roles))
    return {"agent_id": agent_id, "roles": sorted(body.roles)}
