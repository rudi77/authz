"""Resolution of caller references to authz ids.

Decision and delegation endpoints accept the tenant and application by id
or slug, the user by ``user_ref`` (provider, issuer, subject) and the agent
by ``agent_name``. Everything is resolved here, before the tenant scope
binding and the delegation match, so the rest of a request works on UUIDs
only.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException

from authzkit.rbac.checker import SUBJECT_USER
from authzkit.service.schemas import SubjectSchema, UserRefSchema
from authzkit.storage.sqlalchemy import SqlAlchemyStore
from authzkit.tenancy.models import Application, Tenant


def find_tenant(store: SqlAlchemyStore, ref: str) -> Tenant | None:
    return store.get_tenant(ref) or store.get_tenant_by_slug(ref)


def find_application(store: SqlAlchemyStore, ref: str) -> Application | None:
    return store.get_application(ref) or store.get_application_by_slug(ref)


def find_user_id(store: SqlAlchemyStore, ref: UserRefSchema) -> str | None:
    user = store.find_user_by_external_identity(ref.provider, ref.issuer, ref.subject)
    return user.id if user else None


def find_agent_id(
    store: SqlAlchemyStore, tenant_id: str, application_id: str, name: str
) -> str | None:
    agent = store.find_agent_by_name(
        tenant_id=tenant_id, application_id=application_id, name=name
    )
    return agent.id if agent else None


@dataclass(frozen=True)
class DecisionRefs:
    """References of a decision request, resolved.

    Unknown references keep their raw value and set ``deny_reason`` to the
    reason the engine gives for the same situation, so an unknown reference
    is indistinguishable from an inactive one.
    """

    tenant_id: str
    application_id: str
    subject: SubjectSchema
    deny_reason: str | None = None


def resolve_decision_refs(
    store: SqlAlchemyStore, tenant: str, application: str, subject: SubjectSchema
) -> DecisionRefs:
    t = find_tenant(store, tenant)
    a = find_application(store, application)
    deny: str | None = None
    if t is None:
        deny = "tenant_not_active"
    elif a is None:
        deny = "application_not_active"

    user_id = subject.user_id
    if subject.user_ref is not None:
        user_id = find_user_id(store, subject.user_ref)
        if user_id is None and deny is None:
            deny = (
                "no_active_membership"
                if subject.type == SUBJECT_USER
                else "no_active_user_membership"
            )
    agent_id = subject.agent_id
    if subject.agent_name is not None:
        agent_id = find_agent_id(store, t.id, a.id, subject.agent_name) if t and a else None
        if agent_id is None and deny is None:
            deny = "agent_not_active"

    return DecisionRefs(
        tenant_id=t.id if t else tenant,
        application_id=a.id if a else application,
        subject=subject.model_copy(
            update={"user_id": user_id, "user_ref": None, "agent_id": agent_id, "agent_name": None}
        ),
        deny_reason=deny,
    )


def require_tenant(store: SqlAlchemyStore, ref: str) -> Tenant:
    tenant = find_tenant(store, ref)
    if tenant is None:
        raise HTTPException(status_code=404, detail={"reason": "tenant_not_found"})
    return tenant


def require_application(store: SqlAlchemyStore, ref: str) -> Application:
    app = find_application(store, ref)
    if app is None:
        raise HTTPException(status_code=404, detail={"reason": "application_not_found"})
    return app


def require_user_id(store: SqlAlchemyStore, ref: UserRefSchema) -> str:
    user_id = find_user_id(store, ref)
    if user_id is None:
        raise HTTPException(status_code=404, detail={"reason": "user_not_found"})
    return user_id


def require_agent_id(
    store: SqlAlchemyStore, tenant_id: str, application_id: str, name: str
) -> str:
    agent_id = find_agent_id(store, tenant_id, application_id, name)
    if agent_id is None:
        raise HTTPException(status_code=404, detail={"reason": "agent_not_found"})
    return agent_id
