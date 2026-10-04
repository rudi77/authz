"""Resolution of caller references to authz ids.

Decision and delegation endpoints accept the tenant and application by id
or slug, the user by ``user_ref`` (provider, issuer, subject) and the agent
by ``agent_name``. Decision references resolve in authzkit
(``SqlAlchemyStore.resolve_references``, one session) before the tenant
scope binding and the delegation match; the engine takes the result, so
unknown references end in its usual deny reasons.
"""

from __future__ import annotations

from fastapi import HTTPException

from authzkit.provisioning import UserRef
from authzkit.rbac.checker import ResolvedReferences
from authzkit.service.schemas import SubjectSchema, UserRefSchema
from authzkit.storage.sqlalchemy import SqlAlchemyStore
from authzkit.tenancy.models import Application, Tenant


def find_tenant(store: SqlAlchemyStore, ref: str) -> Tenant | None:
    return store.find_tenant(ref)


def find_application(store: SqlAlchemyStore, ref: str) -> Application | None:
    return store.find_application(ref)


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


def resolve_decision_refs(
    store: SqlAlchemyStore, tenant: str, application: str, subject: SubjectSchema
) -> tuple[ResolvedReferences, SubjectSchema]:
    """The resolved references and the subject in id form."""
    refs = store.resolve_references(
        tenant=tenant,
        application=application,
        user_id=subject.user_id,
        user_ref=UserRef(**subject.user_ref.model_dump()) if subject.user_ref else None,
        agent_id=subject.agent_id,
        agent_name=subject.agent_name,
    )
    ids = {"user_id": refs.user_id, "agent_id": refs.agent_id}
    return refs, subject.model_copy(update={**ids, "user_ref": None, "agent_name": None})


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
