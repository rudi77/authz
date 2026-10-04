"""POST /v1/authorize, /v1/bulk-authorize, /v1/effective-permissions."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException

from authz_service.api.delegations import apply_delegation
from authz_service.config import Settings, get_settings
from authz_service.dependencies import (
    AuditSink,
    enforce_tenant_scope_binding,
    get_audit_sink,
    get_authorization_engine,
    get_delegation_service,
    get_store,
    require_runtime,
)
from authz_service.observability import DECISION_LATENCY, record_decision
from authz_service.references import resolve_decision_refs
from authzkit.audit.logger import AuditEntry
from authzkit.rbac.checker import (
    AuthorizationEngine,
    AuthorizeDecision,
    AuthorizeRequest,
    BulkAuthorizeRequest,
    Subject,
)
from authzkit.security.delegations import DelegationService
from authzkit.security.principal import Principal
from authzkit.service.schemas import (
    AuthorizeRequestSchema,
    AuthorizeResponseSchema,
    BulkAuthorizeRequestSchema,
    BulkAuthorizeResponseSchema,
    BulkCheckResultSchema,
    EffectivePermissionsRequestSchema,
    EffectivePermissionsResponseSchema,
    SubjectSchema,
)
from authzkit.storage.sqlalchemy import SqlAlchemyStore

router = APIRouter(prefix="/v1", tags=["authorize"])

# Optional delegation grant (see api/delegations.py). Absent → unchanged behaviour.
DelegationHeader = Annotated[
    str | None,
    Header(
        alias="X-Delegation-Token",
        description="Optional delegation grant JWT; narrows an agent's permissions.",
    ),
]


def _audit_payload(request, grant_id: str | None) -> dict:
    payload = request.model_dump()
    if grant_id is not None:
        payload["delegation_id"] = grant_id
    return payload


def _to_subject(s: SubjectSchema) -> Subject:
    return Subject(
        type=s.type,
        user_id=s.user_id,
        agent_id=s.agent_id,
        service_account_id=s.service_account_id,
    )


@router.post(
    "/authorize",
    response_model=AuthorizeResponseSchema,
)
def authorize(
    request: AuthorizeRequestSchema,
    engine: Annotated[AuthorizationEngine, Depends(get_authorization_engine)],
    audit: Annotated[AuditSink, Depends(get_audit_sink)],
    principal: Annotated[Principal, Depends(require_runtime)],
    delegations: Annotated[DelegationService, Depends(get_delegation_service)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    request_id: Annotated[str | None, Header(alias="X-Request-Id")] = None,
    x_delegation_token: DelegationHeader = None,
) -> AuthorizeResponseSchema:
    refs = resolve_decision_refs(
        store, request.tenant_id, request.application_id, request.subject
    )
    enforce_tenant_scope_binding(principal, refs.tenant_id)
    delegation = apply_delegation(
        token=x_delegation_token,
        tenant_id=refs.tenant_id,
        application_id=refs.application_id,
        subject=refs.subject,
        delegations=delegations,
        settings=settings,
    )
    deny_reason = refs.deny_reason or delegation.deny_reason
    with DECISION_LATENCY.labels("authorize").time():
        if deny_reason is not None:
            decision = AuthorizeDecision.deny(deny_reason, f"{request.resource}.{request.action}")
        else:
            decision = engine.authorize(
                AuthorizeRequest(
                    tenant_id=refs.tenant_id,
                    application_id=refs.application_id,
                    subject=_to_subject(delegation.subject),
                    resource=request.resource,
                    action=request.action,
                    context=request.context,
                    delegated_permissions=delegation.permissions,
                )
            )
    response = AuthorizeResponseSchema(
        allowed=decision.allowed,
        decision=decision.decision,
        reason=decision.reason,
        required_permission=decision.required_permission,
        matched_permissions=sorted(decision.matched_permissions),
    )
    record_decision(
        application_id=refs.application_id,
        subject_type=request.subject.type,
        decision=decision.decision,
        reason=decision.reason,
    )
    audit.write(
        AuditEntry(
            decision=decision.decision,
            reason=decision.reason,
            resource=request.resource,
            action=request.action,
            tenant_id=refs.tenant_id,
            application_id=refs.application_id,
            user_id=delegation.subject.user_id,
            agent_id=delegation.subject.agent_id,
            request=_audit_payload(request, delegation.grant_id),
            response=response.model_dump(),
            request_id=request_id or str(uuid.uuid4()),
        ),
        request_id=request_id,
    )
    return response


@router.post(
    "/bulk-authorize",
    response_model=BulkAuthorizeResponseSchema,
)
def bulk_authorize(
    request: BulkAuthorizeRequestSchema,
    engine: Annotated[AuthorizationEngine, Depends(get_authorization_engine)],
    audit: Annotated[AuditSink, Depends(get_audit_sink)],
    principal: Annotated[Principal, Depends(require_runtime)],
    delegations: Annotated[DelegationService, Depends(get_delegation_service)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    request_id: Annotated[str | None, Header(alias="X-Request-Id")] = None,
    x_delegation_token: DelegationHeader = None,
) -> BulkAuthorizeResponseSchema:
    refs = resolve_decision_refs(
        store, request.tenant_id, request.application_id, request.subject
    )
    enforce_tenant_scope_binding(principal, refs.tenant_id)
    delegation = apply_delegation(
        token=x_delegation_token,
        tenant_id=refs.tenant_id,
        application_id=refs.application_id,
        subject=refs.subject,
        delegations=delegations,
        settings=settings,
    )
    deny_reason = refs.deny_reason or delegation.deny_reason
    with DECISION_LATENCY.labels("bulk-authorize").time():
        if deny_reason is not None:
            decisions = [
                AuthorizeDecision.deny(deny_reason, f"{c.resource}.{c.action}")
                for c in request.checks
            ]
        else:
            decisions = engine.bulk_authorize(
                BulkAuthorizeRequest(
                    tenant_id=refs.tenant_id,
                    application_id=refs.application_id,
                    subject=_to_subject(delegation.subject),
                    checks=[(c.resource, c.action) for c in request.checks],
                    context=request.context,
                    delegated_permissions=delegation.permissions,
                )
            )
    for d in decisions:
        record_decision(
            application_id=refs.application_id,
            subject_type=request.subject.type,
            decision=d.decision,
            reason=d.reason,
        )
    results = [
        BulkCheckResultSchema(
            resource=check.resource,
            action=check.action,
            allowed=decision.allowed,
            reason=decision.reason,
        )
        for check, decision in zip(request.checks, decisions, strict=True)
    ]
    # Each individual decision audited so denies can be queried per resource.
    for check, decision, result in zip(request.checks, decisions, results, strict=True):
        audit.write(
            AuditEntry(
                decision=decision.decision,
                reason=decision.reason,
                resource=check.resource,
                action=check.action,
                tenant_id=refs.tenant_id,
                application_id=refs.application_id,
                user_id=delegation.subject.user_id,
                agent_id=delegation.subject.agent_id,
                request=_audit_payload(request, delegation.grant_id),
                response=result.model_dump(),
                request_id=request_id,
            ),
            request_id=request_id,
        )
    return BulkAuthorizeResponseSchema(results=results)


@router.post(
    "/effective-permissions",
    response_model=EffectivePermissionsResponseSchema,
)
def effective_permissions(
    request: EffectivePermissionsRequestSchema,
    engine: Annotated[AuthorizationEngine, Depends(get_authorization_engine)],
    principal: Annotated[Principal, Depends(require_runtime)],
    delegations: Annotated[DelegationService, Depends(get_delegation_service)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    x_delegation_token: DelegationHeader = None,
) -> EffectivePermissionsResponseSchema:
    refs = resolve_decision_refs(
        store, request.tenant_id, request.application_id, request.subject
    )
    enforce_tenant_scope_binding(principal, refs.tenant_id)
    if refs.deny_reason is not None:
        # Unknown reference: same answer as for an inactive tenant/user/agent.
        return EffectivePermissionsResponseSchema(
            tenant_id=refs.tenant_id,
            application_id=refs.application_id,
            subject=refs.subject,
            permissions=[],
        )
    delegation = apply_delegation(
        token=x_delegation_token,
        tenant_id=refs.tenant_id,
        application_id=refs.application_id,
        subject=refs.subject,
        delegations=delegations,
        settings=settings,
    )
    if delegation.deny_reason is not None:
        # Only reachable when the caller opted into delegation (header sent,
        # or AUTHZ_DELEGATION_REQUIRED) — an explicit error beats an empty set.
        raise HTTPException(status_code=403, detail={"error": delegation.deny_reason})
    permissions = engine.effective_permissions(
        tenant_id=refs.tenant_id,
        application_id=refs.application_id,
        subject=_to_subject(delegation.subject),
        delegated_permissions=delegation.permissions,
    )
    return EffectivePermissionsResponseSchema(
        tenant_id=refs.tenant_id,
        application_id=refs.application_id,
        subject=delegation.subject,
        permissions=sorted(permissions),
    )
