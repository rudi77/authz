"""POST /v1/authorize, /v1/bulk-authorize, /v1/effective-permissions."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header

from authz_service.dependencies import (
    AuditSink,
    enforce_tenant_scope_binding,
    get_audit_sink,
    get_authorization_engine,
    require_runtime_scope,
)
from authz_service.observability import DECISION_LATENCY, record_decision
from authzkit.audit.logger import AuditEntry
from authzkit.rbac.checker import (
    AuthorizationEngine,
    AuthorizeRequest,
    BulkAuthorizeRequest,
    Subject,
)
from authzkit.security.api_keys import ApiKeyRecord
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

router = APIRouter(prefix="/v1", tags=["authorize"])


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
    api_key: Annotated[ApiKeyRecord, Depends(require_runtime_scope)],
    request_id: Annotated[str | None, Header(alias="X-Request-Id")] = None,
) -> AuthorizeResponseSchema:
    enforce_tenant_scope_binding(api_key, request.tenant_id)
    with DECISION_LATENCY.labels("authorize").time():
        decision = engine.authorize(
            AuthorizeRequest(
                tenant_id=request.tenant_id,
                application_id=request.application_id,
                subject=_to_subject(request.subject),
                resource=request.resource,
                action=request.action,
                context=request.context,
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
        application_id=request.application_id,
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
            tenant_id=request.tenant_id,
            application_id=request.application_id,
            user_id=request.subject.user_id,
            agent_id=request.subject.agent_id,
            request=request.model_dump(),
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
    api_key: Annotated[ApiKeyRecord, Depends(require_runtime_scope)],
    request_id: Annotated[str | None, Header(alias="X-Request-Id")] = None,
) -> BulkAuthorizeResponseSchema:
    enforce_tenant_scope_binding(api_key, request.tenant_id)
    with DECISION_LATENCY.labels("bulk-authorize").time():
        decisions = engine.bulk_authorize(
            BulkAuthorizeRequest(
                tenant_id=request.tenant_id,
                application_id=request.application_id,
                subject=_to_subject(request.subject),
                checks=[(c.resource, c.action) for c in request.checks],
                context=request.context,
            )
        )
    for d in decisions:
        record_decision(
            application_id=request.application_id,
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
                tenant_id=request.tenant_id,
                application_id=request.application_id,
                user_id=request.subject.user_id,
                agent_id=request.subject.agent_id,
                request=request.model_dump(),
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
    api_key: Annotated[ApiKeyRecord, Depends(require_runtime_scope)],
) -> EffectivePermissionsResponseSchema:
    enforce_tenant_scope_binding(api_key, request.tenant_id)
    permissions = engine.effective_permissions(
        tenant_id=request.tenant_id,
        application_id=request.application_id,
        subject=_to_subject(request.subject),
    )
    return EffectivePermissionsResponseSchema(
        tenant_id=request.tenant_id,
        application_id=request.application_id,
        subject=request.subject,
        permissions=sorted(permissions),
    )
