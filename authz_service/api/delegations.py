"""Delegation grants: a user hands an agent a time-boxed permission subset.

POST   /v1/delegations             — issue a grant (runtime), returns the signed JWT once
GET    /v1/delegations             — list grants (admin)
GET    /v1/delegations/jwks        — public keys to verify grants offline
GET    /v1/delegations/{id}        — read one grant (runtime)
DELETE /v1/delegations/{id}        — revoke one grant (runtime)
POST   /v1/delegations/revoke      — kill switch: revoke by tenant / user / agent (runtime)
POST   /v1/delegations/introspect  — RFC 7662-style token check (runtime)

The grant is *used* by sending it as ``X-Delegation-Token`` on
``/v1/authorize``, ``/v1/bulk-authorize`` and ``/v1/effective-permissions``;
see :func:`apply_delegation`. Without that header those endpoints behave
exactly as before.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator

from authz_service.config import Settings, get_settings
from authz_service.dependencies import (
    enforce_tenant_scope_binding,
    get_authorization_engine,
    get_delegation_service,
    get_signing_key_service,
    get_store,
    require_admin,
    require_runtime,
)
from authz_service.middleware import paginate_params
from authz_service.references import (
    find_agent_id,
    find_application,
    find_user_id,
    require_agent_id,
    require_application,
    require_tenant,
    require_user_id,
)
from authzkit.rbac.checker import SUBJECT_AGENT, AuthorizationEngine, Subject
from authzkit.security.delegations import (
    REASON_MISMATCH,
    REASON_REQUIRED,
    DelegationError,
    DelegationGrant,
    DelegationService,
)
from authzkit.security.principal import Principal, principal_subject_label
from authzkit.security.signing_keys import SigningKeyError, SigningKeyService
from authzkit.service.schemas import SubjectSchema, UserRefSchema
from authzkit.storage.sqlalchemy import SqlAlchemyStore

_log = logging.getLogger("authz.delegations")

router = APIRouter(prefix="/v1/delegations", tags=["delegations"])


def _at_most_one(a: object, b: object, names: str) -> None:
    if a is not None and b is not None:
        raise ValueError(f"give {names}, not both")


class DelegationIn(BaseModel):
    tenant_id: str = Field(description="Tenant id or slug")
    application_id: str = Field(description="Application id or slug")
    user_id: str | None = Field(default=None, description="The user delegating their access")
    user_ref: UserRefSchema | None = Field(
        default=None, description="Alternative to user_id: the user's IdP identity"
    )
    agent_id: str | None = Field(default=None, description="The agent receiving the delegation")
    agent_name: str | None = Field(
        default=None, description="Alternative to agent_id: the agent's name"
    )
    permissions: list[str] | None = Field(
        default=None,
        description="Subset to delegate. Omit to delegate everything the agent "
        "may currently do for this user (user ∩ agent ∩ tenant mask).",
    )
    ttl_seconds: int | None = Field(default=None, ge=1)
    purpose: str | None = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def _exactly_one_form(self) -> DelegationIn:
        if (self.user_id is None) == (self.user_ref is None):
            raise ValueError("give exactly one of user_id, user_ref")
        if (self.agent_id is None) == (self.agent_name is None):
            raise ValueError("give exactly one of agent_id, agent_name")
        return self


class DelegationOut(BaseModel):
    id: str
    tenant_id: str
    application_id: str
    user_id: str
    agent_id: str
    permissions: list[str]
    purpose: str | None
    issued_by: str | None
    status: str
    active: bool
    expires_at: datetime
    revoked_at: datetime | None
    created_at: datetime | None


class DelegationCreated(DelegationOut):
    """Returned once at issuance; ``token`` goes to the agent runtime."""

    token: str


class RevokeIn(BaseModel):
    tenant_id: str = Field(description="Tenant id or slug")
    application_id: str | None = Field(
        default=None, description="Application id or slug; required with agent_name"
    )
    user_id: str | None = None
    user_ref: UserRefSchema | None = None
    agent_id: str | None = None
    agent_name: str | None = None

    @model_validator(mode="after")
    def _one_form_per_reference(self) -> RevokeIn:
        _at_most_one(self.user_id, self.user_ref, "user_id or user_ref")
        _at_most_one(self.agent_id, self.agent_name, "agent_id or agent_name")
        if self.agent_name is not None and self.application_id is None:
            raise ValueError("agent_name needs application_id")
        return self


class IntrospectIn(BaseModel):
    token: str


def _out(grant: DelegationGrant) -> DelegationOut:
    return DelegationOut(
        id=grant.id,
        tenant_id=grant.tenant_id,
        application_id=grant.application_id,
        user_id=grant.user_id,
        agent_id=grant.agent_id,
        permissions=sorted(grant.permissions),
        purpose=grant.purpose,
        issued_by=grant.issued_by,
        status=grant.status,
        active=grant.active,
        expires_at=grant.expires_at,
        revoked_at=grant.revoked_at,
        created_at=grant.created_at,
    )


@router.post(
    "",
    response_model=DelegationCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_delegation(
    body: DelegationIn,
    principal: Annotated[Principal, Depends(require_runtime)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    engine: Annotated[AuthorizationEngine, Depends(get_authorization_engine)],
    delegations: Annotated[DelegationService, Depends(get_delegation_service)],
    signing_keys: Annotated[SigningKeyService, Depends(get_signing_key_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> DelegationCreated:
    tenant_id = require_tenant(store, body.tenant_id).id
    application_id = require_application(store, body.application_id).id
    user_id = body.user_id if body.user_ref is None else require_user_id(store, body.user_ref)
    if body.agent_name is not None:
        agent_id = require_agent_id(store, tenant_id, application_id, body.agent_name)
    else:
        assert body.agent_id is not None
        agent_id = body.agent_id
    assert user_id is not None
    enforce_tenant_scope_binding(principal, tenant_id)

    if store.get_agent(
        tenant_id=tenant_id, application_id=application_id, agent_id=agent_id
    ) is None:
        raise HTTPException(status_code=404, detail={"reason": "agent_not_found"})

    ttl = body.ttl_seconds or settings.delegation_default_ttl_seconds
    if ttl > settings.delegation_max_ttl_seconds:
        raise HTTPException(
            status_code=400,
            detail={"error": "ttl_too_long", "max_ttl_seconds": settings.delegation_max_ttl_seconds},
        )

    # What the agent may do for this user right now — a grant can only narrow it.
    available = engine.effective_permissions(
        tenant_id=tenant_id,
        application_id=application_id,
        subject=Subject(type=SUBJECT_AGENT, user_id=user_id, agent_id=agent_id),
    )
    if body.permissions is None:
        requested = set(available)
    else:
        requested = set(body.permissions)
        not_delegable = sorted(requested - available)
        if not_delegable:
            raise HTTPException(
                status_code=403,
                detail={"error": "permissions_not_delegable", "permissions": not_delegable},
            )
    if not requested:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "nothing_to_delegate",
                "hint": "user ∩ agent is empty, or the user/agent is inactive",
            },
        )

    kwargs = dict(
        tenant_id=tenant_id,
        application_id=application_id,
        user_id=user_id,
        agent_id=agent_id,
        permissions=requested,
        ttl=timedelta(seconds=ttl),
        purpose=body.purpose,
        issued_by=principal_subject_label(principal),
    )
    try:
        issued = delegations.issue(**kwargs)  # type: ignore[arg-type]
    except SigningKeyError as exc:
        if not settings.database_url.startswith("sqlite"):
            _log.error("delegation issuance failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "signing_key_unavailable",
                    "hint": "set AUTHZ_OAUTH_SIGNING_KEY_PEM or run "
                    "`authz oauth signing-key generate`",
                },
            ) from exc
        # SQLite: the key lives in the same file as everything else, so
        # bootstrapping one is no weaker than the data it protects.
        signing_keys.generate_if_missing()
        issued = delegations.issue(**kwargs)  # type: ignore[arg-type]
    return DelegationCreated(**_out(issued.grant).model_dump(), token=issued.token)


@router.get("", response_model=list[DelegationOut], dependencies=[Depends(require_admin)])
def list_delegations(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    delegations: Annotated[DelegationService, Depends(get_delegation_service)],
    tenant_id: str | None = None,
    user_id: str | None = None,
    user_provider: str | None = None,
    user_issuer: str | None = None,
    user_subject: str | None = None,
    application_id: str | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
    active_only: bool = False,
    page: int = 1,
    page_size: int = 100,
) -> list[DelegationOut]:
    """Filters accept references: ``tenant_id`` as id or slug, the user as
    ``user_provider`` + ``user_issuer`` + ``user_subject``, the agent as
    ``agent_name`` (with ``tenant_id`` and ``application_id``). A reference
    that matches nobody yields an empty list."""
    ref_parts = (user_provider, user_issuer, user_subject)
    if any(p is not None for p in ref_parts) and (
        user_id is not None or any(p is None for p in ref_parts)
    ):
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_user_ref", "hint": "user_id or all of user_provider, "
                    "user_issuer, user_subject"},
        )
    if agent_name is not None and (
        agent_id is not None or tenant_id is None or application_id is None
    ):
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_agent_ref", "hint": "agent_name needs tenant_id and "
                    "application_id, and excludes agent_id"},
        )
    resolved_tenant = require_tenant(store, tenant_id).id if tenant_id else None
    if user_provider is not None and user_issuer is not None and user_subject is not None:
        user_id = find_user_id(
            store, UserRefSchema(provider=user_provider, issuer=user_issuer, subject=user_subject)
        )
        if user_id is None:
            return []
    if agent_name is not None and resolved_tenant is not None and application_id is not None:
        app = find_application(store, application_id)
        agent_id = find_agent_id(store, resolved_tenant, app.id, agent_name) if app else None
        if agent_id is None:
            return []
    offset, limit = paginate_params(page, page_size)
    return [
        _out(g)
        for g in delegations.list(
            tenant_id=resolved_tenant,
            user_id=user_id,
            agent_id=agent_id,
            active_only=active_only,
            offset=offset,
            limit=limit,
        )
    ]


@router.get("/jwks")
def delegation_jwks(
    signing_keys: Annotated[SigningKeyService, Depends(get_signing_key_service)],
) -> JSONResponse:
    """Public verification keys (same set as the AS JWKS). No auth: keys are public."""
    return JSONResponse(signing_keys.all_public_jwks())


@router.post("/revoke")
def revoke_delegations(
    body: RevokeIn,
    principal: Annotated[Principal, Depends(require_runtime)],
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    delegations: Annotated[DelegationService, Depends(get_delegation_service)],
) -> dict:
    tenant_id = require_tenant(store, body.tenant_id).id
    enforce_tenant_scope_binding(principal, tenant_id)
    user_id = body.user_id if body.user_ref is None else require_user_id(store, body.user_ref)
    agent_id = body.agent_id
    if body.agent_name is not None:
        assert body.application_id is not None
        application_id = require_application(store, body.application_id).id
        agent_id = require_agent_id(store, tenant_id, application_id, body.agent_name)
    count = delegations.revoke_matching(tenant_id=tenant_id, user_id=user_id, agent_id=agent_id)
    return {"revoked": count}


@router.post("/introspect")
def introspect_delegation(
    body: IntrospectIn,
    principal: Annotated[Principal, Depends(require_runtime)],
    delegations: Annotated[DelegationService, Depends(get_delegation_service)],
) -> dict:
    try:
        grant = delegations.verify(body.token)
    except DelegationError as exc:
        return {"active": False, "reason": exc.reason}
    enforce_tenant_scope_binding(principal, grant.tenant_id)
    return {"active": True, **_out(grant).model_dump(mode="json")}


def _grant_for_caller(
    grant_id: str, principal: Principal, delegations: DelegationService
) -> DelegationGrant:
    grant = delegations.get(grant_id)
    if grant is None:
        raise HTTPException(status_code=404, detail={"reason": "delegation_not_found"})
    enforce_tenant_scope_binding(principal, grant.tenant_id)
    return grant


@router.get("/{grant_id}", response_model=DelegationOut)
def get_delegation(
    grant_id: str,
    principal: Annotated[Principal, Depends(require_runtime)],
    delegations: Annotated[DelegationService, Depends(get_delegation_service)],
) -> DelegationOut:
    return _out(_grant_for_caller(grant_id, principal, delegations))


@router.delete("/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_delegation(
    grant_id: str,
    principal: Annotated[Principal, Depends(require_runtime)],
    delegations: Annotated[DelegationService, Depends(get_delegation_service)],
) -> None:
    _grant_for_caller(grant_id, principal, delegations)
    delegations.revoke(grant_id)


# ---------------------------------------------------------------------------
# Used by the decision endpoints when X-Delegation-Token is present.
# ---------------------------------------------------------------------------


class DelegationOutcome(BaseModel):
    """Result of checking an optional ``X-Delegation-Token`` header."""

    permissions: frozenset[str] | None = None  # None → no grant in play
    grant_id: str | None = None
    deny_reason: str | None = None
    subject: SubjectSchema


def apply_delegation(
    *,
    token: str | None,
    tenant_id: str,
    application_id: str,
    subject: SubjectSchema,
    delegations: DelegationService,
    settings: Settings,
) -> DelegationOutcome:
    """Validate the grant against the request and return the subset to apply.

    No token → unchanged behaviour (unless ``AUTHZ_DELEGATION_REQUIRED``
    is on and the subject is an agent). With a token, an agent subject may
    omit ``user_id`` / ``agent_id``; they're filled in from the grant.
    """
    if not token:
        if settings.delegation_required and subject.type == SUBJECT_AGENT:
            return DelegationOutcome(deny_reason=REASON_REQUIRED, subject=subject)
        return DelegationOutcome(subject=subject)

    try:
        grant = delegations.verify(token)
    except DelegationError as exc:
        return DelegationOutcome(deny_reason=exc.reason, subject=subject)

    if subject.type != SUBJECT_AGENT:
        return DelegationOutcome(deny_reason=REASON_MISMATCH, grant_id=grant.id, subject=subject)
    filled = subject.model_copy(
        update={
            "user_id": subject.user_id or grant.user_id,
            "agent_id": subject.agent_id or grant.agent_id,
        }
    )
    if (
        tenant_id != grant.tenant_id
        or application_id != grant.application_id
        or filled.user_id != grant.user_id
        or filled.agent_id != grant.agent_id
    ):
        return DelegationOutcome(deny_reason=REASON_MISMATCH, grant_id=grant.id, subject=filled)
    return DelegationOutcome(permissions=grant.permissions, grant_id=grant.id, subject=filled)
