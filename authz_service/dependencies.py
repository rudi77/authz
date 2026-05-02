"""FastAPI dependencies: store, engine, auth, audit.

Service-to-service auth lives here. Two key sources are checked in order:

1. The ``AUTHZ_API_KEYS`` env-var list — kept for bootstrap and
   compatibility with the simple v0.1 deployment story.
2. The ``api_keys`` database table — scoped, hashed, rotatable.

The DB-backed lookup wins when both succeed; an env-var key is implicitly
``admin``-scoped because it predates the scoping system.
"""

from __future__ import annotations

import hmac
import logging
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import Engine

from authz_service.config import Settings, get_settings, should_auto_create_schema
from authzkit.audit.logger import AuditEntry
from authzkit.policies.engine import PolicyEngine
from authzkit.rbac.checker import AuthorizationEngine
from authzkit.security.api_keys import (
    SCOPE_ADMIN,
    SCOPE_RUNTIME,
    ApiKeyRecord,
    ApiKeyService,
    scope_allows,
    tenant_scope_matches,
)
from authzkit.security.invitations import InvitationService
from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url, init_schema

_log = logging.getLogger("authz")
_engine: Engine | None = None
_store: SqlAlchemyStore | None = None


def get_engine(settings: Annotated[Settings, Depends(get_settings)]) -> Engine:
    global _engine
    if _engine is None:
        _engine = create_engine_from_url(settings.database_url)
        if should_auto_create_schema(settings):
            _log.info("auto-creating schema (sqlite or AUTHZ_AUTO_CREATE_SCHEMA=true)")
            init_schema(_engine)
        else:
            _log.info(
                "schema auto-creation disabled; ensure 'alembic upgrade head' has run "
                "or set AUTHZ_AUTO_CREATE_SCHEMA=true"
            )
    return _engine


def get_store(engine: Annotated[Engine, Depends(get_engine)]) -> SqlAlchemyStore:
    global _store
    if _store is None or _store.engine is not engine:
        _store = SqlAlchemyStore(engine)
    return _store


def get_authorization_engine(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> AuthorizationEngine:
    return AuthorizationEngine(store, policy_engine=PolicyEngine())


def get_api_key_service(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> ApiKeyService:
    return ApiKeyService(store)


def get_invitation_service(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> InvitationService:
    return InvitationService(store)


class AuditSink:
    def __init__(self, store: SqlAlchemyStore, audit_all: bool) -> None:
        self.store = store
        self.audit_all = audit_all

    def write(self, entry: AuditEntry, *, request_id: str | None = None) -> None:
        if entry.decision != "allow" or self.audit_all:
            self.store.write_audit(entry, request_id=request_id)


def get_audit_sink(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuditSink:
    return AuditSink(store, audit_all=settings.audit_all_decisions)


# ----------------------------------------------------------------------------
# API key authentication
# ----------------------------------------------------------------------------


def _extract_key(authorization: str | None, x_api_key: str | None) -> str | None:
    if x_api_key:
        return x_api_key
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(None, 1)[1].strip()
    return None


def _env_key_record(candidate: str, env_keys: tuple[str, ...]) -> ApiKeyRecord | None:
    """Constant-time match against any of the env-configured keys.

    Iterating over every candidate (rather than a hash-set lookup) keeps
    the comparison time independent of whether the key prefix matches one
    of the configured values.
    """
    matched = False
    for known in env_keys:
        if hmac.compare_digest(candidate.encode("utf-8"), known.encode("utf-8")):
            matched = True
    if not matched:
        return None
    return ApiKeyRecord(
        id="env",
        name="env-bootstrap-key",
        key_prefix=candidate[:8],
        scopes=(SCOPE_ADMIN,),
        tenant_id=None,
        status="active",
        expires_at=None,
        last_used_at=None,
        rotates=None,
    )


def _resolve_api_key(
    candidate: str | None,
    settings: Settings,
    api_keys: ApiKeyService,
) -> ApiKeyRecord | None:
    if candidate is None:
        return None
    record = _env_key_record(candidate, settings.api_keys)
    if record is not None:
        return record
    return api_keys.find_active(candidate)


def require_api_key(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    api_keys: Annotated[ApiKeyService, Depends(get_api_key_service)],
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> ApiKeyRecord:
    """Service-to-service auth — backwards compatible with v0.1 env keys.

    Stashes the resolved record on ``request.state.api_key`` so per-route
    scope checks (admin vs runtime vs tenant-scoped) don't have to redo
    the lookup.
    """
    candidate = _extract_key(authorization, x_api_key)
    # Dev mode: only when explicitly opted in via AUTHZ_DEV_MODE=true *and*
    # no env keys *and* no DB keys, accept any caller. As soon as a single
    # DB key is provisioned the service flips to enforcing mode regardless
    # of the flag — the first real key auto-locks the service down.
    if (
        settings.dev_mode
        and not settings.api_keys
        and not _has_any_db_key(api_keys)
    ):
        stub = ApiKeyRecord(
            id="dev",
            name="dev-mode",
            key_prefix="dev",
            scopes=(SCOPE_ADMIN,),
            tenant_id=None,
            status="active",
            expires_at=None,
            last_used_at=None,
            rotates=None,
        )
        request.state.api_key = stub
        return stub
    record = _resolve_api_key(candidate, settings, api_keys)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "missing_or_invalid_api_key"},
        )
    request.state.api_key = record
    return record


def _has_any_db_key(api_keys: ApiKeyService) -> bool:
    """Cheap probe so dev mode auto-disables once a real key is provisioned."""
    return any(k.status == "active" for k in api_keys.list_keys())


def require_admin_scope(
    record: Annotated[ApiKeyRecord, Depends(require_api_key)],
) -> ApiKeyRecord:
    if not scope_allows(record.scopes, surface=SCOPE_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "scope_required", "scope": SCOPE_ADMIN},
        )
    return record


def require_runtime_scope(
    record: Annotated[ApiKeyRecord, Depends(require_api_key)],
) -> ApiKeyRecord:
    """Capability check for runtime endpoints.

    Lets through admin / runtime / tenant-scoped keys. The per-request
    tenant binding for tenant-scoped keys is enforced separately via
    :func:`enforce_tenant_scope_binding` because the tenant id only
    becomes known once the request body is parsed.
    """
    if not scope_allows(record.scopes, surface=SCOPE_RUNTIME):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "scope_required", "scope": SCOPE_RUNTIME},
        )
    return record


def enforce_tenant_scope_binding(record: ApiKeyRecord, tenant_id: str) -> None:
    """Reject runtime requests that target a tenant the key isn't bound to.

    Codex P1.1 — without this check, a key scoped ``tenant:<A>`` could
    call /v1/authorize with ``tenant_id=<B>`` and still receive a
    decision. Admin and runtime keys remain unrestricted.
    """
    if not tenant_scope_matches(record.scopes, tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "tenant_scope_mismatch", "tenant_id": tenant_id},
        )


def require_tenant_scope(tenant_id: str):
    """Build a dependency that requires admin OR tenant-specific scope."""

    def _checker(
        record: Annotated[ApiKeyRecord, Depends(require_api_key)],
    ) -> ApiKeyRecord:
        if not scope_allows(record.scopes, surface=SCOPE_ADMIN, tenant_id=tenant_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "scope_required", "tenant_id": tenant_id},
            )
        return record

    return _checker


def reset_engine() -> None:
    global _engine, _store
    _engine = None
    _store = None
