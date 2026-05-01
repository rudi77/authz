"""FastAPI dependencies: store, engine, auth, audit."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import Engine

from authzkit.audit.logger import AuditEntry
from authzkit.policies.engine import PolicyEngine
from authzkit.rbac.checker import AuthorizationEngine
from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url, init_schema
from authz_service.config import Settings, get_settings, should_auto_create_schema


_log = logging.getLogger("authz")
_engine: Engine | None = None
_store: SqlAlchemyStore | None = None


def get_engine(settings: Annotated[Settings, Depends(get_settings)]) -> Engine:
    global _engine
    if _engine is None:
        _engine = create_engine_from_url(settings.database_url)
        if should_auto_create_schema(settings):
            # Single source of truth: Alembic in production. Auto-create only
            # when the URL says "this is a dev/test DB" or the operator
            # explicitly opted in via AUTHZ_AUTO_CREATE_SCHEMA=true.
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


class AuditSink:
    """Service-level audit sink that writes to the SqlAlchemyStore."""

    def __init__(self, store: SqlAlchemyStore, audit_all: bool) -> None:
        self.store = store
        self.audit_all = audit_all

    def write(self, entry: AuditEntry, *, request_id: str | None = None) -> None:
        # Always log denies; allows are sampled-in via AUTHZ_AUDIT_ALL.
        if entry.decision != "allow" or self.audit_all:
            self.store.write_audit(entry, request_id=request_id)


def get_audit_sink(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuditSink:
    return AuditSink(store, audit_all=settings.audit_all_decisions)


def require_api_key(
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    """Service-to-service auth: API key in X-API-Key or "Bearer" header.

    When ``AUTHZ_API_KEYS`` is unset the server runs in development mode and
    accepts any caller; this is intentional and logged at startup.
    """
    if not settings.api_keys:
        return "dev"
    candidate = x_api_key
    if candidate is None and authorization and authorization.lower().startswith("bearer "):
        candidate = authorization.split(None, 1)[1].strip()
    if candidate and candidate in settings.api_keys:
        return candidate
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "missing_or_invalid_api_key"},
    )


# Dropping the engine in tests so a fresh DB url takes effect on the next call.
def reset_engine() -> None:
    global _engine, _store
    _engine = None
    _store = None
