"""FastAPI dependencies: store, engine, auth, audit.

Service-to-service auth lives here. The service accepts three principal
kinds, resolved by :func:`require_caller` and unified through the
:data:`~authzkit.security.principal.Principal` discriminated union:

1. **API keys** (:class:`ApiKeyRecord`) — checked in two sources, in order:
   the ``AUTHZ_API_KEYS`` env-var list (admin-implicit, kept for v0.1
   compatibility) and the DB-backed ``api_keys`` table.
2. **OAuth Bearer JWTs** (:class:`TokenPrincipal`) — verified against the
   configured external issuers; this service may also be one of the
   issuers when the Authorization-Server role is enabled.
3. **Admin sessions** (:class:`SessionPrincipal`) — established by the
   ``/oauth/login`` → ``/oauth/callback`` OIDC flow; carried by the
   ``authz_session`` cookie.

The legacy ``require_api_key`` / ``require_admin_scope`` / ``require_runtime_scope``
helpers are kept as thin wrappers around the union-aware variants so
existing routers can be migrated incrementally.
"""

from __future__ import annotations

import hmac
import logging
import re
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import Engine

from authz_service.config import (
    Settings,
    admin_oidc_is_enabled,
    get_settings,
    oauth_resource_is_enabled,
    should_auto_create_schema,
)
from authzkit.audit.logger import AuditEntry
from authzkit.identity.jwt_validation import JWTValidationError
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
from authzkit.security.oauth_clients import OAuthClientService
from authzkit.security.oauth_resource import JwtResolver
from authzkit.security.principal import (
    Principal,
    SessionPrincipal,
    TokenPrincipal,
    principal_allows,
)
from authzkit.security.sessions import AdminSessionService
from authzkit.security.signing_keys import SigningKeyService
from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url, init_schema

_log = logging.getLogger("authz")
_engine: Engine | None = None
_store: SqlAlchemyStore | None = None
_jwt_resolver: JwtResolver | None = None
_signing_key_service: SigningKeyService | None = None

# JWT shape sniff: three base64url segments joined by ``.``. ``=`` padding is
# legal in JWS too, even though most issuers strip it.
_JWT_SHAPE_RE = re.compile(r"^[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+$")


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


def get_oauth_client_service(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
) -> OAuthClientService:
    return OAuthClientService(store)


def get_signing_key_service(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SigningKeyService:
    """Singleton so the in-process key cache stays warm across requests."""
    global _signing_key_service
    if _signing_key_service is None or _signing_key_service.store is not store:
        _signing_key_service = SigningKeyService(
            store,
            env_pem=settings.oauth_signing_key_pem,
            dev_mode=settings.dev_mode,
            database_url=settings.database_url,
        )
    return _signing_key_service


def get_admin_session_service(
    store: Annotated[SqlAlchemyStore, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AdminSessionService:
    return AdminSessionService(
        store, session_ttl_seconds=settings.admin_oidc_session_ttl_seconds
    )


def get_jwt_resolver(
    settings: Annotated[Settings, Depends(get_settings)],
    signing_keys: Annotated[SigningKeyService, Depends(get_signing_key_service)],
) -> JwtResolver | None:
    """Build the multi-issuer JWT resolver, once.

    Returns ``None`` when neither external issuers nor the AS self-issuer
    are configured — callers treat that as "no Bearer-JWT support". The
    self-issuer is auto-injected when the Authorization Server is enabled
    so PEPs can present tokens minted by this same service.
    """
    global _jwt_resolver
    if _jwt_resolver is not None:
        return _jwt_resolver
    issuers = _load_issuer_configs(settings)
    self_issuer = settings.oauth_issuer if settings.oauth_as_enabled else None
    self_provider = None
    if self_issuer:
        # Ensure the self-issuer is part of the resolver's known set so
        # ``_peek_issuer`` routes self-issued tokens to the local path.
        from authzkit.security.oauth_resource import IssuerConfig

        if not any(cfg.issuer == self_issuer for cfg in issuers):
            audience = settings.oauth_audience or settings.oauth_issuer
            issuers.append(
                IssuerConfig(
                    issuer=self_issuer,
                    audience=audience,
                    scope_claim="scope",
                    tenant_claim="tenant_id",
                )
            )
        self_provider = signing_keys.all_public_jwks
    if not issuers:
        return None
    _jwt_resolver = JwtResolver(
        issuers,
        jwks_ttl_seconds=float(settings.oauth_jwks_cache_ttl_seconds),
        self_issuer=self_issuer,
        self_jwks_provider=self_provider,
    )
    return _jwt_resolver


def _load_issuer_configs(settings: Settings):
    # Local import to avoid module-load-order issues; oauth_config imports Settings.
    from authz_service.oauth_config import load_issuer_configs

    return load_issuer_configs(settings)


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
# Credential extraction
# ----------------------------------------------------------------------------


def _looks_like_jwt(candidate: str) -> bool:
    """Cheap shape test so ``Authorization: Bearer <opaque-api-key>`` still works.

    We do not parse the token here — if it has three base64url segments
    separated by ``.``, send it down the JWT path; otherwise treat the
    value as an opaque API key. ``X-API-Key`` always wins regardless of
    what's in ``Authorization`` so the historical caller behaviour is
    preserved exactly.
    """
    return bool(_JWT_SHAPE_RE.match(candidate))


def _extract_credential(
    authorization: str | None, x_api_key: str | None
) -> tuple[str, str] | None:
    """Return ``("api_key"|"jwt", value)`` or None.

    Resolution rules — kept identical to the v0.1 behaviour for the API-key
    path so SDK clients don't regress:

    * ``X-API-Key`` header present → API key, wins over anything else.
    * Otherwise ``Authorization: Bearer …`` is examined; the value is
      classified as a JWT iff it has the three-segment shape, else as an
      opaque API key (this preserves the legacy "Bearer <api-key>" path).
    """
    if x_api_key:
        return ("api_key", x_api_key)
    if authorization and authorization.lower().startswith("bearer "):
        # ``split(None, 1)`` collapses runs of whitespace and may return a
        # single element (e.g. for the malformed value ``"Bearer "`` with
        # no token after the space). Guard the index access so a malformed
        # header surfaces as 401, not 500.
        parts = authorization.split(None, 1)
        if len(parts) < 2:
            return None
        value = parts[1].strip()
        if not value:
            return None
        return ("jwt" if _looks_like_jwt(value) else "api_key", value)
    return None


# Kept for backward compatibility — only used in legacy call sites.
def _extract_key(authorization: str | None, x_api_key: str | None) -> str | None:
    cred = _extract_credential(authorization, x_api_key)
    if cred is None:
        return None
    return cred[1]


# ----------------------------------------------------------------------------
# API key authentication (DB + env)
# ----------------------------------------------------------------------------


def _env_key_record(candidate: str, env_keys: tuple[str, ...]) -> ApiKeyRecord | None:
    """Constant-time match against any of the env-configured keys."""
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


def _has_any_db_key(api_keys: ApiKeyService) -> bool:
    """Cheap probe so dev mode auto-disables once a real key is provisioned."""
    return any(k.status == "active" for k in api_keys.list_keys())


def _dev_bypass_active(
    settings: Settings,
    api_keys: ApiKeyService,
    jwt_resolver: JwtResolver | None,
) -> bool:
    """Dev-mode bypass fires only when *no* auth source is configured.

    Extended for OAuth: the moment any external issuer is configured (or
    the AS is enabled), the bypass disengages. Mirrors the API-key
    auto-lock semantics — a provisioned credential always wins over
    convenience.
    """
    if not settings.dev_mode:
        return False
    if settings.api_keys:
        return False
    if _has_any_db_key(api_keys):
        return False
    if jwt_resolver is not None and jwt_resolver.issuers:
        return False
    if oauth_resource_is_enabled(settings):
        return False
    return not admin_oidc_is_enabled(settings)


def _dev_bypass_principal() -> ApiKeyRecord:
    return ApiKeyRecord(
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


# ----------------------------------------------------------------------------
# Session lookup (admin OIDC)
# ----------------------------------------------------------------------------


SESSION_COOKIE_NAME = "authz_session"


def _resolve_session(
    request: Request, session_service: AdminSessionService
) -> SessionPrincipal | None:
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return None
    session = session_service.lookup_session(session_id)
    if session is None:
        return None
    return session_service.to_principal(session)


# ----------------------------------------------------------------------------
# Unified caller resolution
# ----------------------------------------------------------------------------


def require_caller(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    api_keys: Annotated[ApiKeyService, Depends(get_api_key_service)],
    sessions: Annotated[AdminSessionService, Depends(get_admin_session_service)],
    jwt_resolver: Annotated[JwtResolver | None, Depends(get_jwt_resolver)] = None,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> Principal:
    """Resolve the caller into a :data:`Principal` or raise 401.

    Resolution order:
    1. Dev-mode bypass (preserves v0.1 convenience).
    2. ``X-API-Key`` header or ``Authorization: Bearer <opaque>``.
    3. ``Authorization: Bearer <jwt>`` — only if a resolver is configured.
    4. Admin session cookie.
    """
    if _dev_bypass_active(settings, api_keys, jwt_resolver):
        principal = _dev_bypass_principal()
        request.state.api_key = principal
        request.state.principal = principal
        return principal

    cred = _extract_credential(authorization, x_api_key)
    if cred is not None:
        kind, value = cred
        if kind == "api_key":
            record = _resolve_api_key(value, settings, api_keys)
            if record is not None:
                request.state.api_key = record
                request.state.principal = record
                return record
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "missing_or_invalid_api_key"},
            )
        # kind == "jwt"
        if jwt_resolver is None:
            raise _bearer_401("Bearer JWT auth is not configured on this service")
        try:
            token_principal = jwt_resolver.resolve(value)
        except JWTValidationError as exc:
            raise _bearer_401(str(exc)) from exc
        request.state.principal = token_principal
        return token_principal

    # No header — fall through to session cookie before failing.
    session_principal = _resolve_session(request, sessions)
    if session_principal is not None:
        request.state.principal = session_principal
        _enforce_csrf(request, session_principal)
        return session_principal

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "missing_or_invalid_api_key"},
        headers={"WWW-Authenticate": 'Bearer realm="authz"'},
    )


def require_api_key(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    api_keys: Annotated[ApiKeyService, Depends(get_api_key_service)],
    sessions: Annotated[AdminSessionService, Depends(get_admin_session_service)],
    jwt_resolver: Annotated[JwtResolver | None, Depends(get_jwt_resolver)] = None,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> ApiKeyRecord:
    """Back-compat wrapper. New code should use :func:`require_caller`.

    Only API-key principals make it through; JWT/Session callers get 401
    so legacy routes don't accidentally widen their auth surface during
    the migration.
    """
    principal = require_caller(
        request, settings, api_keys, sessions, jwt_resolver, authorization, x_api_key
    )
    if not isinstance(principal, ApiKeyRecord):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "missing_or_invalid_api_key"},
        )
    return principal


def require_admin(
    principal: Annotated[Principal, Depends(require_caller)],
) -> Principal:
    """Admit any principal whose scopes include ``admin``."""
    if not principal_allows(principal, surface=SCOPE_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "scope_required", "scope": SCOPE_ADMIN},
            headers=_insufficient_scope_header(principal, SCOPE_ADMIN),
        )
    return principal


def require_runtime(
    principal: Annotated[Principal, Depends(require_caller)],
) -> Principal:
    """Admit admin / runtime / any tenant-scoped principal."""
    if not principal_allows(principal, surface=SCOPE_RUNTIME):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "scope_required", "scope": SCOPE_RUNTIME},
            headers=_insufficient_scope_header(principal, SCOPE_RUNTIME),
        )
    return principal


def require_admin_scope(
    record: Annotated[ApiKeyRecord, Depends(require_api_key)],
) -> ApiKeyRecord:
    """Legacy admin-scope check restricted to API-key callers."""
    if not scope_allows(record.scopes, surface=SCOPE_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "scope_required", "scope": SCOPE_ADMIN},
        )
    return record


def require_runtime_scope(
    record: Annotated[ApiKeyRecord, Depends(require_api_key)],
) -> ApiKeyRecord:
    """Legacy runtime-scope check restricted to API-key callers."""
    if not scope_allows(record.scopes, surface=SCOPE_RUNTIME):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "scope_required", "scope": SCOPE_RUNTIME},
        )
    return record


def enforce_tenant_scope_binding(
    principal: Principal | ApiKeyRecord, tenant_id: str
) -> None:
    """Reject requests that target a tenant the principal isn't bound to.

    Two layered checks:

    1. **Hard tenant pin** — if the principal carries an explicit
       ``tenant_id`` (a JWT ``tid`` claim resolved by
       :class:`JwtResolver`, or a tenant-bound API key), it must equal
       the requested tenant. This fires *even when* the scope vocabulary
       would otherwise allow cross-tenant access (``admin`` / ``runtime``).
       Without this layer, an IdP-issued token pinned to tenant A could
       authorize requests against tenant B as long as it also carried
       ``runtime`` scope.
    2. **Scope vocabulary** — for principals without an explicit pin,
       the historical Codex P1.1 behaviour: ``admin`` / ``runtime``
       passes anywhere, ``tenant:<id>`` only for the matching id.
    """
    pin = getattr(principal, "tenant_id", None)
    if pin is not None and pin != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "tenant_scope_mismatch", "tenant_id": tenant_id},
        )
    if not tenant_scope_matches(principal.scopes, tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "tenant_scope_mismatch", "tenant_id": tenant_id},
        )


def require_tenant_scope(tenant_id: str):
    """Build a dependency that requires admin OR tenant-specific scope."""

    def _checker(
        principal: Annotated[Principal, Depends(require_caller)],
    ) -> Principal:
        if not principal_allows(principal, surface=SCOPE_ADMIN, tenant_id=tenant_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "scope_required", "tenant_id": tenant_id},
            )
        return principal

    return _checker


# ----------------------------------------------------------------------------
# CSRF + RFC 6750 helpers
# ----------------------------------------------------------------------------

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _enforce_csrf(request: Request, principal: SessionPrincipal) -> None:
    """Reject session-authenticated mutating requests without a matching CSRF token.

    Browser-credentialed sessions are the only principal kind subject to
    CSRF — bearer-JWT and X-API-Key callers carry their credential out-of-band
    and the browser cannot attach those headers cross-origin.
    """
    if request.method not in _MUTATING_METHODS:
        return
    presented = request.headers.get("X-CSRF-Token", "")
    if not hmac.compare_digest(presented, principal.csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "csrf_token_required"},
        )


def _bearer_401(description: str) -> HTTPException:
    safe = description.replace('"', "'")
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "invalid_token", "error_description": description},
        headers={"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{safe}"'},
    )


def _insufficient_scope_header(
    principal: Principal, scope: str
) -> dict[str, str] | None:
    """Add ``WWW-Authenticate`` only when the caller is a Bearer principal."""
    if isinstance(principal, TokenPrincipal):
        return {"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{scope}"'}
    return None


def reset_engine() -> None:
    global _engine, _store, _jwt_resolver, _signing_key_service
    _engine = None
    _store = None
    _jwt_resolver = None
    _signing_key_service = None
