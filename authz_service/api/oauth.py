"""OAuth 2.0 endpoints — Authorization Server + Admin-UI OIDC login.

This module hosts three URL families:

* ``POST /oauth/token`` (RFC 6749 §4.4), ``GET /.well-known/oauth-authorization-server``
  (RFC 8414), and ``GET /.well-known/jwks.json`` — only registered when
  ``AUTHZ_OAUTH_AS_ENABLED=true``.
* ``GET /oauth/login`` / ``GET /oauth/callback`` / ``POST /oauth/logout`` /
  ``GET /admin/session`` — only registered when ``AUTHZ_ADMIN_OIDC_ENABLED``
  resolves to true (auto when issuer + client_id are set).

The two halves share this module so the router toggle logic lives in one
place. The :func:`build_router` helper in :mod:`authz_service.main` decides
which endpoints to expose at app construction time.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import secrets
import time
import uuid
from typing import Annotated, Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, Form, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from authz_service.config import Settings, get_settings
from authz_service.dependencies import (
    SESSION_COOKIE_NAME,
    get_admin_session_service,
    get_oauth_client_service,
    get_signing_key_service,
    require_caller,
)
from authzkit.identity.jwt_validation import (
    JWTValidationError,
    JWTValidator,
    JWTValidatorConfig,
)
from authzkit.security.oauth_clients import OAuthClientService
from authzkit.security.principal import (
    SCOPE_ADMIN,
    Principal,
    SessionPrincipal,
    principal_allows,
)
from authzkit.security.sessions import AdminSessionService
from authzkit.security.signing_keys import SigningKeyError, SigningKeyService

_log = logging.getLogger("authz.oauth")

LOGIN_COOKIE_NAME = "authz_login_id"


# =========================================================================
# Authorization Server: /oauth/token, /.well-known/*
# =========================================================================


as_router = APIRouter(tags=["oauth"])


def _parse_basic_auth(header: str | None) -> tuple[str, str] | None:
    """Return ``(client_id, client_secret)`` from a Basic auth header, else None.

    Defensive against malformed headers: an attacker-controlled
    ``Authorization: Basic`` with trailing whitespace or no payload must
    not crash the process — every failure mode collapses to ``None``.
    """
    if not header or not header.lower().startswith("basic "):
        return None
    # ``split(None, 1)`` can return a single element when the header is
    # literally ``"Basic "``; guard the index before base64-decoding so the
    # caller sees the same ``invalid_client`` 401 as for any other bad
    # credential, not a 500.
    parts = header.split(None, 1)
    if len(parts) < 2:
        return None
    payload = parts[1].strip()
    if not payload:
        return None
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return None
    if b":" not in raw:
        return None
    cid, _, secret = raw.partition(b":")
    try:
        return cid.decode("utf-8"), secret.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _oauth_error(error: str, description: str, *, status_code: int) -> JSONResponse:
    """Render an RFC 6749 §5.2 error response."""
    body = {"error": error, "error_description": description}
    headers = {}
    if status_code == 401:
        headers["WWW-Authenticate"] = 'Basic realm="oauth"'
    return JSONResponse(body, status_code=status_code, headers=headers)


@as_router.post("/oauth/token")
def token_endpoint(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    clients: Annotated[OAuthClientService, Depends(get_oauth_client_service)],
    signing_keys: Annotated[SigningKeyService, Depends(get_signing_key_service)],
    grant_type: Annotated[str, Form()] = "",
    scope: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    """RFC 6749 §4.4 ``client_credentials`` token endpoint.

    Accepts both ``client_secret_basic`` (preferred) and
    ``client_secret_post`` per RFC 6749 §3.2.1; Basic wins when both are
    present so a malformed body doesn't silently dilute credentials.
    """
    if grant_type != "client_credentials":
        return _oauth_error(
            "unsupported_grant_type",
            f"grant_type {grant_type!r} not supported",
            status_code=400,
        )
    basic = _parse_basic_auth(authorization)
    if basic is not None:
        client_id, client_secret = basic
    if not client_id or not client_secret:
        return _oauth_error(
            "invalid_client", "client authentication required", status_code=401
        )
    client = clients.authenticate(client_id, client_secret)
    if client is None:
        return _oauth_error(
            "invalid_client", "client authentication failed", status_code=401
        )
    # Per-client_id rate-limit bucket. Applied here (post-auth) rather than
    # in the global middleware so we don't have to peek the form body before
    # the route can parse it. ``client_id`` is now known to be authentic.
    limiter = getattr(request.app.state, "rate_limiter", None)
    if limiter is not None:
        allowed, _remaining, retry_after = limiter.allow(f"oauth:{client.client_id}")
        if not allowed:
            response = JSONResponse(
                {"error": "rate_limited", "retry_after": retry_after},
                status_code=429,
            )
            response.headers["Retry-After"] = f"{retry_after:.0f}"
            return response
    requested = _parse_scope_request(scope, client.scopes)
    if requested is None:
        return _oauth_error(
            "invalid_scope",
            "requested scope is not allowed for this client",
            status_code=400,
        )
    if client.tenant_id is not None:
        # Tenant-bound clients always carry their tenant scope; we forbid
        # asking for a different tenant.
        for s in requested:
            if s.startswith("tenant:") and s != f"tenant:{client.tenant_id}":
                return _oauth_error(
                    "invalid_scope",
                    "client is bound to a different tenant",
                    status_code=400,
                )
        if f"tenant:{client.tenant_id}" not in requested:
            requested = (*requested, f"tenant:{client.tenant_id}")
    now = int(time.time())
    ttl = settings.oauth_access_token_ttl_seconds
    audience = settings.oauth_audience or settings.oauth_issuer
    claims: dict[str, Any] = {
        "iss": settings.oauth_issuer,
        "sub": client.client_id,
        "aud": audience,
        "exp": now + ttl,
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4()),
        "scope": " ".join(requested),
        "client_id": client.client_id,
    }
    if client.tenant_id is not None:
        claims["tenant_id"] = client.tenant_id
    try:
        token = signing_keys.sign(claims)
    except SigningKeyError as exc:
        _log.error("token issuance failed: %s", exc)
        return _oauth_error(
            "server_error", "signing key unavailable", status_code=500
        )
    return JSONResponse(
        {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": ttl,
            "scope": " ".join(requested),
        }
    )


def _parse_scope_request(
    scope: str | None, owned: tuple[str, ...]
) -> tuple[str, ...] | None:
    """Intersect requested scope with what the client owns.

    None of ``requested`` ⊄ ``owned`` ⇒ invalid_scope. Empty request grants
    the full set the client owns. Returns ``None`` to signal rejection.
    """
    owned_set = set(owned)
    if not scope or not scope.strip():
        return owned
    requested = tuple(s for s in scope.split(" ") if s)
    if not requested:
        return owned
    for s in requested:
        if s not in owned_set:
            return None
    return requested


@as_router.get("/.well-known/oauth-authorization-server")
def authorization_server_metadata(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> JSONResponse:
    """RFC 8414 Authorization Server Metadata."""
    base = settings.oauth_issuer or str(request.base_url).rstrip("/")
    return JSONResponse(
        {
            "issuer": settings.oauth_issuer or base,
            "token_endpoint": f"{base}/oauth/token",
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "grant_types_supported": ["client_credentials"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "response_types_supported": [],
            "scopes_supported": ["admin", "runtime"],
        }
    )


@as_router.get("/.well-known/jwks.json")
def jwks_endpoint(
    signing_keys: Annotated[SigningKeyService, Depends(get_signing_key_service)],
) -> JSONResponse:
    """Public JWKs for verifying service-issued tokens (active + retiring)."""
    try:
        return JSONResponse(signing_keys.all_public_jwks())
    except SigningKeyError:
        # AS enabled but no key yet — return empty set rather than 500 so
        # the metadata document is still useful for clients.
        return JSONResponse({"keys": []})


# =========================================================================
# Admin OIDC: /oauth/login, /oauth/callback, /oauth/logout, /admin/session
# =========================================================================


admin_router = APIRouter(tags=["oauth"])


def _pkce_pair() -> tuple[str, str]:
    """Generate (verifier, challenge) pair per RFC 7636.

    ``code_verifier`` is 43–128 chars of unreserved URI characters; we use
    the urlsafe alphabet via ``secrets.token_urlsafe``. The challenge is
    base64url(SHA-256(verifier)) with no padding.
    """
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


_OIDC_DISCOVERY_TTL_SECONDS = 3600.0  # 1 hour
_OIDC_DISCOVERY_CACHE: dict[str, tuple[dict[str, Any], float]] = {}


def _oidc_discover(
    issuer: str, *, http: httpx.Client | None = None
) -> dict[str, Any]:
    """Discover the IdP's authorization and token endpoints.

    Cached per process with a 1-hour TTL so the operator does not have to
    restart the service after an IdP endpoint migration. JWKS is cached
    separately by the long-lived :class:`JWTValidator` (see
    :func:`_admin_validator`); both caches stay in sync because every
    callback consults discovery before JWKS.
    """
    now = time.monotonic()
    cached = _OIDC_DISCOVERY_CACHE.get(issuer)
    if cached is not None and cached[1] > now:
        return cached[0]
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    client = http or httpx.Client(timeout=5.0)
    try:
        response = client.get(url)
        if response.status_code >= 400:
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "oidc_discovery_failed",
                    "issuer": issuer,
                    "status": response.status_code,
                },
            )
        payload = response.json()
    finally:
        if http is None:
            client.close()
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=502,
            detail={"error": "oidc_discovery_invalid", "issuer": issuer},
        )
    _OIDC_DISCOVERY_CACHE[issuer] = (payload, now + _OIDC_DISCOVERY_TTL_SECONDS)
    return payload


# Module-level admin JWTValidator cache, keyed by (issuer, audience). Each
# entry retains its own JWKS cache (TTL governed by ``JWTValidator``), so a
# burst of /oauth/callback hits doesn't hammer the IdP. ``reset_admin_oidc``
# is exposed for tests; production never invalidates this cache.
_ADMIN_VALIDATORS: dict[tuple[str, str], JWTValidator] = {}


def _admin_validator(issuer: str, audience: str) -> JWTValidator:
    """Return a process-shared JWTValidator for the admin IdP.

    Without this cache, every callback built a fresh validator (and its
    embedded ``httpx.Client``), leaking sockets and refetching the IdP's
    JWKS on every login.
    """
    key = (issuer, audience)
    cached = _ADMIN_VALIDATORS.get(key)
    if cached is not None:
        return cached
    cached = JWTValidator(
        [JWTValidatorConfig(issuer=issuer, audience=audience)],
    )
    _ADMIN_VALIDATORS[key] = cached
    return cached


def reset_admin_oidc() -> None:
    """Test hook: clear discovery + validator caches between tests."""
    _OIDC_DISCOVERY_CACHE.clear()
    _ADMIN_VALIDATORS.clear()


@admin_router.get("/oauth/login")
def oidc_login(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    sessions: Annotated[AdminSessionService, Depends(get_admin_session_service)],
    return_to: str = "/admin/",
) -> RedirectResponse:
    """Kick off the OIDC Authorization-Code + PKCE flow."""
    if not _admin_oidc_configured(settings):
        raise HTTPException(
            status_code=503, detail={"error": "admin_oidc_not_configured"}
        )
    if not _is_safe_return_to(return_to):
        # Open-redirect guard: only accept same-origin absolute paths.
        # Reject protocol-relative URLs (``//evil.com/x``), backslash
        # variants (``/\evil.com``), and anything with an explicit scheme.
        return_to = "/admin/"
    discovery = _oidc_discover(settings.admin_oidc_issuer)
    auth_url = discovery.get("authorization_endpoint")
    if not auth_url:
        raise HTTPException(
            status_code=502, detail={"error": "no_authorization_endpoint"}
        )
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    verifier, challenge = _pkce_pair()
    attempt = sessions.create_login_attempt(
        state=state, code_verifier=verifier, nonce=nonce, return_to=return_to
    )
    params = {
        "response_type": "code",
        "client_id": settings.admin_oidc_client_id,
        "redirect_uri": settings.admin_oidc_redirect_uri,
        "scope": settings.admin_oidc_scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    target = f"{auth_url}?{urlencode(params)}"
    response = RedirectResponse(target, status_code=302)
    response.set_cookie(
        LOGIN_COOKIE_NAME,
        attempt.id,
        max_age=600,
        httponly=True,
        secure=not settings.dev_mode,
        samesite="lax",
        path="/",
    )
    return response


@admin_router.get("/oauth/callback")
def oidc_callback(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    sessions: Annotated[AdminSessionService, Depends(get_admin_session_service)],
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> RedirectResponse:
    """Exchange the authorization code, validate id_token, set session cookie."""
    if not _admin_oidc_configured(settings):
        raise HTTPException(
            status_code=503, detail={"error": "admin_oidc_not_configured"}
        )
    if error:
        raise HTTPException(
            status_code=400,
            detail={"error": error, "error_description": error_description or ""},
        )
    if not code or not state:
        raise HTTPException(status_code=400, detail={"error": "missing_code_or_state"})
    cookie_id = request.cookies.get(LOGIN_COOKIE_NAME)
    if not cookie_id:
        raise HTTPException(status_code=400, detail={"error": "missing_login_cookie"})
    attempt = sessions.consume_login_attempt(cookie_id, state=state)
    if attempt is None:
        raise HTTPException(status_code=400, detail={"error": "invalid_state"})
    discovery = _oidc_discover(settings.admin_oidc_issuer)
    token_url = discovery.get("token_endpoint")
    if not token_url:
        raise HTTPException(
            status_code=502, detail={"error": "no_token_endpoint"}
        )
    token_response = _exchange_code(
        token_url=token_url,
        code=code,
        redirect_uri=settings.admin_oidc_redirect_uri,
        client_id=settings.admin_oidc_client_id,
        client_secret=settings.admin_oidc_client_secret,
        code_verifier=attempt.code_verifier,
    )
    id_token = token_response.get("id_token")
    if not id_token:
        raise HTTPException(status_code=502, detail={"error": "no_id_token"})
    claims = _validate_admin_id_token(
        id_token,
        issuer=settings.admin_oidc_issuer,
        audience=settings.admin_oidc_client_id,
        nonce=attempt.nonce,
    )
    scopes = _admin_scopes_from_claims(claims, settings)
    if not scopes:
        raise HTTPException(
            status_code=403,
            detail={"error": "admin_access_denied", "reason": "no admin claims"},
        )
    session = sessions.create_session(
        subject=str(claims.get("sub", "")),
        email=claims.get("email"),
        issuer=settings.admin_oidc_issuer,
        scopes=scopes,
        raw_claims=dict(claims),
    )
    response = RedirectResponse(attempt.return_to, status_code=302)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session.id,
        max_age=settings.admin_oidc_session_ttl_seconds,
        httponly=True,
        secure=not settings.dev_mode,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(LOGIN_COOKIE_NAME, path="/")
    return response


def _exchange_code(
    *,
    token_url: str,
    code: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str,
    code_verifier: str,
) -> dict[str, Any]:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "code_verifier": code_verifier,
    }
    with httpx.Client(timeout=5.0) as http:
        response = http.post(token_url, data=data)
    if response.status_code >= 400:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "token_exchange_failed",
                "status": response.status_code,
                "body": response.text,
            },
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=502, detail={"error": "token_exchange_invalid"}
        )
    return payload


def _validate_admin_id_token(
    id_token: str, *, issuer: str, audience: str, nonce: str
) -> dict[str, Any]:
    """Verify the id_token signature, iss, aud, exp, and nonce.

    Uses a process-shared :class:`JWTValidator` (see :func:`_admin_validator`)
    so the JWKS cache is amortised across logins.
    """
    validator = _admin_validator(issuer, audience)
    try:
        claims = validator.validate(id_token, expected_issuer=issuer)
    except JWTValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_id_token", "reason": str(exc)},
        ) from exc
    if claims.get("nonce") != nonce:
        raise HTTPException(
            status_code=400, detail={"error": "nonce_mismatch"}
        )
    return claims


def _admin_scopes_from_claims(
    claims: dict[str, Any], settings: Settings
) -> tuple[str, ...]:
    """Map verified id_token claims to internal admin scopes.

    Groups are trusted directly: IdPs assign them through their own admin
    surface, attestation is implicit.

    The email allowlist is **only** consulted when the IdP also confirmed
    the email is verified (``email_verified=true`` per OIDC core §5.1).
    Without that gate, a user who can register an arbitrary email at the
    IdP (Entra personal accounts, Auth0 passwordless, multi-tenant apps)
    could claim an admin email they don't own and inherit the admin
    scope — verified by signature + iss + aud is not the same as verified
    ownership of the email.
    """
    groups_claim = settings.admin_oidc_groups_claim
    admin_groups = set(settings.admin_oidc_admin_groups)
    raw_groups = claims.get(groups_claim) or []
    if isinstance(raw_groups, str):
        raw_groups = [raw_groups]
    if any(g in admin_groups for g in raw_groups):
        return (SCOPE_ADMIN,)
    email = claims.get("email")
    email_verified = claims.get("email_verified")
    if (
        email
        and email_verified is True
        and email.lower()
        in {e.lower() for e in settings.admin_oidc_email_allowlist}
    ):
        return (SCOPE_ADMIN,)
    return ()


@admin_router.post("/oauth/logout")
def oidc_logout(
    request: Request,
    sessions: Annotated[AdminSessionService, Depends(get_admin_session_service)],
    principal: Annotated[Principal, Depends(require_caller)],
) -> JSONResponse:
    """Delete the session row and clear the cookie.

    Depends on :func:`require_caller` so the CSRF token is enforced for
    session-authenticated callers — without this, a drive-by cross-origin
    page could force-log-out an admin (CSRF logout, sometimes used as a
    stepping stone for session fixation). API-key or Bearer-JWT callers
    are accepted too (so an automation pipeline can revoke its own UI
    session) but they will have no session cookie to clear.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if isinstance(principal, SessionPrincipal):
        sessions.delete_session(principal.session_id)
    elif session_id:
        # API-key / token caller passing a session cookie along — best-effort
        # cleanup. require_caller didn't validate this cookie because the
        # X-API-Key path won out.
        sessions.delete_session(session_id)
    response = JSONResponse({"status": "logged_out"})
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


@admin_router.get("/admin/session")
def session_probe(
    principal: Annotated[Principal, Depends(require_caller)],
) -> JSONResponse:
    """Return the current session's principal info so the SPA can render UI.

    Works for any principal kind — API-key callers get a minimal view, the
    SPA mostly cares about session principals so it can pull the CSRF
    token. Bearer-JWT callers see the mapped scopes only.
    """
    if isinstance(principal, SessionPrincipal):
        return JSONResponse(
            {
                "authenticated": True,
                "kind": "session",
                "subject": principal.subject,
                "email": principal.email,
                "scopes": list(principal.scopes),
                "csrf_token": principal.csrf_token,
                "is_admin": principal_allows(principal, surface=SCOPE_ADMIN),
            }
        )
    # API-key or token principal — they don't need CSRF.
    return JSONResponse(
        {
            "authenticated": True,
            "kind": "apikey" if hasattr(principal, "key_prefix") else "token",
            "scopes": list(principal.scopes),
            "is_admin": principal_allows(principal, surface=SCOPE_ADMIN),
        }
    )


def _admin_oidc_configured(settings: Settings) -> bool:
    return bool(
        settings.admin_oidc_issuer
        and settings.admin_oidc_client_id
        and settings.admin_oidc_client_secret
        and settings.admin_oidc_redirect_uri
    )


def _is_safe_return_to(target: str) -> bool:
    """Return True iff ``target`` is a same-origin absolute path.

    Reject anything that a browser would route off-origin:
    * Protocol-relative (``//host/x`` or ``/\\host/x`` — backslashes are
      normalized to forward slashes by some browsers).
    * Explicit scheme (``http:`` / ``https:`` / ``javascript:`` / ``data:`` …).
    * Anything not starting with ``/`` (relative URLs are interpreted
      against the current page).
    """
    if not target or not target.startswith("/"):
        return False
    if target.startswith("//") or target.startswith("/\\"):
        return False
    # Defence in depth: parse and require netloc/scheme to be empty.
    from urllib.parse import urlparse

    parsed = urlparse(target)
    return not parsed.scheme and not parsed.netloc


__all__ = ["admin_router", "as_router", "LOGIN_COOKIE_NAME"]
