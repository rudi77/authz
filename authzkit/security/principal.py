"""Principal types used for caller identification.

Three principal kinds flow through the AuthZ service today:

- :class:`~authzkit.security.api_keys.ApiKeyRecord` — the original
  service-to-service API-key caller (long-lived bearer secret).
- :class:`TokenPrincipal` — a caller authenticated by a verified OAuth 2.0
  bearer JWT (RFC 6750), either from an external IdP or from this service's
  own Authorization-Server role.
- :class:`SessionPrincipal` — a browser session minted after an admin's
  OIDC login (Authorization Code + PKCE).

All three are unified via the :data:`Principal` discriminated-union alias
so downstream scope/tenant checks have a single entry point.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from authzkit.security.api_keys import (
    SCOPE_ADMIN,
    SCOPE_RUNTIME,
    ApiKeyRecord,
    scope_allows,
    tenant_scope_matches,
)

__all__ = [
    "Principal",
    "SessionPrincipal",
    "TokenPrincipal",
    "principal_scopes",
    "principal_tenant_id",
    "principal_subject_label",
    "principal_allows",
    "principal_tenant_matches",
]


@dataclass(frozen=True)
class TokenPrincipal:
    """Caller authenticated by a verified OAuth 2.0 bearer JWT.

    The contents of :attr:`claims` are the raw, *verified* JWT payload — i.e.
    after signature/iss/aud/exp checks. ``scopes`` are already mapped to the
    internal scope vocabulary (``admin``/``runtime``/``tenant:<id>``), not
    the raw external claim values.
    """

    issuer: str
    subject: str
    client_id: str | None
    scopes: tuple[str, ...]
    tenant_id: str | None
    claims: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SessionPrincipal:
    """Browser session minted from an admin OIDC login.

    The CSRF token is per-session, not per-request: the SPA reads it from
    ``GET /admin/session`` once and echoes it in ``X-CSRF-Token`` on every
    mutating call.
    """

    subject: str
    email: str | None
    scopes: tuple[str, ...]
    session_id: str
    csrf_token: str
    issuer: str | None = None


Principal = ApiKeyRecord | TokenPrincipal | SessionPrincipal


def principal_scopes(principal: Principal) -> tuple[str, ...]:
    """Pull the internal scope tuple regardless of principal kind."""
    return tuple(principal.scopes)


def principal_tenant_id(principal: Principal) -> str | None:
    """Tenant binding of the principal, or None for unrestricted callers."""
    return getattr(principal, "tenant_id", None)


def principal_subject_label(principal: Principal) -> str:
    """Short human-readable identifier used in audit logs.

    Stable across principal kinds so audit rows can be filtered by caller
    without first knowing what authenticated them.
    """
    if isinstance(principal, TokenPrincipal):
        return f"token:{principal.client_id or principal.subject}"
    if isinstance(principal, SessionPrincipal):
        return f"session:{principal.subject}"
    # ApiKeyRecord
    return f"apikey:{principal.id}"


def principal_allows(
    principal: Principal,
    *,
    surface: str,
    tenant_id: str | None = None,
) -> bool:
    """Surface-level capability check spanning every principal kind.

    Reuses :func:`scope_allows` so the matching semantics — admin implies
    everything, runtime implies the four PEP endpoints, ``tenant:<id>``
    implies runtime for that tenant — stay identical for tokens and
    sessions.
    """
    return scope_allows(principal.scopes, surface=surface, tenant_id=tenant_id)


def principal_tenant_matches(principal: Principal, tenant_id: str) -> bool:
    """Per-request tenant binding check (Codex P1.1 parity)."""
    return tenant_scope_matches(principal.scopes, tenant_id)


# Re-exported so callers can `from authzkit.security.principal import SCOPE_ADMIN`
# instead of needing to know about the api_keys module split.
__all__ += ["SCOPE_ADMIN", "SCOPE_RUNTIME"]
