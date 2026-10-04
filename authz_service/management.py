"""Management ownership of applications (``managed_by``).

An application created through the catalog endpoint is *managed*: only the
caller that created it may change its permissions, roles, memberships and
agents. Everyone else — including other admins — gets
``403 application_managed_externally``. Platform surfaces (tenant masks,
feature flags, credentials, signing keys, delegation revocation) are not
affected. ``POST /v1/applications/{app}/release-management`` is the
operator's emergency exit.
"""

from __future__ import annotations

from fastapi import HTTPException, status

from authz_service.config import Settings
from authzkit.security.api_keys import ApiKeyRecord
from authzkit.security.principal import Principal, SessionPrincipal
from authzkit.tenancy.models import Application


def caller_label(principal: Principal, settings: Settings) -> str:
    """Stable identity of a caller as stored in ``managed_by``.

    ``client:<client_id>`` only for tokens this service issued itself, so an
    external IdP client with a colliding id can never match.
    """
    if isinstance(principal, ApiKeyRecord):
        return f"apikey:{principal.id}"
    if isinstance(principal, SessionPrincipal):
        return f"session:{principal.subject}"
    if principal.client_id and settings.oauth_issuer and principal.issuer == settings.oauth_issuer:
        return f"client:{principal.client_id}"
    return f"token:{principal.issuer}#{principal.client_id or principal.subject}"


def enforce_managed_by(app: Application, principal: Principal, settings: Settings) -> None:
    """Reject writes to a managed application by anyone but its manager."""
    if app.managed_by is not None and app.managed_by != caller_label(principal, settings):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "application_managed_externally", "managed_by": app.managed_by},
        )


def require_manager(app: Application, principal: Principal, settings: Settings) -> None:
    """Endpoints that only the manager may call at all (tenant state, role overrides)."""
    if app.managed_by is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "application_not_managed"},
        )
    enforce_managed_by(app, principal, settings)
