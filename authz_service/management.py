"""Management ownership of applications (``managed_by``).

An application created through the catalog endpoint is *managed*: only the
caller that created it may change its permissions, roles, memberships and
agents. Everyone else — including other admins — gets
``403 application_managed_externally``. Platform surfaces (tenant masks,
feature flags, credentials, signing keys, delegation revocation) are not
affected. ``POST /v1/applications/{app}/release-management`` is the
operator's emergency exit, ``…/claim-management`` takes management back.

Every write route on an application's data receives the application (or the
role / agent / membership it writes) through one of the dependencies below,
all of which go through :class:`ManagementGuard`. ``tests/integration/
test_management_guard.py`` fails for a write route that neither uses the guard
nor is listed as exempt.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status

from authz_service.config import Settings, get_settings
from authz_service.dependencies import get_store, require_admin
from authz_service.references import find_application, require_application
from authzkit.agents.models import Agent
from authzkit.rbac.models import Role
from authzkit.security.api_keys import ApiKeyRecord
from authzkit.security.principal import Principal, SessionPrincipal
from authzkit.storage.sqlalchemy import SqlAlchemyStore
from authzkit.tenancy.models import Application, Membership


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


def managed_externally(managed_by: str, status_code: int) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"error": "application_managed_externally", "managed_by": managed_by},
    )


class ManagementGuard:
    """The one check every write to an application's data passes."""

    def __init__(
        self,
        principal: Annotated[Principal, Depends(require_admin)],
        store: Annotated[SqlAlchemyStore, Depends(get_store)],
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> None:
        self.store = store
        self.caller = caller_label(principal, settings)

    def check(self, app: Application) -> Application:
        """Reject writes to a managed application by anyone but its manager."""
        if app.managed_by is not None and app.managed_by != self.caller:
            raise managed_externally(app.managed_by, status.HTTP_403_FORBIDDEN)
        return app

    def application(self, ref: str) -> Application:
        """The application by id or slug (404 if unknown), checked."""
        return self.check(require_application(self.store, ref))

    def application_id(self, application_id: str | None) -> None:
        """Check the application an existing row belongs to (none: platform row)."""
        app = self.store.get_application(application_id) if application_id else None
        if app is not None:
            self.check(app)

    def manager_only(self, ref: str) -> Application:
        """Endpoints that only the manager may call at all (tenant state, role overrides)."""
        app = require_application(self.store, ref)
        if app.managed_by is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "application_not_managed"},
            )
        return self.check(app)


Guard = Annotated[ManagementGuard, Depends()]


def managed_application(application_id: str, guard: Guard) -> Application:
    """Path ``{application_id}``."""
    return guard.application(application_id)


def manager_application(app_slug: str, guard: Guard) -> Application:
    """Path ``{app_slug}``; the application must be managed by the caller."""
    return guard.manager_only(app_slug)


def catalog_application(app_slug: str, guard: Guard) -> Application | None:
    """Path ``{app_slug}``; ``None`` when the catalog call will create it."""
    app = find_application(guard.store, app_slug)
    return guard.check(app) if app is not None else None


def managed_role(role_id: str, guard: Guard) -> Role:
    role = guard.store.get_role(role_id)
    if role is None:
        raise HTTPException(status_code=404, detail={"reason": "role_not_found"})
    guard.application_id(role.application_id)
    return role


def managed_agent(agent_id: str, guard: Guard) -> Agent:
    agent = guard.store.get_agent_by_id(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail={"reason": "agent_not_found"})
    guard.application_id(agent.application_id)
    return agent


def managed_membership(membership_id: str, guard: Guard) -> Membership:
    membership = guard.store.get_membership_by_id(membership_id)
    if membership is None:
        raise HTTPException(status_code=404, detail={"reason": "membership_not_found"})
    guard.application_id(membership.application_id)
    return membership
