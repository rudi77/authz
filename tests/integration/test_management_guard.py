"""Z-4: every write route is either guarded by ``managed_by`` or explicitly exempt.

The guard lives in one place (:class:`authz_service.management.ManagementGuard`).
This test enumerates the mounted write routes so a new endpoint cannot skip
the guard silently: it has to be added to one of the two lists below.
"""

from __future__ import annotations

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from tests.integration._managed_env import make_env

# Writes to an application's permissions, roles (incl. tenant overrides),
# memberships, agents and invitations.
APP_SCOPED = {
    ("POST", "/v1/applications/{application_id}/permissions"),
    ("POST", "/v1/applications/{application_id}/roles"),
    ("PUT", "/v1/roles/{role_id}/permissions"),
    ("PUT", "/v1/applications/{app_slug}/catalog"),
    ("PUT", "/v1/applications/{app_slug}/tenants/{tenant_slug}/state"),
    ("PUT", "/v1/applications/{app_slug}/tenants/{tenant_slug}/roles/{name}"),
    ("DELETE", "/v1/applications/{app_slug}/tenants/{tenant_slug}/roles/{name}"),
    ("POST", "/v1/tenants/{tenant_id}/memberships"),
    ("PATCH", "/v1/memberships/{membership_id}"),
    ("POST", "/v1/tenants/{tenant_id}/applications/{application_id}/agents"),
    ("PUT", "/v1/agents/{agent_id}/roles"),
    ("POST", "/v1/tenants/{tenant_id}/invitations"),
}

# Everything else that writes, with the reason it is not guarded.
EXEMPT = {
    ("POST", "/v1/authorize"): "decision",
    ("POST", "/v1/bulk-authorize"): "decision",
    ("POST", "/v1/effective-permissions"): "decision",
    ("POST", "/v1/resolve-context"): "decision (may provision users/tenants, no app data)",
    ("POST", "/v1/tenants"): "platform: tenants",
    ("PATCH", "/v1/tenants/{tenant_id}"): "platform: tenants",
    ("POST", "/v1/tenants/{tenant_id}/mappings"): "platform: tenant identity mapping",
    ("PUT", "/v1/tenants/{tenant_id}/feature-flags"): "platform: feature flags",
    (
        "PUT",
        "/v1/tenants/{tenant_id}/applications/{application_id}/permission-mask",
    ): "platform: tenant masks",
    ("POST", "/v1/applications"): "platform: creates an unmanaged application",
    ("PATCH", "/v1/applications/{application_id}"): "platform: name/status (operator kill switch)",
    ("POST", "/v1/applications/{application_id}/release-management"): "emergency exit",
    ("POST", "/v1/applications/{application_id}/claim-management"): "claims management itself",
    ("POST", "/v1/api-keys"): "platform: credentials",
    ("POST", "/v1/api-keys/{key_id}/rotate"): "platform: credentials",
    ("DELETE", "/v1/api-keys/{key_id}"): "platform: credentials",
    ("POST", "/v1/invitations/{token}/accept"): "invitations to a managed app cannot be created",
    ("DELETE", "/v1/invitations/{invitation_id}"): "revoking only removes access",
    ("POST", "/v1/users"): "platform: users are not application data",
    ("POST", "/v1/delegations"): "runtime: grants",
    ("POST", "/v1/delegations/revoke"): "delegation revocation (operator may always revoke)",
    ("POST", "/v1/delegations/introspect"): "runtime: read-only check",
    ("DELETE", "/v1/delegations/{grant_id}"): "delegation revocation",
    ("POST", "/oauth/token"): "platform: credentials",
    ("POST", "/oauth/logout"): "platform: admin session",
    ("POST", "/v1/oauth/clients"): "platform: credentials",
    ("POST", "/v1/oauth/clients/{client_id}/rotate"): "platform: credentials",
    ("DELETE", "/v1/oauth/clients/{client_id}"): "platform: credentials",
    ("POST", "/v1/oauth/signing-keys/rotate"): "platform: signing keys",
}


def _routes(routes) -> list[APIRoute]:
    out: list[APIRoute] = []
    for r in routes:
        if isinstance(r, APIRoute):
            out.append(r)
        elif hasattr(r, "original_router"):  # FastAPI's included-router wrapper
            out.extend(_routes(r.original_router.routes))
        elif hasattr(r, "routes"):
            out.extend(_routes(r.routes))
    return out


def _calls(dependant: Dependant) -> set:
    calls = {dependant.call}
    for d in dependant.dependencies:
        calls |= _calls(d)
    return calls


@pytest.fixture()
def write_routes(temp_db_url) -> dict[tuple[str, str], APIRoute]:
    env = make_env(temp_db_url, with_catalog=False)
    return {
        (method, r.path): r
        for r in _routes(env.client.app.routes)
        for method in r.methods - {"GET", "HEAD", "OPTIONS"}
    }


def test_every_write_route_is_classified(write_routes):
    unclassified = set(write_routes) - APP_SCOPED - set(EXEMPT)
    assert not unclassified, f"classify as APP_SCOPED (guarded) or EXEMPT: {unclassified}"
    assert set(write_routes) >= APP_SCOPED


def test_app_scoped_writes_pass_the_management_guard(write_routes):
    from authz_service.management import ManagementGuard

    unguarded = sorted(
        key for key in APP_SCOPED if ManagementGuard not in _calls(write_routes[key].dependant)
    )
    assert not unguarded, f"app-scoped write routes without ManagementGuard: {unguarded}"
