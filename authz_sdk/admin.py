"""Admin-side SDK for the AuthZ service.

Mirrors the management endpoints in :mod:`authz_service.api`. Kept separate
from :class:`AuthzClient` because the runtime path (PEP) and the
provisioning path (admin tooling) have very different latency / auth /
caching profiles.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from authz_sdk.client import AuthzClientError, AuthzServiceError


@dataclass(frozen=True)
class Tenant:
    id: str
    slug: str
    name: str
    status: str


@dataclass(frozen=True)
class Application:
    id: str
    slug: str
    name: str
    status: str


@dataclass(frozen=True)
class Role:
    id: str
    name: str
    scope: str
    application_id: str | None
    tenant_id: str | None
    description: str | None
    is_system: bool


@dataclass(frozen=True)
class Permission:
    id: str
    name: str
    resource: str
    action: str
    application_id: str | None
    description: str | None


@dataclass(frozen=True)
class Membership:
    id: str
    tenant_id: str
    application_id: str | None
    user_id: str
    roles: list[str]
    status: str


@dataclass(frozen=True)
class Agent:
    id: str
    tenant_id: str
    application_id: str
    name: str
    role: str
    status: str


@dataclass(frozen=True)
class ApiKey:
    """API key as returned by the management API.

    ``key`` is the plaintext — only set on the response from issue/rotate.
    Listing returns it as None because the service can't recover it.
    """

    id: str
    name: str
    key_prefix: str
    scopes: list[str]
    tenant_id: str | None
    status: str
    expires_at: str | None
    last_used_at: str | None
    rotates: str | None
    key: str | None = None


@dataclass(frozen=True)
class Invitation:
    id: str
    tenant_id: str
    application_id: str | None
    email: str
    roles: list[str]
    status: str
    expires_at: str
    accepted_at: str | None
    token: str | None = None


class AuthzAdminClient:
    """Sync admin client. Threadsafe via httpx Client semantics."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        timeout: float = 10.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        if not base_url.endswith("/"):
            base_url = base_url + "/"
        if http_client is not None:
            self._http = http_client
            self._owns_http = False
            if api_key:
                self._http.headers["X-API-Key"] = api_key
        else:
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            if api_key:
                headers["X-API-Key"] = api_key
            self._http = httpx.Client(base_url=base_url, timeout=timeout, headers=headers)
            self._owns_http = True

    def __enter__(self) -> AuthzAdminClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    # ---- HTTP helpers --------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self._http.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            raise AuthzClientError(f"transport error: {e}") from e
        if response.status_code == 204:
            return None
        if response.status_code >= 400:
            try:
                detail = response.json()
            except Exception:
                detail = response.text
            raise AuthzServiceError(response.status_code, detail)
        return response.json()

    # ---- Tenants -------------------------------------------------------------

    def create_tenant(self, *, slug: str, name: str, status: str = "active") -> Tenant:
        data = self._request(
            "POST", "v1/tenants", json={"slug": slug, "name": name, "status": status}
        )
        return Tenant(**data)

    def get_tenant(self, tenant_id_or_slug: str) -> Tenant:
        data = self._request("GET", f"v1/tenants/{tenant_id_or_slug}")
        return Tenant(**data)

    def map_tenant_external(
        self, tenant_id: str, *, provider: str, issuer: str, external_tenant_id: str
    ) -> dict:
        return self._request(
            "POST",
            f"v1/tenants/{tenant_id}/mappings",
            json={
                "provider": provider,
                "issuer": issuer,
                "external_tenant_id": external_tenant_id,
            },
        )

    def set_feature_flag(
        self, tenant_id: str, *, key: str, value: Any, application_id: str | None = None
    ) -> dict:
        return self._request(
            "PUT",
            f"v1/tenants/{tenant_id}/feature-flags",
            json={"application_id": application_id, "key": key, "value": value},
        )

    # ---- Applications --------------------------------------------------------

    def create_application(
        self, *, slug: str, name: str, status: str = "active"
    ) -> Application:
        data = self._request(
            "POST",
            "v1/applications",
            json={"slug": slug, "name": name, "status": status},
        )
        return Application(**data)

    def get_application(self, application_id_or_slug: str) -> Application:
        data = self._request("GET", f"v1/applications/{application_id_or_slug}")
        return Application(**data)

    # ---- Roles + Permissions -------------------------------------------------

    def create_role(
        self,
        application_id: str,
        *,
        name: str,
        scope: str = "application",
        description: str | None = None,
        tenant_id: str | None = None,
    ) -> Role:
        data = self._request(
            "POST",
            f"v1/applications/{application_id}/roles",
            json={
                "name": name,
                "scope": scope,
                "description": description,
                "tenant_id": tenant_id,
            },
        )
        return Role(**data)

    def list_roles(self, application_id: str) -> list[Role]:
        rows = self._request("GET", f"v1/applications/{application_id}/roles")
        return [Role(**r) for r in rows]

    def create_permission(
        self,
        application_id: str,
        *,
        name: str,
        description: str | None = None,
    ) -> Permission:
        data = self._request(
            "POST",
            f"v1/applications/{application_id}/permissions",
            json={"name": name, "description": description},
        )
        return Permission(**data)

    def list_permissions(self, application_id: str) -> list[Permission]:
        rows = self._request("GET", f"v1/applications/{application_id}/permissions")
        return [Permission(**r) for r in rows]

    def set_role_permissions(self, role_id: str, permissions: list[str]) -> dict:
        return self._request(
            "PUT", f"v1/roles/{role_id}/permissions", json={"permissions": permissions}
        )

    def get_role_permissions(self, role_id: str) -> list[str]:
        data = self._request("GET", f"v1/roles/{role_id}/permissions")
        return list(data.get("permissions") or [])

    # ---- Memberships ---------------------------------------------------------

    def create_membership(
        self,
        tenant_id: str,
        *,
        user_id: str,
        application_id: str | None = None,
        roles: list[str] | None = None,
        status: str = "active",
    ) -> Membership:
        data = self._request(
            "POST",
            f"v1/tenants/{tenant_id}/memberships",
            json={
                "user_id": user_id,
                "application_id": application_id,
                "roles": roles or [],
                "status": status,
            },
        )
        return Membership(**data)

    def list_memberships(
        self,
        tenant_id: str,
        *,
        page: int = 1,
        page_size: int = 50,
    ) -> list[Membership]:
        rows = self._request(
            "GET",
            f"v1/tenants/{tenant_id}/memberships",
            params={"page": page, "page_size": page_size},
        )
        return [Membership(**r) for r in rows]

    def update_membership(
        self,
        membership_id: str,
        *,
        roles: list[str] | None = None,
        status: str | None = None,
    ) -> Membership:
        body: dict[str, Any] = {}
        if roles is not None:
            body["roles"] = roles
        if status is not None:
            body["status"] = status
        data = self._request("PATCH", f"v1/memberships/{membership_id}", json=body)
        return Membership(**data)

    # ---- Agents --------------------------------------------------------------

    def create_agent(
        self,
        tenant_id: str,
        application_id: str,
        *,
        name: str,
        role: str = "",
        status: str = "active",
        created_by_user_id: str | None = None,
    ) -> Agent:
        data = self._request(
            "POST",
            f"v1/tenants/{tenant_id}/applications/{application_id}/agents",
            json={
                "name": name,
                "role": role,
                "status": status,
                "created_by_user_id": created_by_user_id,
            },
        )
        return Agent(**data)

    def list_agents(self, tenant_id: str, application_id: str) -> list[Agent]:
        rows = self._request(
            "GET", f"v1/tenants/{tenant_id}/applications/{application_id}/agents"
        )
        return [Agent(**r) for r in rows]

    def set_agent_roles(self, agent_id: str, roles: list[str]) -> dict:
        return self._request(
            "PUT", f"v1/agents/{agent_id}/roles", json={"roles": roles}
        )

    # ---- API Keys ------------------------------------------------------------

    def issue_api_key(
        self,
        *,
        name: str,
        scopes: list[str],
        tenant_id: str | None = None,
    ) -> ApiKey:
        data = self._request(
            "POST",
            "v1/api-keys",
            json={"name": name, "scopes": scopes, "tenant_id": tenant_id},
        )
        return ApiKey(**data)

    def list_api_keys(self) -> list[ApiKey]:
        rows = self._request("GET", "v1/api-keys")
        return [ApiKey(**r) for r in rows]

    def rotate_api_key(self, key_id: str) -> ApiKey:
        data = self._request("POST", f"v1/api-keys/{key_id}/rotate")
        return ApiKey(**data)

    def revoke_api_key(self, key_id: str) -> None:
        self._request("DELETE", f"v1/api-keys/{key_id}")

    # ---- Invitations ---------------------------------------------------------

    def create_invitation(
        self,
        tenant_id: str,
        *,
        email: str,
        application_id: str | None = None,
        roles: list[str] | None = None,
        ttl_days: int = 7,
    ) -> Invitation:
        data = self._request(
            "POST",
            f"v1/tenants/{tenant_id}/invitations",
            json={
                "email": email,
                "application_id": application_id,
                "roles": roles or [],
                "ttl_days": ttl_days,
            },
        )
        return Invitation(**data)

    def list_invitations(self, tenant_id: str) -> list[Invitation]:
        rows = self._request("GET", f"v1/tenants/{tenant_id}/invitations")
        return [Invitation(**r) for r in rows]

    def revoke_invitation(self, invitation_id: str) -> None:
        self._request("DELETE", f"v1/invitations/{invitation_id}")

    def accept_invitation(
        self,
        token: str,
        *,
        provider: str,
        issuer: str,
        subject: str,
        email: str | None = None,
        external_tenant_id: str | None = None,
        claims: dict[str, Any] | None = None,
    ) -> Invitation:
        data = self._request(
            "POST",
            f"v1/invitations/{token}/accept",
            json={
                "provider": provider,
                "issuer": issuer,
                "subject": subject,
                "email": email,
                "external_tenant_id": external_tenant_id,
                "claims": claims or {},
            },
        )
        return Invitation(**data)

    # ---- Convenience: bootstrap a (role, permissions) tuple in one call ------

    def upsert_role_with_permissions(
        self,
        application_id: str,
        *,
        name: str,
        permissions: list[str],
        scope: str = "application",
        description: str | None = None,
    ) -> Role:
        """Create a role if missing, then PUT its permission set.

        Idempotent: existing roles are reused, permissions are replaced.
        """
        existing = next(
            (r for r in self.list_roles(application_id) if r.name == name), None
        )
        if existing is None:
            role = self.create_role(
                application_id,
                name=name,
                scope=scope,
                description=description,
            )
        else:
            role = existing
        self.set_role_permissions(role.id, permissions)
        return role
