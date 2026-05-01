"""Repository protocol for tenancy data access.

Concrete implementations live under :mod:`authzkit.storage`. The protocol
keeps the business logic free of any storage backend coupling.
"""

from __future__ import annotations

from typing import Any, Protocol

from authzkit.tenancy.models import (
    Application,
    ExternalIdentity,
    Membership,
    Tenant,
    TenantIdentityMapping,
    User,
)


class TenancyRepository(Protocol):
    # Tenants
    def get_tenant(self, tenant_id: str) -> Tenant | None: ...
    def get_tenant_by_slug(self, slug: str) -> Tenant | None: ...
    def create_tenant(self, *, slug: str, name: str, status: str = "active") -> Tenant: ...

    # Applications
    def get_application(self, application_id: str) -> Application | None: ...
    def get_application_by_slug(self, slug: str) -> Application | None: ...
    def create_application(
        self, *, slug: str, name: str, status: str = "active"
    ) -> Application: ...

    # Users + External Identities
    def get_user(self, user_id: str) -> User | None: ...
    def find_user_by_external_identity(
        self, provider: str, issuer: str, subject: str
    ) -> User | None: ...
    def upsert_user_from_identity(
        self,
        *,
        provider: str,
        issuer: str,
        subject: str,
        email: str | None,
        external_tenant_id: str | None,
        display_name: str | None = None,
    ) -> tuple[User, ExternalIdentity]: ...

    # Tenant identity mapping
    def find_tenant_by_external(
        self, provider: str, issuer: str, external_tenant_id: str
    ) -> Tenant | None: ...
    def create_tenant_identity_mapping(
        self,
        *,
        tenant_id: str,
        provider: str,
        issuer: str,
        external_tenant_id: str,
    ) -> TenantIdentityMapping: ...

    # Memberships
    def get_membership(
        self, *, tenant_id: str, application_id: str | None, user_id: str
    ) -> Membership | None: ...
    def list_memberships_for_user(self, user_id: str) -> list[Membership]: ...
    def create_membership(
        self,
        *,
        tenant_id: str,
        application_id: str | None,
        user_id: str,
        status: str = "active",
        roles: set[str] | None = None,
    ) -> Membership: ...
    def set_membership_roles(self, membership_id: str, role_names: set[str]) -> None: ...

    # Tenant feature flags
    def get_tenant_feature_flags(
        self, tenant_id: str, application_id: str | None
    ) -> dict[str, Any]: ...
