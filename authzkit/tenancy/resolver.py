"""Resolves an IdentityPrincipal into an internal UserContext."""

from __future__ import annotations

from dataclasses import dataclass, field

from authzkit.exceptions import (
    InvalidRequestError,
    NoActiveMembershipError,
    TenantNotActiveError,
)
from authzkit.identity.base import IdentityPrincipal
from authzkit.rbac.resolver import PermissionResolver
from authzkit.tenancy.models import (
    MEMBERSHIP_STATUS_ACTIVE,
    TENANT_STATUS_ACTIVE,
    Membership,
    Tenant,
    User,
)
from authzkit.tenancy.repository import TenancyRepository


@dataclass(frozen=True)
class UserContext:
    """The result of resolving a principal against tenant + application."""

    tenant_id: str
    application_id: str
    user_id: str
    roles: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[str] = field(default_factory=frozenset)


class TenantContextResolver:
    """Maps a normalized IdentityPrincipal to a UserContext.

    Resolution order:
      1. Find or create the internal user from the external identity.
      2. Resolve the tenant — first via explicit application slug + membership,
         then via external tenant id mapping.
      3. Load the membership that scopes the user to the tenant + application.
      4. Resolve the membership's roles into permissions.

    Setting ``allow_auto_provision_user=True`` lets the resolver create the
    user record on first sight; auto-provisioning a tenant requires
    ``allow_auto_provision_tenant=True`` because that's a business decision.
    """

    def __init__(
        self,
        repository: TenancyRepository,
        permission_resolver: PermissionResolver,
        *,
        allow_auto_provision_user: bool = True,
        allow_auto_provision_tenant: bool = False,
    ) -> None:
        self.repository = repository
        self.permission_resolver = permission_resolver
        self.allow_auto_provision_user = allow_auto_provision_user
        self.allow_auto_provision_tenant = allow_auto_provision_tenant

    def resolve(
        self,
        principal: IdentityPrincipal,
        *,
        application_slug: str,
        explicit_tenant_id: str | None = None,
    ) -> UserContext:
        application = self.repository.get_application_by_slug(application_slug)
        if application is None:
            raise InvalidRequestError(f"unknown application: {application_slug}")

        user = self._resolve_user(principal)
        tenant = self._resolve_tenant(principal, explicit_tenant_id)
        if tenant.status != TENANT_STATUS_ACTIVE:
            raise TenantNotActiveError(tenant.id)

        membership = self.repository.get_membership(
            tenant_id=tenant.id,
            application_id=application.id,
            user_id=user.id,
        )
        if membership is None:
            # Fall back to a tenant-wide membership when the application-scoped
            # one is absent. Application-scoped wins when both exist.
            membership = self.repository.get_membership(
                tenant_id=tenant.id, application_id=None, user_id=user.id
            )
        if membership is None or membership.status != MEMBERSHIP_STATUS_ACTIVE:
            raise NoActiveMembershipError(
                f"user {user.id} has no active membership in tenant {tenant.id}"
            )

        permissions = self.permission_resolver.resolve_membership_permissions(membership)
        return UserContext(
            tenant_id=tenant.id,
            application_id=application.id,
            user_id=user.id,
            roles=frozenset(membership.roles),
            permissions=frozenset(permissions),
        )

    def _resolve_user(self, principal: IdentityPrincipal) -> User:
        existing = self.repository.find_user_by_external_identity(
            provider=principal.provider,
            issuer=principal.issuer,
            subject=principal.subject,
        )
        if existing is not None:
            return existing
        if not self.allow_auto_provision_user:
            raise NoActiveMembershipError("user not provisioned")
        user, _ = self.repository.upsert_user_from_identity(
            provider=principal.provider,
            issuer=principal.issuer,
            subject=principal.subject,
            email=principal.email,
            external_tenant_id=principal.external_tenant_id,
        )
        return user

    def _resolve_tenant(
        self, principal: IdentityPrincipal, explicit_tenant_id: str | None
    ) -> Tenant:
        if explicit_tenant_id:
            tenant = self.repository.get_tenant(explicit_tenant_id)
            if tenant is None:
                raise InvalidRequestError(f"unknown tenant: {explicit_tenant_id}")
            return tenant
        if principal.external_tenant_id:
            tenant = self.repository.find_tenant_by_external(
                provider=principal.provider,
                issuer=principal.issuer,
                external_tenant_id=principal.external_tenant_id,
            )
            if tenant is not None:
                return tenant
        # Use a single existing membership when there's no ambiguity.
        user = self.repository.find_user_by_external_identity(
            principal.provider, principal.issuer, principal.subject
        )
        if user is not None:
            memberships: list[Membership] = self.repository.list_memberships_for_user(user.id)
            active = [m for m in memberships if m.status == MEMBERSHIP_STATUS_ACTIVE]
            unique_tenants = {m.tenant_id for m in active}
            if len(unique_tenants) == 1:
                tenant_id = next(iter(unique_tenants))
                tenant = self.repository.get_tenant(tenant_id)
                if tenant is not None:
                    return tenant
        raise NoActiveMembershipError("could not resolve tenant for principal")
