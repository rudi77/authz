"""In-memory storage backend.

Used for unit tests, examples, and the Python SDK's offline mode. Implements
:class:`TenancyRepository`, :class:`RBACRepository` and an agent repository.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from authzkit.agents.models import Agent
from authzkit.rbac.models import Permission, Role, RoleScope
from authzkit.tenancy.models import (
    MEMBERSHIP_STATUS_ACTIVE,
    Application,
    ExternalIdentity,
    Membership,
    Tenant,
    TenantIdentityMapping,
    User,
)


def _new_id() -> str:
    return str(uuid.uuid4())


class InMemoryStore:
    """Single-process store implementing all required repository protocols."""

    def __init__(self) -> None:
        self.tenants: dict[str, Tenant] = {}
        self.applications: dict[str, Application] = {}
        self.users: dict[str, User] = {}
        self.external_identities: dict[str, ExternalIdentity] = {}
        self.tenant_identity_mappings: dict[str, TenantIdentityMapping] = {}
        self.memberships: dict[str, Membership] = {}
        self.roles: dict[str, Role] = {}
        self.permissions: dict[str, Permission] = {}
        self.role_permissions: dict[str, set[str]] = {}  # role_id -> {permission_id}
        self.membership_roles: dict[str, set[str]] = {}  # membership_id -> {role_id}
        self.agents: dict[str, Agent] = {}
        self.agent_roles: dict[str, set[str]] = {}  # agent_id -> {role_id}
        self.tenant_feature_flags: dict[tuple[str, str | None], dict[str, Any]] = {}
        self.tenant_permission_masks: dict[tuple[str, str], set[str]] = {}

    # ---- Tenants -------------------------------------------------------------

    def create_tenant(self, *, slug: str, name: str, status: str = "active") -> Tenant:
        tenant = Tenant(id=_new_id(), slug=slug, name=name, status=status)
        self.tenants[tenant.id] = tenant
        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        return self.tenants.get(tenant_id)

    def get_tenant_by_slug(self, slug: str) -> Tenant | None:
        return next((t for t in self.tenants.values() if t.slug == slug), None)

    def is_tenant_active(self, tenant_id: str) -> bool:
        t = self.tenants.get(tenant_id)
        return t is not None and t.status == "active"

    # ---- Applications --------------------------------------------------------

    def create_application(
        self, *, slug: str, name: str, status: str = "active", managed_by: str | None = None
    ) -> Application:
        app = Application(
            id=_new_id(), slug=slug, name=name, status=status, managed_by=managed_by
        )
        self.applications[app.id] = app
        return app

    def get_application(self, application_id: str) -> Application | None:
        return self.applications.get(application_id)

    def get_application_by_slug(self, slug: str) -> Application | None:
        return next((a for a in self.applications.values() if a.slug == slug), None)

    def is_application_active(self, application_id: str) -> bool:
        a = self.applications.get(application_id)
        return a is not None and a.status == "active"

    def set_application_managed_by(self, application_id: str, managed_by: str | None) -> None:
        app = self.applications.get(application_id)
        if app is not None:
            self.applications[application_id] = replace(app, managed_by=managed_by)

    # ---- Users + identities --------------------------------------------------

    def get_user(self, user_id: str) -> User | None:
        return self.users.get(user_id)

    def find_user_by_external_identity(
        self, provider: str, issuer: str, subject: str
    ) -> User | None:
        for ident in self.external_identities.values():
            if (
                ident.provider == provider
                and ident.issuer == issuer
                and ident.subject == subject
            ):
                return self.users.get(ident.user_id)
        return None

    def upsert_user_from_identity(
        self,
        *,
        provider: str,
        issuer: str,
        subject: str,
        email: str | None,
        external_tenant_id: str | None,
        display_name: str | None = None,
    ) -> tuple[User, ExternalIdentity]:
        existing = self.find_user_by_external_identity(provider, issuer, subject)
        if existing is not None:
            ident = next(
                i
                for i in self.external_identities.values()
                if i.provider == provider and i.issuer == issuer and i.subject == subject
            )
            return existing, ident
        user = User(id=_new_id(), display_name=display_name, email=email, status="active")
        self.users[user.id] = user
        ident = ExternalIdentity(
            id=_new_id(),
            user_id=user.id,
            provider=provider,
            issuer=issuer,
            subject=subject,
            external_tenant_id=external_tenant_id,
            email=email,
        )
        self.external_identities[ident.id] = ident
        return user, ident

    # ---- Tenant identity mapping --------------------------------------------

    def find_tenant_by_external(
        self, provider: str, issuer: str, external_tenant_id: str
    ) -> Tenant | None:
        for m in self.tenant_identity_mappings.values():
            if (
                m.provider == provider
                and m.issuer == issuer
                and m.external_tenant_id == external_tenant_id
            ):
                return self.tenants.get(m.tenant_id)
        return None

    def create_tenant_identity_mapping(
        self,
        *,
        tenant_id: str,
        provider: str,
        issuer: str,
        external_tenant_id: str,
    ) -> TenantIdentityMapping:
        m = TenantIdentityMapping(
            id=_new_id(),
            tenant_id=tenant_id,
            provider=provider,
            issuer=issuer,
            external_tenant_id=external_tenant_id,
        )
        self.tenant_identity_mappings[m.id] = m
        return m

    # ---- Memberships ---------------------------------------------------------

    def create_membership(
        self,
        *,
        tenant_id: str,
        application_id: str | None,
        user_id: str,
        status: str = MEMBERSHIP_STATUS_ACTIVE,
        roles: set[str] | None = None,
    ) -> Membership:
        membership = Membership(
            id=_new_id(),
            tenant_id=tenant_id,
            application_id=application_id,
            user_id=user_id,
            status=status,
            roles=frozenset(roles or set()),
        )
        self.memberships[membership.id] = membership
        self.membership_roles[membership.id] = {
            r.id
            for r in self.find_assignable_roles(
                tenant_id=tenant_id, application_id=application_id, names=roles or set()
            ).values()
        }
        return membership

    def get_membership(
        self, *, tenant_id: str, application_id: str | None, user_id: str
    ) -> Membership | None:
        for m in self.memberships.values():
            if (
                m.tenant_id == tenant_id
                and m.application_id == application_id
                and m.user_id == user_id
            ):
                return m
        return None

    def list_memberships_for_user(self, user_id: str) -> list[Membership]:
        return [m for m in self.memberships.values() if m.user_id == user_id]

    def set_membership_roles(self, membership_id: str, role_names: set[str]) -> None:
        membership = self.memberships[membership_id]
        self.membership_roles[membership_id] = {
            r.id
            for r in self.find_assignable_roles(
                tenant_id=membership.tenant_id,
                application_id=membership.application_id,
                names=role_names,
            ).values()
        }
        self.memberships[membership_id] = replace(membership, roles=frozenset(role_names))

    def is_user_membership_active(
        self, *, tenant_id: str, application_id: str, user_id: str
    ) -> bool:
        m = self.get_membership(
            tenant_id=tenant_id, application_id=application_id, user_id=user_id
        )
        if m is None:
            m = self.get_membership(tenant_id=tenant_id, application_id=None, user_id=user_id)
        return m is not None and m.status == MEMBERSHIP_STATUS_ACTIVE

    # ---- Roles + Permissions -------------------------------------------------

    def create_role(
        self,
        *,
        name: str,
        scope: RoleScope,
        application_id: str | None = None,
        tenant_id: str | None = None,
        description: str | None = None,
    ) -> Role:
        role = Role(
            id=_new_id(),
            name=name,
            scope=scope,
            application_id=application_id,
            tenant_id=tenant_id,
            description=description,
        )
        self.roles[role.id] = role
        self.role_permissions.setdefault(role.id, set())
        return role

    def get_role(self, role_id: str) -> Role | None:
        return self.roles.get(role_id)

    def get_role_by_name(
        self, *, application_id: str | None, tenant_id: str | None, name: str
    ) -> Role | None:
        for r in self.roles.values():
            if (
                r.name == name
                and r.application_id == application_id
                and r.tenant_id == tenant_id
            ):
                return r
        return None

    def find_assignable_roles(
        self, *, tenant_id: str, application_id: str | None, names: Iterable[str]
    ) -> dict[str, Role]:
        """Resolve role names tenant-first: this tenant's role, else the
        application-wide one, never a role bound to another tenant.

        Internal per-agent roles are not assignable by name.
        """
        wanted = set(names)
        found: dict[str, Role] = {}
        for r in self.roles.values():
            if (
                r.name in wanted
                and r.application_id == application_id
                and r.agent_id is None
                and r.tenant_id in (None, tenant_id)
                and (r.tenant_id is not None or r.name not in found)
            ):
                found[r.name] = r
        return found

    def _effective_role_ids(self, tenant_id: str, role_ids: set[str]) -> set[str]:
        """A tenant role named like a linked application-wide role overrides
        it; links to another tenant's role grant nothing."""
        effective: set[str] = set()
        for rid in role_ids:
            role = self.roles.get(rid)
            if role is None or role.tenant_id not in (None, tenant_id):
                continue
            if role.tenant_id is None and role.agent_id is None:
                override = next(
                    (
                        o
                        for o in self.roles.values()
                        if o.tenant_id == tenant_id
                        and o.agent_id is None
                        and o.application_id == role.application_id
                        and o.name == role.name
                    ),
                    None,
                )
                if override is not None:
                    role = override
            effective.add(role.id)
        return effective

    def create_permission(
        self,
        *,
        name: str,
        application_id: str | None = None,
        description: str | None = None,
    ) -> Permission:
        permission = Permission.from_name(name, application_id=application_id)
        self.permissions[permission.id] = permission
        return permission

    def list_application_permissions(self, application_id: str | None) -> list[Permission]:
        return [p for p in self.permissions.values() if p.application_id == application_id]

    def list_role_permissions(self, role_id: str) -> list[Permission]:
        ids = self.role_permissions.get(role_id, set())
        return [p for pid, p in self.permissions.items() if pid in ids]

    def set_role_permissions(self, role_id: str, permission_names: set[str]) -> None:
        permission_ids = {
            p.id for p in self.permissions.values() if p.name in permission_names
        }
        self.role_permissions[role_id] = permission_ids

    # ---- Aggregated permission resolution -----------------------------------

    def resolve_user_permissions(
        self, *, tenant_id: str, application_id: str, user_id: str
    ) -> set[str]:
        # Union of (app-scoped for this app) ∪ (tenant-wide) memberships.
        # Memberships in other apps must not contribute — that would cross
        # application isolation. Permissions from each membership are also
        # filtered to those scoped to this app or unscoped platform perms.
        candidates = [
            m
            for m in self.memberships.values()
            if m.tenant_id == tenant_id
            and m.user_id == user_id
            and m.status == MEMBERSHIP_STATUS_ACTIVE
            and (m.application_id == application_id or m.application_id is None)
        ]
        permissions: set[str] = set()
        for m in candidates:
            linked = self.membership_roles.get(m.id, set())
            for role_id in self._effective_role_ids(tenant_id, linked):
                for p in self.list_role_permissions(role_id):
                    if p.application_id in (application_id, None) and not p.deprecated:
                        permissions.add(p.name)
        return permissions

    def resolve_agent_permissions(
        self, *, tenant_id: str, application_id: str, agent_id: str
    ) -> set[str]:
        agent = self.agents.get(agent_id)
        if agent is None or agent.tenant_id != tenant_id or agent.application_id != application_id:
            return set()
        permissions: set[str] = set()
        for role_id in self._effective_role_ids(tenant_id, self.agent_roles.get(agent_id, set())):
            for p in self.list_role_permissions(role_id):
                if not p.deprecated:
                    permissions.add(p.name)
        return permissions

    def resolve_tenant_permissions(
        self, *, tenant_id: str, application_id: str
    ) -> set[str]:
        return set(self.tenant_permission_masks.get((tenant_id, application_id), set()))

    def set_tenant_permission_mask(
        self, *, tenant_id: str, application_id: str, permissions: set[str]
    ) -> None:
        self.tenant_permission_masks[(tenant_id, application_id)] = set(permissions)

    def get_tenant_feature_flags(
        self, tenant_id: str, application_id: str | None
    ) -> dict[str, Any]:
        return dict(self.tenant_feature_flags.get((tenant_id, application_id), {}))

    def set_tenant_feature_flag(
        self, tenant_id: str, application_id: str | None, key: str, value: Any
    ) -> None:
        bucket = self.tenant_feature_flags.setdefault((tenant_id, application_id), {})
        bucket[key] = value

    # ---- Agents --------------------------------------------------------------

    def create_agent(
        self,
        *,
        tenant_id: str,
        application_id: str,
        name: str,
        role: str = "",
        status: str = "active",
        created_by_user_id: str | None = None,
        display_name: str | None = None,
    ) -> Agent:
        agent = Agent(
            id=_new_id(),
            tenant_id=tenant_id,
            application_id=application_id,
            name=name,
            role=role,
            status=status,
            created_by_user_id=created_by_user_id,
            display_name=display_name,
        )
        self.agents[agent.id] = agent
        self.agent_roles.setdefault(agent.id, set())
        return agent

    def get_agent(
        self, *, tenant_id: str, application_id: str, agent_id: str
    ) -> Agent | None:
        agent = self.agents.get(agent_id)
        if agent is None:
            return None
        if agent.tenant_id != tenant_id or agent.application_id != application_id:
            return None
        return agent

    def get_agent_by_id(self, agent_id: str) -> Agent | None:
        return self.agents.get(agent_id)

    def find_agent_by_name(
        self, *, tenant_id: str, application_id: str, name: str
    ) -> Agent | None:
        return next(
            (
                a
                for a in self.agents.values()
                if a.tenant_id == tenant_id
                and a.application_id == application_id
                and a.name == name
            ),
            None,
        )

    def is_agent_active(
        self, *, tenant_id: str, application_id: str, agent_id: str
    ) -> bool:
        agent = self.get_agent(
            tenant_id=tenant_id, application_id=application_id, agent_id=agent_id
        )
        return agent is not None and agent.status == "active"

    def set_agent_roles(self, agent_id: str, role_names: set[str]) -> None:
        agent = self.agents[agent_id]
        self.agent_roles[agent_id] = {
            r.id
            for r in self.find_assignable_roles(
                tenant_id=agent.tenant_id, application_id=agent.application_id, names=role_names
            ).values()
        }
