"""In-memory storage backend.

Used for unit tests, examples, and the Python SDK's offline mode. Implements
:class:`TenancyRepository`, :class:`RBACRepository` and an agent repository.
"""

from __future__ import annotations

import uuid
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
        self, *, slug: str, name: str, status: str = "active"
    ) -> Application:
        app = Application(id=_new_id(), slug=slug, name=name, status=status)
        self.applications[app.id] = app
        return app

    def get_application(self, application_id: str) -> Application | None:
        return self.applications.get(application_id)

    def get_application_by_slug(self, slug: str) -> Application | None:
        return next((a for a in self.applications.values() if a.slug == slug), None)

    def is_application_active(self, application_id: str) -> bool:
        a = self.applications.get(application_id)
        return a is not None and a.status == "active"

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
        if roles:
            role_ids = {self._role_id_by_name(application_id, name) for name in roles}
            role_ids.discard(None)
            self.membership_roles[membership.id] = {r for r in role_ids if r}
        else:
            self.membership_roles[membership.id] = set()
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
        role_ids: set[str] = set()
        for name in role_names:
            rid = self._role_id_by_name(membership.application_id, name)
            if rid is not None:
                role_ids.add(rid)
        self.membership_roles[membership_id] = role_ids
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

    def _role_id_by_name(self, application_id: str | None, name: str) -> str | None:
        for r in self.roles.values():
            if r.name == name and r.application_id == application_id:
                return r.id
        return None

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

    def list_application_permissions(self, application_id: str) -> list[Permission]:
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
        membership = self.get_membership(
            tenant_id=tenant_id, application_id=application_id, user_id=user_id
        )
        if membership is None:
            membership = self.get_membership(
                tenant_id=tenant_id, application_id=None, user_id=user_id
            )
        if membership is None:
            return set()
        permissions: set[str] = set()
        for role_id in self.membership_roles.get(membership.id, set()):
            for p in self.list_role_permissions(role_id):
                permissions.add(p.name)
        return permissions

    def resolve_agent_permissions(
        self, *, tenant_id: str, application_id: str, agent_id: str
    ) -> set[str]:
        agent = self.agents.get(agent_id)
        if agent is None or agent.tenant_id != tenant_id or agent.application_id != application_id:
            return set()
        permissions: set[str] = set()
        for role_id in self.agent_roles.get(agent_id, set()):
            for p in self.list_role_permissions(role_id):
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
    ) -> Agent:
        agent = Agent(
            id=_new_id(),
            tenant_id=tenant_id,
            application_id=application_id,
            name=name,
            role=role,
            status=status,
            created_by_user_id=created_by_user_id,
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

    def is_agent_active(
        self, *, tenant_id: str, application_id: str, agent_id: str
    ) -> bool:
        agent = self.get_agent(
            tenant_id=tenant_id, application_id=application_id, agent_id=agent_id
        )
        return agent is not None and agent.status == "active"

    def set_agent_roles(self, agent_id: str, role_names: set[str]) -> None:
        agent = self.agents[agent_id]
        role_ids: set[str] = set()
        for name in role_names:
            rid = self._role_id_by_name(agent.application_id, name)
            if rid is not None:
                role_ids.add(rid)
        self.agent_roles[agent_id] = role_ids
