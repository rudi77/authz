"""SQLAlchemy-backed implementation of all repository protocols."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import Engine, create_engine, delete, or_, select
from sqlalchemy.orm import Session, sessionmaker

from authzkit.agents.models import AGENT_STATUS_DISABLED
from authzkit.agents.models import Agent as AgentModel
from authzkit.audit.logger import AuditEntry
from authzkit.provisioning import (
    DESIRED_STATUSES,
    CatalogPermission,
    CatalogResult,
    CatalogRole,
    DesiredAgent,
    DesiredMember,
    ProvisioningError,
    ProvisioningIssue,
    TenantRoleView,
    TenantState,
    TenantStateResult,
    UserRef,
    agent_role_name,
)
from authzkit.rbac.models import Permission as PermissionModel
from authzkit.rbac.models import Role as RoleModel
from authzkit.rbac.models import RoleScope
from authzkit.storage import orm
from authzkit.tenancy.models import (
    MEMBERSHIP_STATUS_ACTIVE,
    MEMBERSHIP_STATUS_DISABLED,
    TENANT_STATUSES,
)
from authzkit.tenancy.models import (
    Application as ApplicationModel,
)
from authzkit.tenancy.models import (
    ExternalIdentity as ExternalIdentityModel,
)
from authzkit.tenancy.models import (
    Membership as MembershipModel,
)
from authzkit.tenancy.models import (
    Tenant as TenantModel,
)
from authzkit.tenancy.models import (
    TenantIdentityMapping as TenantIdentityMappingModel,
)
from authzkit.tenancy.models import (
    User as UserModel,
)


def create_engine_from_url(url: str, *, echo: bool = False) -> Engine:
    """Create a SQLAlchemy engine. SQLite gets sane defaults for tests."""
    if url.startswith("sqlite"):
        return create_engine(
            url,
            echo=echo,
            connect_args={"check_same_thread": False},
        )
    return create_engine(url, echo=echo, pool_pre_ping=True)


def init_schema(engine: Engine) -> None:
    """Create all tables (use Alembic migrations in production)."""
    orm.Base.metadata.create_all(engine)


class SqlAlchemyStore:
    """SQLAlchemy implementation of TenancyRepository + RBACRepository.

    A single store instance is safe to reuse across requests; each public
    method opens a short-lived session via the configured sessionmaker.
    """

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._SessionMaker = sessionmaker(bind=engine, expire_on_commit=False)

    def session(self) -> Session:
        return self._SessionMaker()

    # ---- helpers -------------------------------------------------------------

    @staticmethod
    def _to_tenant(row: orm.Tenant) -> TenantModel:
        return TenantModel(id=row.id, slug=row.slug, name=row.name, status=row.status)

    @staticmethod
    def _to_application(row: orm.Application) -> ApplicationModel:
        return ApplicationModel(
            id=row.id,
            slug=row.slug,
            name=row.name,
            status=row.status,
            managed_by=row.managed_by,
        )

    @staticmethod
    def _to_user(row: orm.User) -> UserModel:
        return UserModel(
            id=row.id,
            display_name=row.display_name,
            email=row.email,
            status=row.status,
        )

    @staticmethod
    def _to_external_identity(row: orm.ExternalIdentity) -> ExternalIdentityModel:
        return ExternalIdentityModel(
            id=row.id,
            user_id=row.user_id,
            provider=row.provider,
            issuer=row.issuer,
            subject=row.subject,
            external_tenant_id=row.external_tenant_id,
            email=row.email,
        )

    @staticmethod
    def _to_membership(row: orm.Membership, role_names: Iterable[str]) -> MembershipModel:
        return MembershipModel(
            id=row.id,
            tenant_id=row.tenant_id,
            application_id=row.application_id,
            user_id=row.user_id,
            status=row.status,
            roles=frozenset(role_names),
        )

    @staticmethod
    def _to_role(row: orm.Role) -> RoleModel:
        return RoleModel(
            id=row.id,
            name=row.name,
            scope=RoleScope(row.scope),
            tenant_id=row.tenant_id,
            application_id=row.application_id,
            description=row.description,
            is_system=row.is_system,
            agent_id=row.agent_id,
        )

    @staticmethod
    def _to_permission(row: orm.Permission) -> PermissionModel:
        return PermissionModel(
            id=row.id,
            name=row.name,
            resource=row.resource,
            action=row.action,
            application_id=row.application_id,
            description=row.description,
            deprecated=row.deprecated,
            critical=row.critical,
        )

    @staticmethod
    def _to_agent(row: orm.Agent) -> AgentModel:
        return AgentModel(
            id=row.id,
            tenant_id=row.tenant_id,
            application_id=row.application_id,
            name=row.name,
            role=row.role_label,
            status=row.status,
            created_by_user_id=row.created_by_user_id,
            display_name=row.display_name,
        )

    # ---- Tenants -------------------------------------------------------------

    def create_tenant(self, *, slug: str, name: str, status: str = "active") -> TenantModel:
        with self.session() as s:
            row = orm.Tenant(id=str(uuid.uuid4()), slug=slug, name=name, status=status)
            s.add(row)
            s.commit()
            return self._to_tenant(row)

    def get_tenant(self, tenant_id: str) -> TenantModel | None:
        with self.session() as s:
            row = s.get(orm.Tenant, tenant_id)
            return self._to_tenant(row) if row else None

    def get_tenant_by_slug(self, slug: str) -> TenantModel | None:
        with self.session() as s:
            row = s.scalar(select(orm.Tenant).where(orm.Tenant.slug == slug))
            return self._to_tenant(row) if row else None

    def is_tenant_active(self, tenant_id: str) -> bool:
        with self.session() as s:
            row = s.get(orm.Tenant, tenant_id)
            return row is not None and row.status == "active"

    # ---- Applications --------------------------------------------------------

    def create_application(
        self, *, slug: str, name: str, status: str = "active", managed_by: str | None = None
    ) -> ApplicationModel:
        with self.session() as s:
            row = orm.Application(
                id=str(uuid.uuid4()), slug=slug, name=name, status=status, managed_by=managed_by
            )
            s.add(row)
            s.commit()
            return self._to_application(row)

    def get_application(self, application_id: str) -> ApplicationModel | None:
        with self.session() as s:
            row = s.get(orm.Application, application_id)
            return self._to_application(row) if row else None

    def get_application_by_slug(self, slug: str) -> ApplicationModel | None:
        with self.session() as s:
            row = s.scalar(select(orm.Application).where(orm.Application.slug == slug))
            return self._to_application(row) if row else None

    def is_application_active(self, application_id: str) -> bool:
        with self.session() as s:
            row = s.get(orm.Application, application_id)
            return row is not None and row.status == "active"

    def set_application_managed_by(self, application_id: str, managed_by: str | None) -> None:
        with self.session() as s:
            row = s.get(orm.Application, application_id)
            if row is not None:
                row.managed_by = managed_by
                s.commit()

    # ---- Users + identities --------------------------------------------------

    def get_user(self, user_id: str) -> UserModel | None:
        with self.session() as s:
            row = s.get(orm.User, user_id)
            return self._to_user(row) if row else None

    def find_user_by_external_identity(
        self, provider: str, issuer: str, subject: str
    ) -> UserModel | None:
        with self.session() as s:
            row = s.scalar(
                select(orm.ExternalIdentity).where(
                    orm.ExternalIdentity.provider == provider,
                    orm.ExternalIdentity.issuer == issuer,
                    orm.ExternalIdentity.subject == subject,
                )
            )
            if row is None:
                return None
            user = s.get(orm.User, row.user_id)
            return self._to_user(user) if user else None

    def upsert_user_from_identity(
        self,
        *,
        provider: str,
        issuer: str,
        subject: str,
        email: str | None,
        external_tenant_id: str | None,
        display_name: str | None = None,
    ) -> tuple[UserModel, ExternalIdentityModel]:
        with self.session() as s:
            existing = s.scalar(
                select(orm.ExternalIdentity).where(
                    orm.ExternalIdentity.provider == provider,
                    orm.ExternalIdentity.issuer == issuer,
                    orm.ExternalIdentity.subject == subject,
                )
            )
            if existing is not None:
                user = s.get(orm.User, existing.user_id)
                return self._to_user(user), self._to_external_identity(existing)
            user_row = orm.User(
                id=str(uuid.uuid4()),
                display_name=display_name,
                email=email,
            )
            s.add(user_row)
            s.flush()
            ident = orm.ExternalIdentity(
                id=str(uuid.uuid4()),
                user_id=user_row.id,
                provider=provider,
                issuer=issuer,
                subject=subject,
                external_tenant_id=external_tenant_id,
                email=email,
            )
            s.add(ident)
            s.commit()
            return self._to_user(user_row), self._to_external_identity(ident)

    # ---- Tenant identity mapping --------------------------------------------

    def find_tenant_by_external(
        self, provider: str, issuer: str, external_tenant_id: str
    ) -> TenantModel | None:
        with self.session() as s:
            row = s.scalar(
                select(orm.TenantIdentityMapping).where(
                    orm.TenantIdentityMapping.provider == provider,
                    orm.TenantIdentityMapping.issuer == issuer,
                    orm.TenantIdentityMapping.external_tenant_id == external_tenant_id,
                )
            )
            if row is None:
                return None
            tenant = s.get(orm.Tenant, row.tenant_id)
            return self._to_tenant(tenant) if tenant else None

    def create_tenant_identity_mapping(
        self,
        *,
        tenant_id: str,
        provider: str,
        issuer: str,
        external_tenant_id: str,
    ) -> TenantIdentityMappingModel:
        with self.session() as s:
            row = orm.TenantIdentityMapping(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                provider=provider,
                issuer=issuer,
                external_tenant_id=external_tenant_id,
            )
            s.add(row)
            s.commit()
            return TenantIdentityMappingModel(
                id=row.id,
                tenant_id=row.tenant_id,
                provider=row.provider,
                issuer=row.issuer,
                external_tenant_id=row.external_tenant_id,
            )

    # ---- Memberships ---------------------------------------------------------

    def membership_role_names(self, s: Session, membership_id: str) -> list[str]:
        rows = s.execute(
            select(orm.Role.name)
            .join(orm.membership_roles, orm.membership_roles.c.role_id == orm.Role.id)
            .where(orm.membership_roles.c.membership_id == membership_id)
        ).all()
        return [r[0] for r in rows]

    def create_membership(
        self,
        *,
        tenant_id: str,
        application_id: str | None,
        user_id: str,
        status: str = MEMBERSHIP_STATUS_ACTIVE,
        roles: set[str] | None = None,
    ) -> MembershipModel:
        with self.session() as s:
            row = orm.Membership(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                application_id=application_id,
                user_id=user_id,
                status=status,
            )
            s.add(row)
            s.flush()
            if roles:
                role_rows = self._assignable_roles(
                    s, tenant_id=tenant_id, application_id=application_id, names=roles
                ).values()
                for r in role_rows:
                    s.execute(
                        orm.membership_roles.insert().values(
                            membership_id=row.id, role_id=r.id
                        )
                    )
            s.commit()
            names = self.membership_role_names(s, row.id)
            return self._to_membership(row, names)

    def get_membership(
        self, *, tenant_id: str, application_id: str | None, user_id: str
    ) -> MembershipModel | None:
        with self.session() as s:
            stmt = select(orm.Membership).where(
                orm.Membership.tenant_id == tenant_id,
                orm.Membership.user_id == user_id,
            )
            if application_id is None:
                stmt = stmt.where(orm.Membership.application_id.is_(None))
            else:
                stmt = stmt.where(orm.Membership.application_id == application_id)
            row = s.scalar(stmt)
            if row is None:
                return None
            names = self.membership_role_names(s, row.id)
            return self._to_membership(row, names)

    def list_memberships_for_user(self, user_id: str) -> list[MembershipModel]:
        with self.session() as s:
            rows = s.scalars(
                select(orm.Membership).where(orm.Membership.user_id == user_id)
            ).all()
            return [self._to_membership(r, self.membership_role_names(s, r.id)) for r in rows]

    def set_membership_roles(self, membership_id: str, role_names: set[str]) -> None:
        with self.session() as s:
            membership = s.get(orm.Membership, membership_id)
            if membership is None:
                return
            s.execute(
                delete(orm.membership_roles).where(
                    orm.membership_roles.c.membership_id == membership_id
                )
            )
            role_rows = self._assignable_roles(
                s,
                tenant_id=membership.tenant_id,
                application_id=membership.application_id,
                names=role_names,
            ).values()
            for r in role_rows:
                s.execute(
                    orm.membership_roles.insert().values(
                        membership_id=membership_id, role_id=r.id
                    )
                )
            s.commit()

    def is_user_membership_active(
        self, *, tenant_id: str, application_id: str, user_id: str
    ) -> bool:
        with self.session() as s:
            row = s.scalar(
                select(orm.Membership).where(
                    orm.Membership.tenant_id == tenant_id,
                    orm.Membership.user_id == user_id,
                    orm.Membership.application_id == application_id,
                )
            )
            if row is None:
                # Tenant-wide membership counts too.
                row = s.scalar(
                    select(orm.Membership).where(
                        orm.Membership.tenant_id == tenant_id,
                        orm.Membership.user_id == user_id,
                        orm.Membership.application_id.is_(None),
                    )
                )
            return row is not None and row.status == MEMBERSHIP_STATUS_ACTIVE

    # ---- Roles & Permissions -------------------------------------------------

    @staticmethod
    def _assignable_roles(
        s: Session, *, tenant_id: str | None, application_id: str | None, names: Iterable[str]
    ) -> dict[str, orm.Role]:
        """Resolve role names tenant-first: this tenant's role, else the
        application-wide one, never a role bound to another tenant.

        Internal per-agent roles are not assignable by name.
        """
        wanted = set(names)
        if not wanted:
            return {}
        app_clause = (
            orm.Role.application_id.is_(None)
            if application_id is None
            else orm.Role.application_id == application_id
        )
        rows = s.scalars(
            select(orm.Role).where(
                app_clause,
                orm.Role.name.in_(wanted),
                orm.Role.agent_id.is_(None),
                or_(orm.Role.tenant_id == tenant_id, orm.Role.tenant_id.is_(None)),
            )
        ).all()
        found: dict[str, orm.Role] = {}
        for r in rows:
            if r.tenant_id is not None or r.name not in found:
                found[r.name] = r
        return found

    def find_assignable_roles(
        self, *, tenant_id: str, application_id: str | None, names: Iterable[str]
    ) -> dict[str, RoleModel]:
        """Public view of the tenant-first name resolution (for validation)."""
        with self.session() as s:
            return {
                name: self._to_role(row)
                for name, row in self._assignable_roles(
                    s, tenant_id=tenant_id, application_id=application_id, names=names
                ).items()
            }

    @staticmethod
    def _effective_role_ids(s: Session, tenant_id: str, linked: Iterable[orm.Role]) -> set[str]:
        """Role ids that actually grant permissions for links in ``tenant_id``.

        A tenant role named like a linked application-wide role overrides it,
        no matter which was created first. Links to another tenant's role
        grant nothing.
        """
        own = [r for r in linked if r.tenant_id in (None, tenant_id)]
        names = {r.name for r in own if r.tenant_id is None and r.agent_id is None}
        overrides: dict[tuple[str | None, str], str] = {}
        if names:
            for o in s.scalars(
                select(orm.Role).where(
                    orm.Role.tenant_id == tenant_id,
                    orm.Role.agent_id.is_(None),
                    orm.Role.name.in_(names),
                )
            ).all():
                overrides[(o.application_id, o.name)] = o.id
        return {
            overrides.get((r.application_id, r.name), r.id)
            if r.tenant_id is None and r.agent_id is None
            else r.id
            for r in own
        }

    def create_role(
        self,
        *,
        name: str,
        scope: RoleScope,
        application_id: str | None = None,
        tenant_id: str | None = None,
        description: str | None = None,
    ) -> RoleModel:
        with self.session() as s:
            row = orm.Role(
                id=str(uuid.uuid4()),
                name=name,
                scope=scope.value,
                application_id=application_id,
                tenant_id=tenant_id,
                description=description,
            )
            s.add(row)
            s.commit()
            return self._to_role(row)

    def get_role(self, role_id: str) -> RoleModel | None:
        with self.session() as s:
            row = s.get(orm.Role, role_id)
            return self._to_role(row) if row else None

    def get_role_by_name(
        self, *, application_id: str | None, tenant_id: str | None, name: str
    ) -> RoleModel | None:
        with self.session() as s:
            stmt = select(orm.Role).where(orm.Role.name == name)
            stmt = (
                stmt.where(orm.Role.application_id.is_(None))
                if application_id is None
                else stmt.where(orm.Role.application_id == application_id)
            )
            stmt = (
                stmt.where(orm.Role.tenant_id.is_(None))
                if tenant_id is None
                else stmt.where(orm.Role.tenant_id == tenant_id)
            )
            row = s.scalar(stmt)
            return self._to_role(row) if row else None

    def list_roles_for_application(self, application_id: str) -> list[RoleModel]:
        with self.session() as s:
            rows = s.scalars(
                select(orm.Role).where(orm.Role.application_id == application_id)
            ).all()
            return [self._to_role(r) for r in rows]

    def create_permission(
        self,
        *,
        name: str,
        application_id: str | None = None,
        description: str | None = None,
    ) -> PermissionModel:
        # Reuse the parser in domain model so resource/action stay consistent.
        parsed = PermissionModel.from_name(name, application_id=application_id)
        with self.session() as s:
            row = orm.Permission(
                id=str(uuid.uuid4()),
                application_id=application_id,
                name=name,
                resource=parsed.resource,
                action=parsed.action,
                description=description,
            )
            s.add(row)
            s.commit()
            return self._to_permission(row)

    def list_application_permissions(self, application_id: str | None) -> list[PermissionModel]:
        """Permissions of one application, or the platform ones for ``None``."""
        with self.session() as s:
            rows = s.scalars(
                select(orm.Permission).where(
                    orm.Permission.application_id.is_(None)
                    if application_id is None
                    else orm.Permission.application_id == application_id
                )
            ).all()
            return [self._to_permission(r) for r in rows]

    def list_role_permissions(self, role_id: str) -> list[PermissionModel]:
        with self.session() as s:
            rows = s.scalars(
                select(orm.Permission)
                .join(orm.role_permissions, orm.role_permissions.c.permission_id == orm.Permission.id)
                .where(orm.role_permissions.c.role_id == role_id)
            ).all()
            return [self._to_permission(r) for r in rows]

    def set_role_permissions(self, role_id: str, permission_names: set[str]) -> None:
        with self.session() as s:
            role = s.get(orm.Role, role_id)
            if role is None:
                return
            s.execute(
                delete(orm.role_permissions).where(orm.role_permissions.c.role_id == role_id)
            )
            stmt = select(orm.Permission).where(orm.Permission.name.in_(permission_names))
            if role.application_id is not None:
                stmt = stmt.where(orm.Permission.application_id == role.application_id)
            permissions = s.scalars(stmt).all()
            for p in permissions:
                s.execute(
                    orm.role_permissions.insert().values(role_id=role_id, permission_id=p.id)
                )
            s.commit()

    # ---- Aggregated permission resolution -----------------------------------

    def resolve_user_permissions(
        self, *, tenant_id: str, application_id: str, user_id: str
    ) -> set[str]:
        with self.session() as s:
            # Eligible memberships: app-scoped for this app OR tenant-wide.
            # Memberships in *other* apps must not contribute permissions
            # to this app — that would cross application isolation.
            membership_rows = s.scalars(
                select(orm.Membership).where(
                    orm.Membership.tenant_id == tenant_id,
                    orm.Membership.user_id == user_id,
                    orm.Membership.status == MEMBERSHIP_STATUS_ACTIVE,
                    or_(
                        orm.Membership.application_id == application_id,
                        orm.Membership.application_id.is_(None),
                    ),
                )
            ).all()
            ids = [m.id for m in membership_rows]
            if not ids:
                return set()
            linked = s.scalars(
                select(orm.Role)
                .join(orm.membership_roles, orm.membership_roles.c.role_id == orm.Role.id)
                .where(orm.membership_roles.c.membership_id.in_(ids))
            ).all()
            role_ids = self._effective_role_ids(s, tenant_id, linked)
            if not role_ids:
                return set()
            # Restrict permissions to those scoped to this app (or unscoped
            # platform permissions). A tenant-wide membership might carry a
            # platform role; its permissions still need to be relevant here.
            rows = s.execute(
                select(orm.Permission.name)
                .join(orm.role_permissions, orm.role_permissions.c.permission_id == orm.Permission.id)
                .where(
                    orm.role_permissions.c.role_id.in_(role_ids),
                    orm.Permission.deprecated.is_(False),
                    or_(
                        orm.Permission.application_id == application_id,
                        orm.Permission.application_id.is_(None),
                    ),
                )
            ).all()
            return {r[0] for r in rows}

    def resolve_agent_permissions(
        self, *, tenant_id: str, application_id: str, agent_id: str
    ) -> set[str]:
        with self.session() as s:
            agent = s.get(orm.Agent, agent_id)
            if (
                agent is None
                or agent.tenant_id != tenant_id
                or agent.application_id != application_id
            ):
                return set()
            linked = s.scalars(
                select(orm.Role)
                .join(orm.agent_roles, orm.agent_roles.c.role_id == orm.Role.id)
                .where(orm.agent_roles.c.agent_id == agent_id)
            ).all()
            role_ids = self._effective_role_ids(s, tenant_id, linked)
            if not role_ids:
                return set()
            rows = s.execute(
                select(orm.Permission.name)
                .join(orm.role_permissions, orm.role_permissions.c.permission_id == orm.Permission.id)
                .where(
                    orm.role_permissions.c.role_id.in_(role_ids),
                    orm.Permission.deprecated.is_(False),
                )
            ).all()
            return {r[0] for r in rows}

    def resolve_tenant_permissions(
        self, *, tenant_id: str, application_id: str
    ) -> set[str]:
        with self.session() as s:
            rows = s.scalars(
                select(orm.TenantPermissionMask.permission_name).where(
                    orm.TenantPermissionMask.tenant_id == tenant_id,
                    orm.TenantPermissionMask.application_id == application_id,
                )
            ).all()
            return set(rows)

    def set_tenant_permission_mask(
        self, *, tenant_id: str, application_id: str, permissions: set[str]
    ) -> None:
        with self.session() as s:
            s.execute(
                delete(orm.TenantPermissionMask).where(
                    orm.TenantPermissionMask.tenant_id == tenant_id,
                    orm.TenantPermissionMask.application_id == application_id,
                )
            )
            for name in permissions:
                s.add(
                    orm.TenantPermissionMask(
                        tenant_id=tenant_id,
                        application_id=application_id,
                        permission_name=name,
                    )
                )
            s.commit()

    def get_tenant_feature_flags(
        self, tenant_id: str, application_id: str | None
    ) -> dict[str, Any]:
        with self.session() as s:
            stmt = select(orm.TenantFeatureFlag).where(
                orm.TenantFeatureFlag.tenant_id == tenant_id
            )
            stmt = (
                stmt.where(orm.TenantFeatureFlag.application_id.is_(None))
                if application_id is None
                else stmt.where(orm.TenantFeatureFlag.application_id == application_id)
            )
            rows = s.scalars(stmt).all()
            return {r.key: r.value for r in rows}

    def set_tenant_feature_flag(
        self, tenant_id: str, application_id: str | None, key: str, value: Any
    ) -> None:
        with self.session() as s:
            existing = s.scalar(
                select(orm.TenantFeatureFlag).where(
                    orm.TenantFeatureFlag.tenant_id == tenant_id,
                    orm.TenantFeatureFlag.application_id == application_id,
                    orm.TenantFeatureFlag.key == key,
                )
            )
            if existing:
                existing.value = value
            else:
                s.add(
                    orm.TenantFeatureFlag(
                        tenant_id=tenant_id,
                        application_id=application_id,
                        key=key,
                        value=value,
                    )
                )
            s.commit()

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
    ) -> AgentModel:
        with self.session() as s:
            row = orm.Agent(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                application_id=application_id,
                name=name,
                display_name=display_name,
                role_label=role,
                status=status,
                created_by_user_id=created_by_user_id,
            )
            s.add(row)
            s.commit()
            return self._to_agent(row)

    def get_agent(
        self, *, tenant_id: str, application_id: str, agent_id: str
    ) -> AgentModel | None:
        with self.session() as s:
            row = s.get(orm.Agent, agent_id)
            if (
                row is None
                or row.tenant_id != tenant_id
                or row.application_id != application_id
            ):
                return None
            return self._to_agent(row)

    def get_agent_by_id(self, agent_id: str) -> AgentModel | None:
        with self.session() as s:
            row = s.get(orm.Agent, agent_id)
            return self._to_agent(row) if row else None

    def find_agent_by_name(
        self, *, tenant_id: str, application_id: str, name: str
    ) -> AgentModel | None:
        with self.session() as s:
            row = s.scalar(
                select(orm.Agent).where(
                    orm.Agent.tenant_id == tenant_id,
                    orm.Agent.application_id == application_id,
                    orm.Agent.name == name,
                )
            )
            return self._to_agent(row) if row else None

    def is_agent_active(
        self, *, tenant_id: str, application_id: str, agent_id: str
    ) -> bool:
        agent = self.get_agent(
            tenant_id=tenant_id, application_id=application_id, agent_id=agent_id
        )
        return agent is not None and agent.status == "active"

    def set_agent_roles(self, agent_id: str, role_names: set[str]) -> None:
        with self.session() as s:
            agent = s.get(orm.Agent, agent_id)
            if agent is None:
                return
            s.execute(delete(orm.agent_roles).where(orm.agent_roles.c.agent_id == agent_id))
            role_rows = self._assignable_roles(
                s,
                tenant_id=agent.tenant_id,
                application_id=agent.application_id,
                names=role_names,
            ).values()
            for r in role_rows:
                s.execute(orm.agent_roles.insert().values(agent_id=agent_id, role_id=r.id))
            s.commit()

    def list_agents(self, *, tenant_id: str, application_id: str) -> list[AgentModel]:
        with self.session() as s:
            rows = s.scalars(
                select(orm.Agent).where(
                    orm.Agent.tenant_id == tenant_id,
                    orm.Agent.application_id == application_id,
                )
            ).all()
            return [self._to_agent(r) for r in rows]

    # ---- Declarative provisioning (catalog, tenant state, role overrides) -----

    def apply_application_catalog(
        self,
        *,
        slug: str,
        name: str,
        permissions: list[CatalogPermission],
        default_roles: list[CatalogRole],
        managed_by: str | None,
    ) -> CatalogResult:
        """Write an application's complete vocabulary in one transaction.

        Creates the application if needed (with ``managed_by``). Listed
        permissions are created or updated, unlisted ones are deprecated;
        each default role gets exactly the listed permissions. Raises
        :class:`ProvisioningError` without writing anything when invalid.
        """
        errors: list[ProvisioningIssue] = []
        for i, p in enumerate(permissions):
            if "." not in p.name:
                errors.append(
                    ProvisioningIssue(
                        f"permissions[{i}].name",
                        "invalid_permission_name",
                        f"permission name must contain '.': {p.name!r}",
                    )
                )
        listed = {p.name: p for p in permissions}
        for i, r in enumerate(default_roles):
            for j, perm in enumerate(r.permissions):
                if perm not in listed:
                    errors.append(
                        ProvisioningIssue(
                            f"default_roles[{i}].permissions[{j}]",
                            "unknown_permission",
                            f"permission {perm!r} is not in the catalog",
                        )
                    )
        if errors:
            raise ProvisioningError(errors)

        with self.session() as s:
            app = s.scalar(select(orm.Application).where(orm.Application.slug == slug))
            if app is None:
                app = orm.Application(
                    id=str(uuid.uuid4()), slug=slug, name=name, managed_by=managed_by
                )
                s.add(app)
            else:
                app.name = name
            s.flush()

            existing = {
                p.name: p
                for p in s.scalars(
                    select(orm.Permission).where(orm.Permission.application_id == app.id)
                ).all()
            }
            created = deprecated = 0
            for perm_name, spec in listed.items():
                row = existing.get(perm_name)
                if row is None:
                    parsed = PermissionModel.from_name(perm_name)
                    row = orm.Permission(
                        id=str(uuid.uuid4()),
                        application_id=app.id,
                        name=perm_name,
                        resource=parsed.resource,
                        action=parsed.action,
                    )
                    s.add(row)
                    existing[perm_name] = row
                    created += 1
                row.description = spec.description
                row.critical = spec.critical
                row.deprecated = False
            for perm_name, row in existing.items():
                if perm_name not in listed and not row.deprecated:
                    row.deprecated = True
                    deprecated += 1
            s.flush()

            roles = {
                r.name: r
                for r in s.scalars(
                    select(orm.Role).where(
                        orm.Role.application_id == app.id,
                        orm.Role.tenant_id.is_(None),
                        orm.Role.agent_id.is_(None),
                    )
                ).all()
            }
            roles_created = roles_updated = 0
            for spec_role in default_roles:
                role = roles.get(spec_role.name)
                if role is None:
                    role = orm.Role(
                        id=str(uuid.uuid4()),
                        name=spec_role.name,
                        scope=RoleScope.APPLICATION.value,
                        application_id=app.id,
                    )
                    s.add(role)
                    roles[spec_role.name] = role
                    roles_created += 1
                else:
                    roles_updated += 1
                role.description = spec_role.description
                s.flush()
                self._replace_role_permissions(
                    s, role.id, {existing[n].id for n in spec_role.permissions}
                )
            s.commit()
            return CatalogResult(
                application_id=app.id,
                permissions_created=created,
                permissions_deprecated=deprecated,
                roles_created=roles_created,
                roles_updated=roles_updated,
            )

    @staticmethod
    def _replace_role_permissions(s: Session, role_id: str, permission_ids: set[str]) -> bool:
        """Set a role's permission links; returns whether anything changed."""
        current = set(
            s.scalars(
                select(orm.role_permissions.c.permission_id).where(
                    orm.role_permissions.c.role_id == role_id
                )
            ).all()
        )
        if current == permission_ids:
            return False
        s.execute(delete(orm.role_permissions).where(orm.role_permissions.c.role_id == role_id))
        for pid in permission_ids:
            s.execute(orm.role_permissions.insert().values(role_id=role_id, permission_id=pid))
        return True

    @staticmethod
    def _active_permissions(s: Session, application_id: str) -> dict[str, orm.Permission]:
        return {
            p.name: p
            for p in s.scalars(
                select(orm.Permission).where(
                    orm.Permission.application_id == application_id,
                    orm.Permission.deprecated.is_(False),
                )
            ).all()
        }

    def apply_tenant_state(
        self, *, application_id: str, tenant_slug: str, state: TenantState
    ) -> TenantStateResult:
        """Make one tenant's members and agents of an application match ``state``.

        One transaction: the tenant and unknown users are created, listed
        memberships/agents are created or updated, unlisted ones disabled.
        Roles resolve tenant-first; agent permissions live on an internal
        per-agent role. Raises :class:`ProvisioningError` (nothing applied)
        on unknown roles/permissions, duplicates or invalid statuses.
        """
        with self.session() as s:
            tenant = s.scalar(select(orm.Tenant).where(orm.Tenant.slug == tenant_slug))
            role_rows = self._assignable_roles(
                s,
                tenant_id=tenant.id if tenant else None,
                application_id=application_id,
                names={n for m in state.members for n in m.roles},
            )
            perm_rows = self._active_permissions(s, application_id)
            self._validate_tenant_state(state, role_rows, perm_rows)

            if tenant is None:
                tenant = orm.Tenant(
                    id=str(uuid.uuid4()), slug=tenant_slug, name=state.name, status=state.status
                )
                s.add(tenant)
            else:
                tenant.name = state.name
                tenant.status = state.status
            s.flush()

            result = TenantStateResult(tenant_id=tenant.id)
            self._apply_members(s, tenant.id, application_id, state.members, role_rows, result)
            self._apply_agents(s, tenant.id, application_id, state.agents, perm_rows, result)
            s.commit()
            return result

    @staticmethod
    def _validate_tenant_state(
        state: TenantState,
        role_rows: dict[str, orm.Role],
        perm_rows: dict[str, orm.Permission],
    ) -> None:
        errors: list[ProvisioningIssue] = []
        if state.status not in TENANT_STATUSES:
            errors.append(
                ProvisioningIssue("status", "invalid_status", f"unknown tenant status {state.status!r}")
            )
        seen_users: set[UserRef] = set()
        for i, m in enumerate(state.members):
            if m.user_ref in seen_users:
                errors.append(
                    ProvisioningIssue(
                        f"members[{i}].user_ref", "duplicate_member", "user listed twice"
                    )
                )
            seen_users.add(m.user_ref)
            if m.status not in DESIRED_STATUSES:
                errors.append(
                    ProvisioningIssue(
                        f"members[{i}].status", "invalid_status", f"unknown status {m.status!r}"
                    )
                )
            for j, role in enumerate(m.roles):
                if role not in role_rows:
                    errors.append(
                        ProvisioningIssue(
                            f"members[{i}].roles[{j}]", "unknown_role", f"role {role!r} does not exist"
                        )
                    )
        seen_agents: set[str] = set()
        for i, a in enumerate(state.agents):
            if a.name in seen_agents:
                errors.append(
                    ProvisioningIssue(f"agents[{i}].name", "duplicate_agent", "agent listed twice")
                )
            seen_agents.add(a.name)
            if a.status not in DESIRED_STATUSES:
                errors.append(
                    ProvisioningIssue(
                        f"agents[{i}].status", "invalid_status", f"unknown status {a.status!r}"
                    )
                )
            for j, perm in enumerate(a.permissions):
                if perm not in perm_rows:
                    errors.append(
                        ProvisioningIssue(
                            f"agents[{i}].permissions[{j}]",
                            "unknown_permission",
                            f"permission {perm!r} is not in the catalog",
                        )
                    )
        if errors:
            raise ProvisioningError(errors)

    @staticmethod
    def _apply_members(
        s: Session,
        tenant_id: str,
        application_id: str,
        members: tuple[DesiredMember, ...],
        role_rows: dict[str, orm.Role],
        result: TenantStateResult,
    ) -> None:
        desired_users: set[str] = set()
        for m in members:
            ident = s.scalar(
                select(orm.ExternalIdentity).where(
                    orm.ExternalIdentity.provider == m.user_ref.provider,
                    orm.ExternalIdentity.issuer == m.user_ref.issuer,
                    orm.ExternalIdentity.subject == m.user_ref.subject,
                )
            )
            if ident is None:
                user = orm.User(id=str(uuid.uuid4()), display_name=m.display_name, email=m.email)
                s.add(user)
                s.flush()
                s.add(
                    orm.ExternalIdentity(
                        id=str(uuid.uuid4()),
                        user_id=user.id,
                        provider=m.user_ref.provider,
                        issuer=m.user_ref.issuer,
                        subject=m.user_ref.subject,
                        email=m.email,
                    )
                )
                user_id = user.id
            else:
                user_id = ident.user_id
                existing_user = s.get(orm.User, user_id)
                if existing_user is not None:
                    if m.display_name is not None:
                        existing_user.display_name = m.display_name
                    if m.email is not None:
                        existing_user.email = m.email
            desired_users.add(user_id)

            role_ids = {role_rows[n].id for n in m.roles}
            membership = s.scalar(
                select(orm.Membership).where(
                    orm.Membership.tenant_id == tenant_id,
                    orm.Membership.application_id == application_id,
                    orm.Membership.user_id == user_id,
                )
            )
            if membership is None:
                membership = orm.Membership(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    application_id=application_id,
                    user_id=user_id,
                    status=m.status,
                )
                s.add(membership)
                s.flush()
                current: set[str] = set()
                result.members.created += 1
            else:
                current = set(
                    s.scalars(
                        select(orm.membership_roles.c.role_id).where(
                            orm.membership_roles.c.membership_id == membership.id
                        )
                    ).all()
                )
                if current != role_ids or membership.status != m.status:
                    result.members.updated += 1
                membership.status = m.status
            if current != role_ids:
                s.execute(
                    delete(orm.membership_roles).where(
                        orm.membership_roles.c.membership_id == membership.id
                    )
                )
                for rid in role_ids:
                    s.execute(
                        orm.membership_roles.insert().values(
                            membership_id=membership.id, role_id=rid
                        )
                    )

        for other in s.scalars(
            select(orm.Membership).where(
                orm.Membership.tenant_id == tenant_id,
                orm.Membership.application_id == application_id,
                orm.Membership.user_id.not_in(desired_users),
                orm.Membership.status != MEMBERSHIP_STATUS_DISABLED,
            )
        ).all():
            other.status = MEMBERSHIP_STATUS_DISABLED
            result.members.disabled += 1

    def _apply_agents(
        self,
        s: Session,
        tenant_id: str,
        application_id: str,
        agents: tuple[DesiredAgent, ...],
        perm_rows: dict[str, orm.Permission],
        result: TenantStateResult,
    ) -> None:
        for a in agents:
            agent = s.scalar(
                select(orm.Agent).where(
                    orm.Agent.tenant_id == tenant_id,
                    orm.Agent.application_id == application_id,
                    orm.Agent.name == a.name,
                )
            )
            created = agent is None
            changed = False
            if agent is None:
                agent = orm.Agent(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    application_id=application_id,
                    name=a.name,
                    display_name=a.display_name,
                    status=a.status,
                )
                s.add(agent)
                s.flush()
            elif agent.status != a.status or agent.display_name != a.display_name:
                agent.status = a.status
                agent.display_name = a.display_name
                changed = True

            role = s.scalar(select(orm.Role).where(orm.Role.agent_id == agent.id))
            if role is None:
                role = orm.Role(
                    id=str(uuid.uuid4()),
                    name=agent_role_name(a.name),
                    scope=RoleScope.AGENT.value,
                    tenant_id=tenant_id,
                    application_id=application_id,
                    description="Internal: permissions of a provisioned agent",
                    is_system=True,
                    agent_id=agent.id,
                )
                s.add(role)
                s.flush()
            if self._replace_role_permissions(s, role.id, {perm_rows[n].id for n in a.permissions}):
                changed = True
            links = set(
                s.scalars(
                    select(orm.agent_roles.c.role_id).where(orm.agent_roles.c.agent_id == agent.id)
                ).all()
            )
            if links != {role.id}:
                s.execute(delete(orm.agent_roles).where(orm.agent_roles.c.agent_id == agent.id))
                s.execute(orm.agent_roles.insert().values(agent_id=agent.id, role_id=role.id))
                changed = True
            if created:
                result.agents.created += 1
            elif changed:
                result.agents.updated += 1

        for other in s.scalars(
            select(orm.Agent).where(
                orm.Agent.tenant_id == tenant_id,
                orm.Agent.application_id == application_id,
                orm.Agent.name.not_in({a.name for a in agents}),
                orm.Agent.status != AGENT_STATUS_DISABLED,
            )
        ).all():
            other.status = AGENT_STATUS_DISABLED
            result.agents.disabled += 1

    def list_tenant_roles(self, *, tenant_id: str, application_id: str) -> list[TenantRoleView]:
        """Default (application-wide) roles as seen by one tenant, overrides applied."""
        with self.session() as s:
            defaults = s.scalars(
                select(orm.Role)
                .where(
                    orm.Role.application_id == application_id,
                    orm.Role.tenant_id.is_(None),
                    orm.Role.agent_id.is_(None),
                )
                .order_by(orm.Role.name)
            ).all()
            overrides = {
                r.name: r
                for r in s.scalars(
                    select(orm.Role).where(
                        orm.Role.application_id == application_id,
                        orm.Role.tenant_id == tenant_id,
                        orm.Role.agent_id.is_(None),
                    )
                ).all()
            }

            def names(role_id: str) -> list[str]:
                return sorted(
                    s.scalars(
                        select(orm.Permission.name)
                        .join(
                            orm.role_permissions,
                            orm.role_permissions.c.permission_id == orm.Permission.id,
                        )
                        .where(
                            orm.role_permissions.c.role_id == role_id,
                            orm.Permission.deprecated.is_(False),
                        )
                    ).all()
                )

            views: list[TenantRoleView] = []
            for d in defaults:
                default_permissions = names(d.id)
                override = overrides.get(d.name)
                views.append(
                    TenantRoleView(
                        name=d.name,
                        source="tenant" if override else "application",
                        permissions=names(override.id) if override else default_permissions,
                        default_permissions=default_permissions,
                    )
                )
            return views

    def set_tenant_role_override(
        self, *, tenant_id: str, application_id: str, name: str, permissions: set[str]
    ) -> None:
        """Create or replace a tenant's override of the default role ``name``.

        Callers validate that the default role and the permissions exist.
        """
        with self.session() as s:
            role = s.scalar(
                select(orm.Role).where(
                    orm.Role.application_id == application_id,
                    orm.Role.tenant_id == tenant_id,
                    orm.Role.agent_id.is_(None),
                    orm.Role.name == name,
                )
            )
            if role is None:
                default = s.scalar(
                    select(orm.Role).where(
                        orm.Role.application_id == application_id,
                        orm.Role.tenant_id.is_(None),
                        orm.Role.agent_id.is_(None),
                        orm.Role.name == name,
                    )
                )
                role = orm.Role(
                    id=str(uuid.uuid4()),
                    name=name,
                    scope=RoleScope.TENANT.value,
                    tenant_id=tenant_id,
                    application_id=application_id,
                    description=default.description if default else None,
                )
                s.add(role)
                s.flush()
            perm_rows = self._active_permissions(s, application_id)
            self._replace_role_permissions(s, role.id, {perm_rows[n].id for n in permissions})
            s.commit()

    def delete_tenant_role_override(
        self, *, tenant_id: str, application_id: str, name: str
    ) -> None:
        """Remove a tenant override; holders of it keep the default role."""
        with self.session() as s:
            override = s.scalar(
                select(orm.Role).where(
                    orm.Role.application_id == application_id,
                    orm.Role.tenant_id == tenant_id,
                    orm.Role.agent_id.is_(None),
                    orm.Role.name == name,
                )
            )
            if override is None:
                return
            default = s.scalar(
                select(orm.Role).where(
                    orm.Role.application_id == application_id,
                    orm.Role.tenant_id.is_(None),
                    orm.Role.agent_id.is_(None),
                    orm.Role.name == name,
                )
            )
            for table, key in (
                (orm.membership_roles, orm.membership_roles.c.membership_id),
                (orm.agent_roles, orm.agent_roles.c.agent_id),
            ):
                holders = set(s.scalars(select(key).where(table.c.role_id == override.id)).all())
                if default is not None and holders:
                    has_default = set(
                        s.scalars(
                            select(key).where(table.c.role_id == default.id, key.in_(holders))
                        ).all()
                    )
                    for holder in holders - has_default:
                        s.execute(table.insert().values({key.name: holder, "role_id": default.id}))
                s.execute(delete(table).where(table.c.role_id == override.id))
            s.execute(
                delete(orm.role_permissions).where(orm.role_permissions.c.role_id == override.id)
            )
            s.delete(override)
            s.commit()

    # ---- Audit ---------------------------------------------------------------

    def write_audit(self, entry: AuditEntry, *, request_id: str | None = None) -> None:
        with self.session() as s:
            row = orm.AuditLog(
                id=str(uuid.uuid4()),
                tenant_id=entry.tenant_id,
                application_id=entry.application_id,
                user_id=entry.user_id,
                agent_id=entry.agent_id,
                decision=entry.decision,
                resource=entry.resource,
                action=entry.action,
                reason=entry.reason,
                request=entry.request,
                response=entry.response,
                request_id=request_id or entry.request_id,
            )
            s.add(row)
            s.commit()
