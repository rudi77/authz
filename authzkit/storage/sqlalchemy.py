"""SQLAlchemy-backed implementation of all repository protocols."""

from __future__ import annotations

import uuid
from typing import Any, Iterable

from sqlalchemy import Engine, create_engine, delete, select
from sqlalchemy.orm import Session, sessionmaker

from authzkit.agents.models import Agent as AgentModel
from authzkit.audit.logger import AuditEntry
from authzkit.rbac.models import Permission as PermissionModel
from authzkit.rbac.models import Role as RoleModel
from authzkit.rbac.models import RoleScope
from authzkit.storage import orm
from authzkit.tenancy.models import (
    MEMBERSHIP_STATUS_ACTIVE,
    Application as ApplicationModel,
    ExternalIdentity as ExternalIdentityModel,
    Membership as MembershipModel,
    Tenant as TenantModel,
    TenantIdentityMapping as TenantIdentityMappingModel,
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
        return ApplicationModel(id=row.id, slug=row.slug, name=row.name, status=row.status)

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
        self, *, slug: str, name: str, status: str = "active"
    ) -> ApplicationModel:
        with self.session() as s:
            row = orm.Application(id=str(uuid.uuid4()), slug=slug, name=name, status=status)
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

    def _membership_role_names(self, s: Session, membership_id: str) -> list[str]:
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
                role_rows = s.scalars(
                    select(orm.Role).where(
                        orm.Role.application_id == application_id, orm.Role.name.in_(roles)
                    )
                ).all()
                for r in role_rows:
                    s.execute(
                        orm.membership_roles.insert().values(
                            membership_id=row.id, role_id=r.id
                        )
                    )
            s.commit()
            names = self._membership_role_names(s, row.id)
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
            names = self._membership_role_names(s, row.id)
            return self._to_membership(row, names)

    def list_memberships_for_user(self, user_id: str) -> list[MembershipModel]:
        with self.session() as s:
            rows = s.scalars(
                select(orm.Membership).where(orm.Membership.user_id == user_id)
            ).all()
            return [self._to_membership(r, self._membership_role_names(s, r.id)) for r in rows]

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
            role_rows = s.scalars(
                select(orm.Role).where(
                    orm.Role.application_id == membership.application_id,
                    orm.Role.name.in_(role_names),
                )
            ).all()
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

    def list_application_permissions(self, application_id: str) -> list[PermissionModel]:
        with self.session() as s:
            rows = s.scalars(
                select(orm.Permission).where(orm.Permission.application_id == application_id)
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
            # Pull memberships scoped to this app and tenant-wide; either may
            # carry roles that grant permissions for this application.
            membership_rows = s.scalars(
                select(orm.Membership).where(
                    orm.Membership.tenant_id == tenant_id,
                    orm.Membership.user_id == user_id,
                    orm.Membership.status == MEMBERSHIP_STATUS_ACTIVE,
                )
            ).all()
            ids = [m.id for m in membership_rows]
            if not ids:
                return set()
            rows = s.execute(
                select(orm.Permission.name)
                .join(orm.role_permissions, orm.role_permissions.c.permission_id == orm.Permission.id)
                .join(orm.Role, orm.Role.id == orm.role_permissions.c.role_id)
                .join(orm.membership_roles, orm.membership_roles.c.role_id == orm.Role.id)
                .where(orm.membership_roles.c.membership_id.in_(ids))
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
            rows = s.execute(
                select(orm.Permission.name)
                .join(orm.role_permissions, orm.role_permissions.c.permission_id == orm.Permission.id)
                .join(orm.agent_roles, orm.agent_roles.c.role_id == orm.role_permissions.c.role_id)
                .where(orm.agent_roles.c.agent_id == agent_id)
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
    ) -> AgentModel:
        with self.session() as s:
            row = orm.Agent(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                application_id=application_id,
                name=name,
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
            role_rows = s.scalars(
                select(orm.Role).where(
                    orm.Role.application_id == agent.application_id,
                    orm.Role.name.in_(role_names),
                )
            ).all()
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
