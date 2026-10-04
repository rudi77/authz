"""SQLAlchemy-backed implementation of all repository protocols."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any, TypeVar

from sqlalchemy import (
    Column,
    Engine,
    Select,
    Table,
    create_engine,
    delete,
    or_,
    select,
    tuple_,
    update,
)
from sqlalchemy.orm import Session, sessionmaker

from authzkit.agents.models import AGENT_STATUS_DISABLED
from authzkit.agents.models import Agent as AgentModel
from authzkit.audit.logger import AuditEntry
from authzkit.provisioning import (
    DESIRED_STATUSES,
    STATUS_ACTIVE,
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
    UnknownNamesError,
    UserRef,
    agent_role_name,
)
from authzkit.rbac.checker import ResolvedReferences
from authzkit.rbac.models import Permission as PermissionModel
from authzkit.rbac.models import Role as RoleModel
from authzkit.rbac.models import RoleScope
from authzkit.storage import orm
from authzkit.tenancy.models import (
    MEMBERSHIP_STATUS_ACTIVE,
    MEMBERSHIP_STATUS_DISABLED,
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

_SlugRow = TypeVar("_SlugRow", orm.Tenant, orm.Application)


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

    def find_tenant(self, ref: str) -> TenantModel | None:
        """A tenant by id or slug (one query)."""
        with self.session() as s:
            row = self._by_id_or_slug(s, orm.Tenant, ref)
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

    def find_application(self, ref: str) -> ApplicationModel | None:
        """An application by id or slug (one query)."""
        with self.session() as s:
            row = self._by_id_or_slug(s, orm.Application, ref)
            return self._to_application(row) if row else None

    @staticmethod
    def _by_id_or_slug(s: Session, model: type[_SlugRow], ref: str) -> _SlugRow | None:
        """Row whose id or slug is ``ref``; the id wins if both match different rows.

        The id is only compared when ``ref`` parses as a UUID (Postgres
        rejects anything else for a UUID column).
        """
        try:
            uuid.UUID(ref)
            match = or_(model.id == ref, model.slug == ref)
        except ValueError:
            match = model.slug == ref
        rows = s.scalars(select(model).where(match)).all()
        return next((r for r in rows if r.id == ref), rows[0] if rows else None)

    def resolve_references(
        self,
        *,
        tenant: str,
        application: str,
        user_id: str | None = None,
        user_ref: UserRef | None = None,
        agent_id: str | None = None,
        agent_name: str | None = None,
    ) -> ResolvedReferences:
        """Resolve a decision's references in one session, one query each.

        ``tenant`` / ``application`` are ids or slugs; ``user_ref`` and
        ``agent_name`` replace ``user_id`` / ``agent_id`` when given. The
        result goes to the engine (see :class:`ResolvedReferences`).
        """
        with self.session() as s:
            t = self._by_id_or_slug(s, orm.Tenant, tenant)
            a = self._by_id_or_slug(s, orm.Application, application)
            if user_ref is not None:
                user_id = s.scalar(
                    select(orm.ExternalIdentity.user_id).where(
                        orm.ExternalIdentity.provider == user_ref.provider,
                        orm.ExternalIdentity.issuer == user_ref.issuer,
                        orm.ExternalIdentity.subject == user_ref.subject,
                    )
                )
            agent_status = None
            if agent_name is not None:
                agent = (
                    s.execute(
                        select(orm.Agent.id, orm.Agent.status).where(
                            orm.Agent.tenant_id == t.id,
                            orm.Agent.application_id == a.id,
                            orm.Agent.name == agent_name,
                        )
                    ).first()
                    if t is not None and a is not None
                    else None
                )
                agent_id, agent_status = (agent.id, agent.status) if agent else (None, None)
            return ResolvedReferences(
                tenant_id=t.id if t else tenant,
                application_id=a.id if a else application,
                tenant_status=t.status if t else None,
                application_status=a.status if a else None,
                user_id=user_id,
                user_missing=user_ref is not None and user_id is None,
                agent_id=agent_id,
                agent_status=agent_status,
                agent_missing=agent_name is not None and agent_id is None,
            )

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

    def claim_application_management(self, application_id: str, managed_by: str) -> str | None:
        """Set ``managed_by`` only while it is null (atomic); returns the manager after the call."""
        with self.session() as s:
            s.execute(
                update(orm.Application)
                .where(orm.Application.id == application_id, orm.Application.managed_by.is_(None))
                .values(managed_by=managed_by)
            )
            s.commit()
            return s.scalar(
                select(orm.Application.managed_by).where(orm.Application.id == application_id)
            )

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
            user, ident = self._upsert_identity(
                s,
                existing,
                UserRef(provider, issuer, subject),
                email=email,
                external_tenant_id=external_tenant_id,
                display_name=display_name,
            )
            s.commit()
            return self._to_user(user), self._to_external_identity(ident)

    @staticmethod
    def _upsert_identity(
        s: Session,
        existing: orm.ExternalIdentity | None,
        ref: UserRef,
        *,
        email: str | None,
        external_tenant_id: str | None = None,
        display_name: str | None = None,
    ) -> tuple[orm.User, orm.ExternalIdentity]:
        """The user behind ``existing``, or a new user + identity for ``ref`` (not committed)."""
        if existing is not None:
            return s.get_one(orm.User, existing.user_id), existing
        user = orm.User(id=str(uuid.uuid4()), display_name=display_name, email=email)
        ident = orm.ExternalIdentity(
            id=str(uuid.uuid4()),
            user_id=user.id,
            provider=ref.provider,
            issuer=ref.issuer,
            subject=ref.subject,
            external_tenant_id=external_tenant_id,
            email=email,
        )
        s.add(user)
        s.flush()  # no ORM relationship: the user row must exist before its identity
        s.add(ident)
        return user, ident

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
                self._replace_links(
                    s,
                    orm.membership_roles,
                    "membership_id",
                    row.id,
                    {r.id for r in role_rows},
                    set(),
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

    def get_membership_by_id(self, membership_id: str) -> MembershipModel | None:
        with self.session() as s:
            row = s.get(orm.Membership, membership_id)
            return self._to_membership(row, self.membership_role_names(s, row.id)) if row else None

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
            role_rows = self._assignable_roles(
                s,
                tenant_id=membership.tenant_id,
                application_id=membership.application_id,
                names=role_names,
            ).values()
            self._replace_links(
                s, orm.membership_roles, "membership_id", membership_id, {r.id for r in role_rows}
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
        """A named role (never an internal per-agent role)."""
        with self.session() as s:
            row = self._role_by_name(s, application_id, tenant_id, name)
            return self._to_role(row) if row else None

    @staticmethod
    def _named_roles(application_id: str | None, tenant_id: str | None) -> Select:
        """Named roles of an application: application-wide (``tenant_id=None``)
        or bound to one tenant. Internal per-agent roles are excluded."""
        return select(orm.Role).where(
            orm.Role.application_id.is_(None)
            if application_id is None
            else orm.Role.application_id == application_id,
            orm.Role.tenant_id.is_(None) if tenant_id is None else orm.Role.tenant_id == tenant_id,
            orm.Role.agent_id.is_(None),
        )

    @classmethod
    def _role_by_name(
        cls, s: Session, application_id: str | None, tenant_id: str | None, name: str
    ) -> orm.Role | None:
        return s.scalar(cls._named_roles(application_id, tenant_id).where(orm.Role.name == name))

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
        """Replace a role's permissions with active ones of its application.

        Raises :class:`UnknownNamesError` (nothing written) for unknown or
        deprecated names.
        """
        with self.session() as s:
            role = s.get(orm.Role, role_id)
            if role is None:
                return
            rows = self._active_permissions(s, role.application_id, permission_names)
            UnknownNamesError.check("permission", permission_names, rows)
            self._replace_links(
                s, orm.role_permissions, "role_id", role_id, {p.id for p in rows.values()}
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
                    orm.Permission.active,
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
                    orm.Permission.active,
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
        """Replace an agent's roles (resolved tenant-first).

        Raises :class:`UnknownNamesError` (nothing written) for unknown names.
        """
        with self.session() as s:
            agent = s.get(orm.Agent, agent_id)
            if agent is None:
                return
            role_rows = self._assignable_roles(
                s,
                tenant_id=agent.tenant_id,
                application_id=agent.application_id,
                names=role_names,
            )
            UnknownNamesError.check("role", role_names, role_rows)
            self._replace_links(
                s, orm.agent_roles, "agent_id", agent_id, {r.id for r in role_rows.values()}
            )
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
        parsed: dict[str, PermissionModel] = {}
        for i, p in enumerate(permissions):
            try:
                parsed[p.name] = PermissionModel.from_name(p.name)
            except ValueError as exc:
                errors.append(
                    ProvisioningIssue(f"permissions[{i}].name", "invalid_permission_name", str(exc))
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
                    row = orm.Permission(
                        id=str(uuid.uuid4()),
                        application_id=app.id,
                        name=perm_name,
                        resource=parsed[perm_name].resource,
                        action=parsed[perm_name].action,
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

            roles = {r.name: r for r in s.scalars(self._named_roles(app.id, None)).all()}
            current = self._links(
                s, orm.role_permissions, "role_id", [r.id for r in roles.values()]
            )
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
            for spec_role in default_roles:
                role = roles[spec_role.name]
                self._replace_links(
                    s,
                    orm.role_permissions,
                    "role_id",
                    role.id,
                    {existing[n].id for n in spec_role.permissions},
                    current.get(role.id, set()),
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
    def _link_columns(table: Table, owner_col: str) -> tuple[Column, Column]:
        """(owner, other) key columns of a two-key link table."""
        owner = table.c[owner_col]
        return owner, next(c for c in table.primary_key.columns if c is not owner)

    @staticmethod
    def _links(
        s: Session, table: Table, owner_col: str, owner_ids: Iterable[str]
    ) -> dict[str, set[str]]:
        """Current link rows of a two-column link table, per owner, in one query."""
        ids = list(owner_ids)
        if not ids:
            return {}
        owner, other = SqlAlchemyStore._link_columns(table, owner_col)
        out: dict[str, set[str]] = {}
        for owner_id, other_id in s.execute(select(owner, other).where(owner.in_(ids))).all():
            out.setdefault(owner_id, set()).add(other_id)
        return out

    @staticmethod
    def _replace_links(
        s: Session,
        table: Table,
        owner_col: str,
        owner_id: str,
        ids: set[str],
        current: set[str] | None = None,
    ) -> bool:
        """Make ``owner_id``'s links in ``table`` exactly ``ids``; returns whether
        anything changed. ``current`` skips the read when already known."""
        owner, other = SqlAlchemyStore._link_columns(table, owner_col)
        if current is None:
            current = set(s.scalars(select(other).where(owner == owner_id)).all())
        if current == ids:
            return False
        if current - ids:
            s.execute(delete(table).where(owner == owner_id, other.in_(current - ids)))
        if ids - current:
            s.execute(
                table.insert(), [{owner_col: owner_id, other.name: i} for i in ids - current]
            )
        return True

    @staticmethod
    def _active_permissions(
        s: Session, application_id: str | None, names: Iterable[str] | None = None
    ) -> dict[str, orm.Permission]:
        """Assignable permissions of an application (``None``: platform ones), by name."""
        stmt = select(orm.Permission).where(
            orm.Permission.application_id.is_(None)
            if application_id is None
            else orm.Permission.application_id == application_id,
            orm.Permission.active,
        )
        if names is not None:
            stmt = stmt.where(orm.Permission.name.in_(set(names)))
        return {p.name: p for p in s.scalars(stmt).all()}

    def apply_tenant_state(
        self, *, application_id: str, tenant_slug: str, state: TenantState
    ) -> TenantStateResult:
        """Make one tenant's members and agents of an application match ``state``.

        One transaction: the tenant and unknown users are created, listed
        memberships/agents are created or updated, unlisted ones disabled.
        Tenants and users are shared by all applications: an existing tenant's
        name/status and an existing user's profile are never changed here
        (``state.name`` / member names and emails apply on creation only).
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
            perm_rows = self._active_permissions(
                s, application_id, {p for a in state.agents for p in a.permissions}
            )
            self._validate_tenant_state(state, role_rows, perm_rows)

            if tenant is None:
                tenant = orm.Tenant(
                    id=str(uuid.uuid4()), slug=tenant_slug, name=state.name, status=STATUS_ACTIVE
                )
                s.add(tenant)
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
        if state.status != STATUS_ACTIVE:
            errors.append(
                ProvisioningIssue(
                    "status",
                    "tenant_status_not_managed",
                    "the tenant status belongs to the platform; only 'active' is accepted",
                )
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

    def _apply_members(
        self,
        s: Session,
        tenant_id: str,
        application_id: str,
        members: tuple[DesiredMember, ...],
        role_rows: dict[str, orm.Role],
        result: TenantStateResult,
    ) -> None:
        """Set-based: identities, memberships and their roles are read in one
        query each, diffed in memory, then written. Existing users are left as
        they are (shared by all applications); new ones get name and email."""
        refs = [(m.user_ref.provider, m.user_ref.issuer, m.user_ref.subject) for m in members]
        identities = (
            {
                (i.provider, i.issuer, i.subject): i
                for i in s.scalars(
                    select(orm.ExternalIdentity).where(
                        tuple_(
                            orm.ExternalIdentity.provider,
                            orm.ExternalIdentity.issuer,
                            orm.ExternalIdentity.subject,
                        ).in_(refs)
                    )
                ).all()
            }
            if refs
            else {}
        )
        memberships = {
            m.user_id: m
            for m in s.scalars(
                select(orm.Membership).where(
                    orm.Membership.tenant_id == tenant_id,
                    orm.Membership.application_id == application_id,
                )
            ).all()
        }
        current_roles = self._links(
            s, orm.membership_roles, "membership_id", [m.id for m in memberships.values()]
        )

        desired: list[tuple[orm.Membership, set[str], set[str]]] = []
        desired_users: set[str] = set()
        for m, ref in zip(members, refs, strict=True):
            ident = identities.get(ref)
            if ident is None:
                _, ident = self._upsert_identity(
                    s, None, m.user_ref, email=m.email, display_name=m.display_name
                )
            user_id = ident.user_id
            desired_users.add(user_id)

            role_ids = {role_rows[n].id for n in m.roles}
            membership = memberships.get(user_id)
            if membership is None:
                membership = orm.Membership(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    application_id=application_id,
                    user_id=user_id,
                    status=m.status,
                )
                s.add(membership)
                current: set[str] = set()
                result.members.created += 1
            else:
                current = current_roles.get(membership.id, set())
                if current != role_ids or membership.status != m.status:
                    result.members.updated += 1
                membership.status = m.status
            desired.append((membership, role_ids, current))

        s.flush()  # new memberships exist before their link rows
        for membership, role_ids, current in desired:
            self._replace_links(
                s, orm.membership_roles, "membership_id", membership.id, role_ids, current
            )

        for user_id, other in memberships.items():
            if user_id not in desired_users and other.status != MEMBERSHIP_STATUS_DISABLED:
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
        """Set-based like :meth:`_apply_members`: agents, their internal roles,
        agent-role links and role permissions are read in one query each."""
        existing = {
            a.name: a
            for a in s.scalars(
                select(orm.Agent).where(
                    orm.Agent.tenant_id == tenant_id,
                    orm.Agent.application_id == application_id,
                )
            ).all()
        }
        agent_ids = [a.id for a in existing.values()]
        internal_roles = (
            {
                r.agent_id: r
                for r in s.scalars(select(orm.Role).where(orm.Role.agent_id.in_(agent_ids))).all()
            }
            if agent_ids
            else {}
        )
        current_links = self._links(s, orm.agent_roles, "agent_id", agent_ids)
        current_perms = self._links(
            s, orm.role_permissions, "role_id", [r.id for r in internal_roles.values()]
        )

        rows: list[tuple[DesiredAgent, orm.Agent, bool, bool]] = []
        for a in agents:
            agent = existing.get(a.name)
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
            elif agent.status != a.status or agent.display_name != a.display_name:
                agent.status = a.status
                agent.display_name = a.display_name
                changed = True
            rows.append((a, agent, created, changed))
        s.flush()  # new agents exist before their internal roles (no ORM relationship)

        planned: list[tuple[orm.Agent, orm.Role, set[str], bool, bool]] = []
        for a, agent, created, changed in rows:
            role = internal_roles.get(agent.id)
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
            permission_ids = {perm_rows[n].id for n in a.permissions}
            planned.append((agent, role, permission_ids, created, changed))

        s.flush()  # new roles exist before their link rows
        for agent, role, permission_ids, created, changed in planned:
            current = current_perms.get(role.id, set())
            if self._replace_links(
                s, orm.role_permissions, "role_id", role.id, permission_ids, current
            ):
                changed = True
            current = current_links.get(agent.id, set())
            if self._replace_links(s, orm.agent_roles, "agent_id", agent.id, {role.id}, current):
                changed = True
            if created:
                result.agents.created += 1
            elif changed:
                result.agents.updated += 1

        listed = {a.name for a in agents}
        for name, other in existing.items():
            if name not in listed and other.status != AGENT_STATUS_DISABLED:
                other.status = AGENT_STATUS_DISABLED
                result.agents.disabled += 1

    def list_tenant_roles(self, *, tenant_id: str, application_id: str) -> list[TenantRoleView]:
        """Default (application-wide) roles as seen by one tenant, overrides applied."""
        with self.session() as s:
            defaults = s.scalars(
                self._named_roles(application_id, None).order_by(orm.Role.name)
            ).all()
            overrides = {
                r.name: r for r in s.scalars(self._named_roles(application_id, tenant_id)).all()
            }
            role_ids = [r.id for r in defaults] + [r.id for r in overrides.values()]
            names: dict[str, list[str]] = {}
            if role_ids:
                for role_id, perm_name in s.execute(
                    select(orm.role_permissions.c.role_id, orm.Permission.name)
                    .join(
                        orm.role_permissions,
                        orm.role_permissions.c.permission_id == orm.Permission.id,
                    )
                    .where(orm.role_permissions.c.role_id.in_(role_ids), orm.Permission.active)
                ).all():
                    names.setdefault(role_id, []).append(perm_name)

            views: list[TenantRoleView] = []
            for d in defaults:
                default_permissions = sorted(names.get(d.id, []))
                override = overrides.get(d.name)
                views.append(
                    TenantRoleView(
                        name=d.name,
                        source="tenant" if override else "application",
                        permissions=sorted(names.get(override.id, []))
                        if override
                        else default_permissions,
                        default_permissions=default_permissions,
                    )
                )
            return views

    def set_tenant_role_override(
        self, *, tenant_id: str, application_id: str, name: str, permissions: set[str]
    ) -> None:
        """Create or replace a tenant's override of the default role ``name``.

        Callers check that the default role exists. Raises
        :class:`UnknownNamesError` (nothing written) for unknown or
        deprecated permissions.
        """
        with self.session() as s:
            perm_rows = self._active_permissions(s, application_id, permissions)
            UnknownNamesError.check("permission", permissions, perm_rows)
            role = self._role_by_name(s, application_id, tenant_id, name)
            if role is None:
                default = self._role_by_name(s, application_id, None, name)
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
            self._replace_links(
                s, orm.role_permissions, "role_id", role.id, {p.id for p in perm_rows.values()}
            )
            s.commit()

    def delete_tenant_role_override(
        self, *, tenant_id: str, application_id: str, name: str
    ) -> None:
        """Remove a tenant override; holders of it keep the default role."""
        with self.session() as s:
            override = self._role_by_name(s, application_id, tenant_id, name)
            if override is None:
                return
            default = self._role_by_name(s, application_id, None, name)
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
