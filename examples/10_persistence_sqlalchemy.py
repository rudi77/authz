"""SQLAlchemy persistence: production-shape store backed by SQLite.

The production deployment uses Postgres, but the same ``SqlAlchemyStore``
runs against an on-disk SQLite file with zero changes. This example
demonstrates that drop-in compatibility:

- The ``SqlAlchemyStore`` exposes the same protocol as ``InMemoryStore``,
  so the ``AuthorizationEngine`` consumes either one identically
- Decisions written in one process are visible to the next process
  reading the same database file
- Schema is created via ``init_schema`` (Alembic in real deployments)

Run with::

    python examples/10_persistence_sqlalchemy.py
"""

from __future__ import annotations

import os
import tempfile

from authzkit import AuthorizationEngine, AuthorizeRequest, Subject
from authzkit.rbac.models import RoleScope
from authzkit.storage.sqlalchemy import (
    SqlAlchemyStore,
    create_engine_from_url,
    init_schema,
)


def seed(store: SqlAlchemyStore) -> tuple[str, str, str]:
    tenant = store.create_tenant(slug="acme", name="ACME")
    app = store.create_application(slug="docs", name="Docs")
    store.create_permission(name="docs.read", application_id=app.id)
    store.create_permission(name="docs.write", application_id=app.id)
    role = store.create_role(name="editor", scope=RoleScope.APPLICATION, application_id=app.id)
    store.set_role_permissions(role.id, {"docs.read", "docs.write"})

    user, _ = store.upsert_user_from_identity(
        provider="generic_oidc", issuer="https://idp",
        subject="alice", email="alice@acme.com", external_tenant_id=None,
    )
    store.create_membership(
        tenant_id=tenant.id, application_id=app.id, user_id=user.id, roles={"editor"},
    )
    return tenant.id, app.id, user.id


def main() -> None:
    fd, db_path = tempfile.mkstemp(prefix="authz-example-", suffix=".db")
    os.close(fd)
    db_url = f"sqlite+pysqlite:///{db_path}"
    print(f"Using {db_url}")

    try:
        # Phase 1: write tenant/role/user/membership.
        engine = create_engine_from_url(db_url)
        init_schema(engine)
        store = SqlAlchemyStore(engine)
        tenant_id, app_id, user_id = seed(store)
        print(f"Seeded: tenant={tenant_id[:8]}.. app={app_id[:8]}.. user={user_id[:8]}..")

        # Phase 2: open a fresh connection (simulating a different process)
        # and authorize against the same data.
        engine2 = create_engine_from_url(db_url)
        store2 = SqlAlchemyStore(engine2)
        engine_pdp = AuthorizationEngine(store2)

        for resource, action in [("docs", "read"), ("docs", "write"), ("docs", "delete")]:
            decision = engine_pdp.authorize(
                AuthorizeRequest(
                    tenant_id=tenant_id, application_id=app_id,
                    subject=Subject(type="user", user_id=user_id),
                    resource=resource, action=action,
                )
            )
            verdict = "ALLOW" if decision.allowed else f"DENY ({decision.reason})"
            print(f"  {resource}.{action:<6} -> {verdict}")
    finally:
        os.unlink(db_path)


if __name__ == "__main__":
    main()
