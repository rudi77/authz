"""Quickstart: simplest possible authz check, in-memory, no service.

Walks the absolute minimum needed to get a yes/no answer out of the
``AuthorizationEngine``: a tenant, an application, a permission, a role,
a user, and a membership. Everything stays in process — no database,
no HTTP, no JWTs.

Run with::

    python examples/01_quickstart_inmemory.py
"""

from __future__ import annotations

from authzkit import AuthorizationEngine, AuthorizeRequest, Subject
from authzkit.rbac.models import RoleScope
from authzkit.storage.memory import InMemoryStore


def main() -> None:
    store = InMemoryStore()

    tenant = store.create_tenant(slug="acme", name="ACME Inc.")
    app = store.create_application(slug="docs", name="Docs Portal")

    store.create_permission(name="docs.read", application_id=app.id)
    store.create_permission(name="docs.write", application_id=app.id)

    editor = store.create_role(
        name="editor",
        scope=RoleScope.APPLICATION,
        application_id=app.id,
    )
    store.set_role_permissions(editor.id, {"docs.read", "docs.write"})

    user, _ = store.upsert_user_from_identity(
        provider="generic_oidc",
        issuer="https://idp.example",
        subject="alice",
        email="alice@acme.com",
        external_tenant_id=None,
    )
    store.create_membership(
        tenant_id=tenant.id,
        application_id=app.id,
        user_id=user.id,
        roles={"editor"},
    )

    engine = AuthorizationEngine(store)
    subject = Subject(type="user", user_id=user.id)

    decision = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=subject,
            resource="docs",
            action="read",
        )
    )
    print(f"docs.read   -> allowed={decision.allowed} reason={decision.reason}")

    decision = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=subject,
            resource="docs",
            action="delete",
        )
    )
    print(f"docs.delete -> allowed={decision.allowed} reason={decision.reason}")


if __name__ == "__main__":
    main()
