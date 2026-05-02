"""RBAC fundamentals: roles, permission inheritance, multiple users.

Demonstrates:
- Multiple roles within one application
- A user with several roles seeing the union of their permissions
- Role updates taking effect immediately on subsequent checks
- ``effective_permissions`` for previewing what a subject can do

Run with::

    python examples/02_rbac_basics.py
"""

from __future__ import annotations

from authzkit import AuthorizationEngine, AuthorizeRequest, Subject
from authzkit.rbac.models import RoleScope
from authzkit.storage.memory import InMemoryStore


def main() -> None:
    store = InMemoryStore()
    tenant = store.create_tenant(slug="acme", name="ACME")
    app = store.create_application(slug="ticketing", name="Ticketing")

    for name in [
        "tickets.read",
        "tickets.create",
        "tickets.assign",
        "tickets.close",
        "tickets.delete",
        "reports.view",
    ]:
        store.create_permission(name=name, application_id=app.id)

    viewer = store.create_role(name="viewer", scope=RoleScope.APPLICATION, application_id=app.id)
    agent = store.create_role(name="agent", scope=RoleScope.APPLICATION, application_id=app.id)
    manager = store.create_role(name="manager", scope=RoleScope.APPLICATION, application_id=app.id)

    store.set_role_permissions(viewer.id, {"tickets.read", "reports.view"})
    store.set_role_permissions(
        agent.id, {"tickets.read", "tickets.create", "tickets.assign", "tickets.close"}
    )
    store.set_role_permissions(
        manager.id,
        {"tickets.read", "tickets.assign", "tickets.close", "tickets.delete", "reports.view"},
    )

    alice, _ = store.upsert_user_from_identity(
        provider="generic_oidc", issuer="https://idp", subject="alice", email="alice@acme.com",
        external_tenant_id=None,
    )
    bob, _ = store.upsert_user_from_identity(
        provider="generic_oidc", issuer="https://idp", subject="bob", email="bob@acme.com",
        external_tenant_id=None,
    )
    carol, _ = store.upsert_user_from_identity(
        provider="generic_oidc", issuer="https://idp", subject="carol", email="carol@acme.com",
        external_tenant_id=None,
    )

    store.create_membership(tenant_id=tenant.id, application_id=app.id, user_id=alice.id, roles={"viewer"})
    store.create_membership(tenant_id=tenant.id, application_id=app.id, user_id=bob.id, roles={"agent"})
    # Carol holds both roles — her permission set is the union.
    carol_membership = store.create_membership(
        tenant_id=tenant.id, application_id=app.id, user_id=carol.id, roles={"agent", "manager"}
    )

    engine = AuthorizationEngine(store)

    def show(name: str, user_id: str) -> None:
        perms = engine.effective_permissions(
            tenant_id=tenant.id, application_id=app.id,
            subject=Subject(type="user", user_id=user_id),
        )
        print(f"{name:<6}: {sorted(perms)}")

    print("Initial effective permissions:")
    show("alice", alice.id)
    show("bob", bob.id)
    show("carol", carol.id)

    # Try a few actions for Bob.
    print("\nBob's checks:")
    for resource, action in [("tickets", "create"), ("tickets", "delete"), ("reports", "view")]:
        decision = engine.authorize(
            AuthorizeRequest(
                tenant_id=tenant.id, application_id=app.id,
                subject=Subject(type="user", user_id=bob.id),
                resource=resource, action=action,
            )
        )
        verdict = "ALLOW" if decision.allowed else f"DENY ({decision.reason})"
        print(f"  {resource}.{action:<8} -> {verdict}")

    # Promote Carol — drop the agent role, leave manager only.
    print("\nDemoting Carol from agent+manager to manager only...")
    store.set_membership_roles(carol_membership.id, {"manager"})
    show("carol", carol.id)


if __name__ == "__main__":
    main()
