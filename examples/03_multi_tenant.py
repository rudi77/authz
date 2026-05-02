"""Multi-tenant isolation: tenants, feature flags, permission masks.

Demonstrates:
- Two tenants sharing the same application but seeing different feature sets
- Tenant permission masks acting as a per-tenant feature toggle
- The distinct ``tenant_feature_disabled`` deny reason — the user has the
  permission via their role, but the tenant's feature mask blocks it
- Suspending a tenant immediately denies every check

Run with::

    python examples/03_multi_tenant.py
"""

from __future__ import annotations

from dataclasses import replace

from authzkit import AuthorizationEngine, AuthorizeRequest, Subject
from authzkit.rbac.models import RoleScope
from authzkit.storage.memory import InMemoryStore


def seed_tenant(store: InMemoryStore, slug: str, app_id: str, role_id: str) -> tuple[str, str]:
    """Create a tenant + a user with the shared role and return (tenant_id, user_id)."""
    tenant = store.create_tenant(slug=slug, name=slug.upper())
    user, _ = store.upsert_user_from_identity(
        provider="generic_oidc",
        issuer="https://idp",
        subject=f"user-{slug}",
        email=f"admin@{slug}.com",
        external_tenant_id=None,
    )
    store.create_membership(
        tenant_id=tenant.id, application_id=app_id, user_id=user.id, roles={"admin"}
    )
    return tenant.id, user.id


def main() -> None:
    store = InMemoryStore()
    app = store.create_application(slug="crm", name="CRM")

    permissions = [
        "leads.read",
        "leads.write",
        "ai.suggest",
        "ai.generate_email",
        "billing.export",
    ]
    for name in permissions:
        store.create_permission(name=name, application_id=app.id)

    admin = store.create_role(name="admin", scope=RoleScope.APPLICATION, application_id=app.id)
    store.set_role_permissions(admin.id, set(permissions))

    acme_tenant_id, acme_user_id = seed_tenant(store, "acme", app.id, admin.id)
    globex_tenant_id, globex_user_id = seed_tenant(store, "globex", app.id, admin.id)

    # ACME paid for the AI features; Globex didn't.
    store.set_tenant_permission_mask(
        tenant_id=acme_tenant_id,
        application_id=app.id,
        permissions={"leads.read", "leads.write", "ai.suggest", "ai.generate_email", "billing.export"},
    )
    store.set_tenant_permission_mask(
        tenant_id=globex_tenant_id,
        application_id=app.id,
        permissions={"leads.read", "leads.write", "billing.export"},
    )

    engine = AuthorizationEngine(store)

    def check(name: str, tenant_id: str, user_id: str) -> None:
        print(f"\n{name}:")
        for resource, action in [("leads", "write"), ("ai", "generate_email"), ("billing", "export")]:
            decision = engine.authorize(
                AuthorizeRequest(
                    tenant_id=tenant_id, application_id=app.id,
                    subject=Subject(type="user", user_id=user_id),
                    resource=resource, action=action,
                )
            )
            verdict = "ALLOW" if decision.allowed else f"DENY ({decision.reason})"
            print(f"  {resource}.{action:<14} -> {verdict}")

    check("ACME (paid plan)", acme_tenant_id, acme_user_id)
    check("Globex (basic plan)", globex_tenant_id, globex_user_id)

    # Suspend ACME — now everything denies with tenant_not_active.
    print("\nSuspending ACME...")
    store.tenants[acme_tenant_id] = replace(store.tenants[acme_tenant_id], status="suspended")
    check("ACME after suspension", acme_tenant_id, acme_user_id)


if __name__ == "__main__":
    main()
