"""Bulk authorize: the hot path used during agent runs.

``bulk_authorize`` resolves the subject's permission set *once* and reuses
it for N checks. For an agent runtime asking "of these 30 candidate tools,
which ones may this agent call right now?" it's the difference between
30 DB hits and 1.

Demonstrates:
- A shared subject + a list of (resource, action) pairs
- Mixed allow / deny / tenant_feature_disabled / missing_permission outcomes
- Using the result to pre-filter the agent's tool catalog before LLM dispatch

Run with::

    python examples/07_bulk_authorize.py
"""

from __future__ import annotations

from authzkit import AuthorizationEngine, Subject
from authzkit.rbac.checker import BulkAuthorizeRequest
from authzkit.rbac.models import RoleScope
from authzkit.storage.memory import InMemoryStore


def main() -> None:
    store = InMemoryStore()
    tenant = store.create_tenant(slug="acme", name="ACME")
    app = store.create_application(slug="ops-agent", name="Ops Agent")

    catalog_perms = [
        "tools.gmail.read",
        "tools.gmail.send",
        "tools.calendar.read",
        "tools.calendar.create_event",
        "mcp.github.read_repo",
        "mcp.github.create_issue",
        "mcp.github.delete_repo",
        "mcp.slack.post_message",
    ]
    for name in catalog_perms:
        store.create_permission(name=name, application_id=app.id)

    user_role = store.create_role(name="ops_user", scope=RoleScope.APPLICATION, application_id=app.id)
    store.set_role_permissions(
        user_role.id,
        {
            "tools.gmail.read", "tools.gmail.send",
            "tools.calendar.read", "tools.calendar.create_event",
            "mcp.github.read_repo", "mcp.github.create_issue",
            "mcp.slack.post_message",
        },
    )
    agent_role = store.create_role(name="ops_agent", scope=RoleScope.AGENT, application_id=app.id)
    store.set_role_permissions(
        agent_role.id,
        {
            "tools.gmail.read",
            "tools.calendar.read", "tools.calendar.create_event",
            "mcp.github.read_repo", "mcp.github.create_issue",
            "mcp.slack.post_message",
        },
    )

    user, _ = store.upsert_user_from_identity(
        provider="generic_oidc", issuer="https://idp", subject="ops",
        email="ops@acme.com", external_tenant_id=None,
    )
    store.create_membership(
        tenant_id=tenant.id, application_id=app.id, user_id=user.id, roles={"ops_user"},
    )
    agent = store.create_agent(
        tenant_id=tenant.id, application_id=app.id, name="Ops Bot", role="ops_agent",
    )
    store.set_agent_roles(agent.id, {"ops_agent"})

    # Tenant disabled the deletion path entirely.
    store.set_tenant_permission_mask(
        tenant_id=tenant.id, application_id=app.id,
        permissions={p for p in catalog_perms if p != "mcp.github.delete_repo"},
    )

    engine = AuthorizationEngine(store)

    checks = [(p.rsplit(".", 1)[0], p.rsplit(".", 1)[1]) for p in catalog_perms]
    request = BulkAuthorizeRequest(
        tenant_id=tenant.id, application_id=app.id,
        subject=Subject(type="agent", user_id=user.id, agent_id=agent.id),
        checks=checks,
    )

    decisions = engine.bulk_authorize(request)

    print(f"{'permission':<32} {'verdict':<6}  reason")
    print("-" * 70)
    for d in decisions:
        verdict = "ALLOW" if d.allowed else "DENY"
        print(f"{d.required_permission:<32} {verdict:<6}  {d.reason}")

    allowed = [d.required_permission for d in decisions if d.allowed]
    print(f"\nThe agent may call {len(allowed)}/{len(decisions)} tools "
          f"in this session: {allowed}")


if __name__ == "__main__":
    main()
