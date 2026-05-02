"""Agent authorization: the user ∩ agent intersection rule.

Demonstrates the core agent-safety property of the authz model::

    effective = user_permissions ∩ agent_permissions  (∩ tenant mask)

An agent never gets more permission than the acting user, even if the
agent role grants it. This protects against an agent being prompted (or
fooled) into invoking tools the human user wouldn't be allowed to call.

Includes:
- A user with one role
- An agent with a *different* role (some overlap, some agent-only perms)
- The intersection visible in ``effective_permissions``
- ``AgentGuard`` enforcing the result locally

Run with::

    python examples/04_agent_workflow.py
"""

from __future__ import annotations

from authzkit import (
    AgentGuard,
    AuthorizationEngine,
    PermissionDeniedError,
    Subject,
)
from authzkit.agents.models import AgentContext
from authzkit.rbac.models import RoleScope
from authzkit.storage.memory import InMemoryStore


def main() -> None:
    store = InMemoryStore()
    tenant = store.create_tenant(slug="acme", name="ACME")
    app = store.create_application(slug="contract-ai", name="Contract AI")

    for name in [
        "contracts.read",
        "contracts.review",
        "contracts.classify",   # agent only
        "contracts.approve",    # human-only sign-off
        "mcp.github.read_repo",
        "mcp.github.create_issue",
    ]:
        store.create_permission(name=name, application_id=app.id)

    legal_reviewer = store.create_role(
        name="legal_reviewer", scope=RoleScope.APPLICATION, application_id=app.id,
    )
    store.set_role_permissions(
        legal_reviewer.id,
        {"contracts.read", "contracts.review", "contracts.approve", "mcp.github.read_repo"},
    )

    contract_analyzer = store.create_role(
        name="contract_analyzer", scope=RoleScope.AGENT, application_id=app.id,
    )
    store.set_role_permissions(
        contract_analyzer.id,
        {
            "contracts.read",
            "contracts.classify",     # agent has it, user doesn't
            "mcp.github.read_repo",
            "mcp.github.create_issue",  # agent has it, user doesn't
        },
    )

    user, _ = store.upsert_user_from_identity(
        provider="azure_entra", issuer="https://login.example", subject="alice-oid",
        email="alice@acme.com", external_tenant_id=None,
    )
    store.create_membership(
        tenant_id=tenant.id, application_id=app.id, user_id=user.id, roles={"legal_reviewer"},
    )
    agent = store.create_agent(
        tenant_id=tenant.id, application_id=app.id, name="Contract Analyzer",
        role="contract_analyzer", created_by_user_id=user.id,
    )
    store.set_agent_roles(agent.id, {"contract_analyzer"})

    engine = AuthorizationEngine(store)
    user_subject = Subject(type="user", user_id=user.id)
    agent_subject = Subject(type="agent", user_id=user.id, agent_id=agent.id)

    user_perms = engine.effective_permissions(
        tenant_id=tenant.id, application_id=app.id, subject=user_subject,
    )
    agent_perms = engine.effective_permissions(
        tenant_id=tenant.id, application_id=app.id, subject=agent_subject,
    )

    print("User permissions  :", sorted(user_perms))
    print("Agent permissions :", sorted(agent_perms))
    print("Intersection      :", sorted(user_perms & agent_perms))
    print()

    # Build an AgentGuard for the in-process tool-call hot path. Critical
    # actions can opt into a remote revalidation hook — useful when the
    # cached set might be stale by the time the agent fires the tool.
    revalidations: list[str] = []

    def revalidate(_ctx: AgentContext, resource: str, action: str) -> bool:
        revalidations.append(f"{resource}.{action}")
        # Re-run the engine here; in production this would be an HTTP call
        # to /v1/authorize. We approve unless the resource is "contracts".
        return True

    ctx = AgentContext(
        tenant_id=tenant.id, application_id=app.id, user_id=user.id,
        user_roles=frozenset({"legal_reviewer"}),
        user_permissions=frozenset(user_perms),
        agent_id=agent.id, agent_role="contract_analyzer",
        agent_permissions=frozenset(agent_perms),
        effective_permissions=frozenset(agent_perms),
    )
    guard = AgentGuard(
        ctx,
        critical_actions={"mcp.github.create_issue"},
        revalidate=revalidate,
    )

    print("AgentGuard checks:")
    for resource, action, critical in [
        ("contracts", "read", False),         # in both -> ALLOW
        ("contracts", "approve", False),      # user only, agent must NOT do it
        ("contracts", "classify", False),     # agent only, blocked by intersection
        ("mcp.github", "read_repo", False),   # in both
        ("mcp.github", "create_issue", True), # user lacks, blocked by intersection
    ]:
        try:
            guard.require(resource, action, critical=critical)
            print(f"  {resource}.{action:<13} -> ALLOW")
        except PermissionDeniedError as e:
            print(f"  {resource}.{action:<13} -> DENY ({e.permission})")

    print(f"\nRevalidations triggered: {revalidations}")


if __name__ == "__main__":
    main()
