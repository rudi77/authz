"""End-to-end example: contract analysis agent with multi-tenant authz.

Walks through the spec's section 21.1 flow against an in-memory store so the
example runs without a database. For a real deployment, swap ``InMemoryStore``
for ``SqlAlchemyStore`` and keep the rest of the code identical.

Run with: ``python examples/contract_ai_agent.py``
"""

from __future__ import annotations

from authzkit.agents.guard import AgentGuard
from authzkit.agents.models import AgentContext
from authzkit.exceptions import PermissionDeniedError
from authzkit.identity.azure_entra import normalize_entra
from authzkit.rbac.checker import (
    AuthorizationEngine,
    AuthorizeRequest,
    Subject,
)
from authzkit.rbac.models import RoleScope
from authzkit.rbac.resolver import PermissionResolver
from authzkit.storage.memory import InMemoryStore
from authzkit.tenancy.resolver import TenantContextResolver


def seed(store: InMemoryStore):
    tenant = store.create_tenant(slug="acme", name="ACME")
    app = store.create_application(slug="contract-ai", name="Contract AI")
    for name in [
        "contracts.read",
        "contracts.review",
        "contracts.classify",
        "contracts.approve",
        "mcp.github.read_repo",
        "mcp.github.create_issue",
    ]:
        store.create_permission(name=name, application_id=app.id)

    legal_reviewer = store.create_role(
        name="legal_reviewer",
        scope=RoleScope.APPLICATION,
        application_id=app.id,
    )
    store.set_role_permissions(
        legal_reviewer.id,
        {"contracts.read", "contracts.review", "mcp.github.read_repo"},
    )
    contract_agent_role = store.create_role(
        name="contract_analysis_agent",
        scope=RoleScope.AGENT,
        application_id=app.id,
    )
    store.set_role_permissions(
        contract_agent_role.id,
        {
            "contracts.read",
            "contracts.classify",
            "mcp.github.read_repo",
            "mcp.github.create_issue",
        },
    )
    store.create_tenant_identity_mapping(
        tenant_id=tenant.id,
        provider="azure_entra",
        issuer="https://login.microsoftonline.com/external/v2",
        external_tenant_id="ext-acme",
    )
    return tenant, app


def main() -> None:
    store = InMemoryStore()
    tenant, app = seed(store)

    # 1. Application validates a JWT and turns its claims into a principal.
    claims = {
        "iss": "https://login.microsoftonline.com/external/v2",
        "oid": "alice-oid",
        "tid": "ext-acme",
        "preferred_username": "alice@acme.com",
    }
    principal = normalize_entra(claims)
    print(f"[1] Principal: {principal.subject} from tenant {principal.external_tenant_id}")

    # 2. resolve-context: principal + application -> UserContext.
    resolver = TenantContextResolver(
        repository=store,
        permission_resolver=PermissionResolver(store),
    )
    # First time: provision user + membership manually (in production,
    # an admin invites the user and a membership pre-exists).
    user, _ = store.upsert_user_from_identity(
        provider=principal.provider,
        issuer=principal.issuer,
        subject=principal.subject,
        email=principal.email,
        external_tenant_id=principal.external_tenant_id,
    )
    store.create_membership(
        tenant_id=tenant.id,
        application_id=app.id,
        user_id=user.id,
        roles={"legal_reviewer"},
    )
    user_ctx = resolver.resolve(principal, application_slug="contract-ai")
    print(f"[2] UserContext: roles={sorted(user_ctx.roles)}")
    print(f"    permissions={sorted(user_ctx.permissions)}")

    # 3. Agent setup.
    agent = store.create_agent(
        tenant_id=tenant.id,
        application_id=app.id,
        name="Contract Analyzer",
        role="contract_analysis_agent",
    )
    store.set_agent_roles(agent.id, {"contract_analysis_agent"})

    engine = AuthorizationEngine(store)
    effective = engine.effective_permissions(
        tenant_id=tenant.id,
        application_id=app.id,
        subject=Subject(type="agent", user_id=user.id, agent_id=agent.id),
    )
    print(f"[3] Agent effective permissions: {sorted(effective)}")

    # 4. Agent run: build a guard and try a few tool calls.
    agent_ctx = AgentContext(
        tenant_id=tenant.id,
        application_id=app.id,
        user_id=user.id,
        user_roles=frozenset(user_ctx.roles),
        user_permissions=frozenset(user_ctx.permissions),
        agent_id=agent.id,
        agent_role="contract_analysis_agent",
        agent_permissions=frozenset(),
        effective_permissions=frozenset(effective),
    )
    guard = AgentGuard(agent_ctx)

    # Allowed: contracts.read in user ∩ agent ∩ tenant.
    guard.require("contracts", "read")
    print("[4] contracts.read allowed")

    # Denied: contracts.classify is in agent perms but NOT user perms.
    try:
        guard.require("contracts", "classify")
    except PermissionDeniedError as e:
        print(f"[4] contracts.classify denied as expected: {e.permission}")

    # Denied: mcp.github.create_issue allowed by agent role only — user lacks it.
    try:
        guard.require("mcp.github", "create_issue")
    except PermissionDeniedError as e:
        print(f"[4] mcp.github.create_issue denied as expected: {e.permission}")

    # Allowed: mcp.github.read_repo in both sets.
    decision = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="agent", user_id=user.id, agent_id=agent.id),
            resource="mcp.github",
            action="read_repo",
        )
    )
    print(f"[4] mcp.github.read_repo allowed={decision.allowed} reason={decision.reason}")


if __name__ == "__main__":
    main()
