"""End-to-end AuthorizationEngine tests using the in-memory store."""

from authzkit.rbac.checker import (
    AuthorizationEngine,
    AuthorizeRequest,
    BulkAuthorizeRequest,
    Subject,
)
from authzkit.rbac.models import RoleScope
from authzkit.storage.memory import InMemoryStore


def _seed():
    store = InMemoryStore()
    tenant = store.create_tenant(slug="acme", name="ACME")
    app = store.create_application(slug="contract-ai", name="Contract AI")

    perms = [
        "contracts.read",
        "contracts.review",
        "contracts.classify",
        "mcp.github.read_repo",
        "mcp.github.create_issue",
    ]
    for p in perms:
        store.create_permission(name=p, application_id=app.id)

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

    user, _ = store.upsert_user_from_identity(
        provider="azure_entra",
        issuer="https://login.example",
        subject="oid-1",
        email="alice@acme.com",
        external_tenant_id="ext-1",
    )
    store.create_membership(
        tenant_id=tenant.id,
        application_id=app.id,
        user_id=user.id,
        roles={"legal_reviewer"},
    )

    agent = store.create_agent(
        tenant_id=tenant.id,
        application_id=app.id,
        name="Contract Analyzer",
        role="contract_analysis_agent",
    )
    store.set_agent_roles(agent.id, {"contract_analysis_agent"})

    return store, tenant, app, user, agent


def test_user_allowed_when_permission_present():
    store, tenant, app, user, _ = _seed()
    engine = AuthorizationEngine(store)
    decision = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="user", user_id=user.id),
            resource="contracts",
            action="review",
        )
    )
    assert decision.allowed
    assert decision.reason == "permission_granted"


def test_user_denied_when_permission_missing():
    store, tenant, app, user, _ = _seed()
    engine = AuthorizationEngine(store)
    decision = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="user", user_id=user.id),
            resource="contracts",
            action="classify",
        )
    )
    assert not decision.allowed
    assert decision.reason == "missing_permission"


def test_agent_intersected_with_user_permissions():
    """User can read+review; agent can read+classify+create_issue. Intersect."""
    store, tenant, app, user, agent = _seed()
    engine = AuthorizationEngine(store)
    # contracts.read is in both -> allow
    d = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="agent", user_id=user.id, agent_id=agent.id),
            resource="contracts",
            action="read",
        )
    )
    assert d.allowed

    # contracts.classify only in agent set -> deny because user lacks it
    d = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="agent", user_id=user.id, agent_id=agent.id),
            resource="contracts",
            action="classify",
        )
    )
    assert not d.allowed
    assert d.reason == "missing_permission"


def test_agent_denied_when_inactive():
    store, tenant, app, user, agent = _seed()
    # Replace agent with disabled status
    from dataclasses import replace
    store.agents[agent.id] = replace(store.agents[agent.id], status="disabled")
    engine = AuthorizationEngine(store)
    d = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="agent", user_id=user.id, agent_id=agent.id),
            resource="contracts",
            action="read",
        )
    )
    assert not d.allowed
    assert d.reason == "agent_not_active"


def test_tenant_feature_mask_blocks_action():
    store, tenant, app, user, _ = _seed()
    # Limit tenant to read-only; review now blocked.
    store.set_tenant_permission_mask(
        tenant_id=tenant.id, application_id=app.id, permissions={"contracts.read"}
    )
    engine = AuthorizationEngine(store)
    d = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="user", user_id=user.id),
            resource="contracts",
            action="review",
        )
    )
    assert not d.allowed
    assert d.reason == "tenant_feature_disabled"


def test_no_active_membership():
    store = InMemoryStore()
    tenant = store.create_tenant(slug="t", name="t")
    app = store.create_application(slug="a", name="a")
    engine = AuthorizationEngine(store)
    d = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="user", user_id="nonexistent"),
            resource="x",
            action="y",
        )
    )
    assert not d.allowed
    assert d.reason == "no_active_membership"


def test_bulk_authorize_returns_decision_per_check():
    store, tenant, app, user, _ = _seed()
    engine = AuthorizationEngine(store)
    decisions = engine.bulk_authorize(
        BulkAuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="user", user_id=user.id),
            checks=[
                ("contracts", "read"),
                ("contracts", "classify"),
                ("contracts", "review"),
            ],
        )
    )
    assert [d.allowed for d in decisions] == [True, False, True]


def test_effective_permissions_intersect_for_agent():
    store, tenant, app, user, agent = _seed()
    engine = AuthorizationEngine(store)
    perms = engine.effective_permissions(
        tenant_id=tenant.id,
        application_id=app.id,
        subject=Subject(type="agent", user_id=user.id, agent_id=agent.id),
    )
    # Only the intersection of user (review,read,read_repo) and agent
    # (read,classify,read_repo,create_issue) survives.
    assert perms == {"contracts.read", "mcp.github.read_repo"}


def test_invalid_subject_denied():
    store, tenant, app, _, _ = _seed()
    engine = AuthorizationEngine(store)
    d = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="user"),  # missing user_id
            resource="contracts",
            action="read",
        )
    )
    assert not d.allowed


def test_inactive_tenant_denied():
    from dataclasses import replace
    store, tenant, app, user, _ = _seed()
    store.tenants[tenant.id] = replace(store.tenants[tenant.id], status="suspended")
    engine = AuthorizationEngine(store)
    d = engine.authorize(
        AuthorizeRequest(
            tenant_id=tenant.id,
            application_id=app.id,
            subject=Subject(type="user", user_id=user.id),
            resource="contracts",
            action="read",
        )
    )
    assert not d.allowed
    assert d.reason == "tenant_not_active"
