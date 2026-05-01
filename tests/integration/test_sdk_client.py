"""Tests for the Python SDK against the in-process FastAPI app."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from authz_sdk import AuthzClient, BulkCheck, MCPGuard, Subject, ToolGuard
from authz_sdk.agent_session import start_agent_session
from authzkit.exceptions import PermissionDeniedError
from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine


@pytest.fixture()
def sdk(temp_db_url) -> AuthzClient:
    override_settings(
        Settings(
            database_url=temp_db_url,
            api_keys=("k1",),
            log_level="WARNING",
            audit_all_decisions=False,
            auto_provision_user=True,
            auto_provision_tenant=False,
        )
    )
    reset_engine()
    from authz_service.main import create_app

    app = create_app()
    test_client = TestClient(app)
    return AuthzClient(
        base_url="http://testserver",
        api_key="k1",
        http_client=test_client,
        cache_ttl_seconds=60.0,
    )


def _seed(sdk_client: AuthzClient):
    raw = sdk_client._http
    tenant = raw.post("/v1/tenants", json={"slug": "t1", "name": "T1"}).json()
    app = raw.post(
        "/v1/applications", json={"slug": "agent-platform", "name": "Agent Platform"}
    ).json()
    for p in [
        "documents.read",
        "mcp.github.read_repo",
        "mcp.github.create_issue",
        "tools.gmail.send",
    ]:
        raw.post(f"/v1/applications/{app['id']}/permissions", json={"name": p})
    user_role = raw.post(
        f"/v1/applications/{app['id']}/roles",
        json={"name": "researcher", "scope": "application"},
    ).json()
    raw.put(
        f"/v1/roles/{user_role['id']}/permissions",
        json={"permissions": ["documents.read", "mcp.github.read_repo"]},
    )
    agent_role = raw.post(
        f"/v1/applications/{app['id']}/roles",
        json={"name": "research_agent", "scope": "agent"},
    ).json()
    raw.put(
        f"/v1/roles/{agent_role['id']}/permissions",
        json={
            "permissions": [
                "documents.read",
                "mcp.github.read_repo",
                "mcp.github.create_issue",
            ]
        },
    )

    from authzkit.storage.sqlalchemy import SqlAlchemyStore, create_engine_from_url
    from authz_service.config import get_settings

    store = SqlAlchemyStore(create_engine_from_url(get_settings().database_url))
    user, _ = store.upsert_user_from_identity(
        provider="azure_entra",
        issuer="iss",
        subject="sub",
        email=None,
        external_tenant_id=None,
    )
    raw.post(
        f"/v1/tenants/{tenant['id']}/memberships",
        json={
            "user_id": user.id,
            "application_id": app["id"],
            "roles": ["researcher"],
        },
    )
    agent = raw.post(
        f"/v1/tenants/{tenant['id']}/applications/{app['id']}/agents",
        json={"name": "Researcher", "role": "research_agent"},
    ).json()
    raw.put(f"/v1/agents/{agent['id']}/roles", json={"roles": ["research_agent"]})
    return tenant, app, user.id, agent["id"]


def test_sdk_authorize(sdk: AuthzClient):
    tenant, app, user_id, _ = _seed(sdk)
    assert sdk.authorize(
        tenant_id=tenant["id"],
        application_id=app["id"],
        subject=Subject(type="user", user_id=user_id),
        resource="documents",
        action="read",
    )


def test_sdk_require_raises_when_denied(sdk: AuthzClient):
    tenant, app, user_id, _ = _seed(sdk)
    with pytest.raises(PermissionDeniedError):
        sdk.require(
            tenant_id=tenant["id"],
            application_id=app["id"],
            subject=Subject(type="user", user_id=user_id),
            resource="tools.gmail",
            action="send",
        )


def test_sdk_bulk_authorize(sdk: AuthzClient):
    tenant, app, user_id, _ = _seed(sdk)
    results = sdk.bulk_authorize(
        tenant_id=tenant["id"],
        application_id=app["id"],
        subject=Subject(type="user", user_id=user_id),
        checks=[
            BulkCheck("documents", "read"),
            BulkCheck("tools.gmail", "send"),
        ],
    )
    assert results[0].allowed is True
    assert results[1].allowed is False


def test_sdk_effective_permissions_with_cache(sdk: AuthzClient):
    tenant, app, user_id, agent_id = _seed(sdk)
    perms = sdk.get_effective_permissions(
        tenant_id=tenant["id"],
        application_id=app["id"],
        subject=Subject(type="agent", user_id=user_id, agent_id=agent_id),
    )
    # User has documents.read + mcp.github.read_repo;
    # agent has those plus mcp.github.create_issue. Intersection wins.
    assert perms == {"documents.read", "mcp.github.read_repo"}


def test_agent_session_yields_working_guard(sdk: AuthzClient):
    tenant, app, user_id, agent_id = _seed(sdk)
    guard = start_agent_session(
        sdk,
        tenant_id=tenant["id"],
        application_id=app["id"],
        user_id=user_id,
        agent_id=agent_id,
    )
    guard.require("documents", "read")
    with pytest.raises(PermissionDeniedError):
        guard.require("mcp.github", "create_issue")


def test_local_tool_guard_against_preloaded_set():
    g = ToolGuard({"tools.gmail.read"})
    assert g.is_allowed("tools.gmail", "read")
    with pytest.raises(PermissionDeniedError):
        g.require("tools.gmail", "send")


def test_local_mcp_guard():
    g = MCPGuard({"mcp.github.read_repo"})
    assert g.is_allowed("github", "read_repo")
    assert not g.is_allowed("github", "create_issue")
