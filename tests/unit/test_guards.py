"""Tests for ToolGuard, MCPGuard, and AgentGuard."""

import pytest

from authzkit.agents.guard import AgentGuard
from authzkit.agents.models import AgentContext
from authzkit.exceptions import PermissionDeniedError
from authzkit.mcp.guard import MCPGuard
from authzkit.tools.guard import ToolGuard


def test_tool_guard_allows_known_permission():
    g = ToolGuard({"tools.gmail.send", "tools.gmail.read"})
    assert g.is_allowed("tools.gmail", "send")
    g.require("tools.gmail", "send")


def test_tool_guard_blocks_unknown_permission():
    g = ToolGuard({"tools.gmail.read"})
    with pytest.raises(PermissionDeniedError) as exc:
        g.require("tools.gmail", "send")
    assert exc.value.permission == "tools.gmail.send"


def test_mcp_guard_namespace():
    g = MCPGuard({"mcp.github.create_issue", "mcp.github.read_repo"})
    assert g.is_allowed("github", "create_issue")
    assert not g.is_allowed("github", "delete_repo")
    assert sorted(g.allowed_tools("github")) == ["create_issue", "read_repo"]


def test_agent_guard_revalidates_critical_actions():
    calls = []

    def revalidate(_ctx, resource, action):
        calls.append((resource, action))
        return False

    ctx = AgentContext(
        tenant_id="t",
        application_id="a",
        user_id="u",
        user_roles=frozenset(),
        user_permissions=frozenset(),
        agent_id="agent",
        agent_role="r",
        agent_permissions=frozenset(),
        effective_permissions=frozenset({"tools.gmail.send"}),
    )
    guard = AgentGuard(
        ctx,
        critical_actions={"tools.gmail.send"},
        revalidate=revalidate,
    )
    with pytest.raises(PermissionDeniedError):
        guard.require("tools.gmail", "send")
    assert calls == [("tools.gmail", "send")]
