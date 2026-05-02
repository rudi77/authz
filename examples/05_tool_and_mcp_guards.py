"""ToolGuard + MCPGuard: in-process enforcement at the tool-call site.

After ``effective_permissions`` is preloaded once, every subsequent tool
invocation is a local set-membership check — no remote round-trip. This
is the pattern an agent runtime uses inside its tool-execution loop.

Demonstrates:
- ``ToolGuard`` for application-scoped tools (``tools.<name>``)
- ``MCPGuard`` for MCP servers (``mcp.<server>.<tool>``) which folds the
  ``mcp.`` namespace into the check so callers pass ``(server, action)``
- ``filter_allowed`` and ``allowed_tools`` for advertising a per-session
  tool catalog to the LLM

Run with::

    python examples/05_tool_and_mcp_guards.py
"""

from __future__ import annotations

from authzkit import MCPGuard, PermissionDeniedError, ToolGuard


def main() -> None:
    # In production these come from /v1/effective-permissions or the
    # AuthorizationEngine. Here we hardcode a representative set.
    permissions = {
        "tools.gmail.read",
        "tools.calendar.read",
        "tools.calendar.create_event",
        "mcp.github.read_repo",
        "mcp.github.list_issues",
        "mcp.slack.post_message",
    }

    tool_guard = ToolGuard(permissions)
    mcp_guard = MCPGuard(permissions)

    print("ToolGuard checks:")
    for resource, action in [
        ("tools.gmail", "read"),
        ("tools.gmail", "send"),
        ("tools.calendar", "create_event"),
    ]:
        allowed = tool_guard.is_allowed(resource, action)
        print(f"  {resource}.{action:<14} -> {'ALLOW' if allowed else 'DENY '}")

    # ``require`` raises instead of returning a bool — pair with try/except
    # to bubble a 403 from your tool handler.
    try:
        tool_guard.require("tools.gmail", "send")
    except PermissionDeniedError as e:
        print(f"  raise -> {e.permission}")

    # ``filter_allowed`` is handy for "what can I show in the tool palette?".
    palette = tool_guard.filter_allowed(
        [
            ("tools.gmail", "read"),
            ("tools.gmail", "send"),
            ("tools.calendar", "read"),
            ("tools.calendar", "delete"),
        ]
    )
    print("  visible tools:", palette)

    print("\nMCPGuard checks (note plain (server, action) signature):")
    for server, action in [
        ("github", "read_repo"),
        ("github", "delete_repo"),
        ("slack", "post_message"),
        ("notion", "query_db"),
    ]:
        allowed = mcp_guard.is_allowed(server, action)
        print(f"  mcp.{server}.{action:<14} -> {'ALLOW' if allowed else 'DENY '}")

    print(f"  github tools available: {sorted(mcp_guard.allowed_tools('github'))}")
    print(f"  slack tools available : {sorted(mcp_guard.allowed_tools('slack'))}")


if __name__ == "__main__":
    main()
