# Tools & MCP

Once an agent (or any subject) has a permission set, you need to gate
each tool call against it. This is what `ToolGuard` and `MCPGuard` do.

## ToolGuard

Generic gate for application-scoped tools. The permission convention
is `tools.<name>.<action>`:

```python
from authz_sdk import ToolGuard, PermissionDeniedError

guard = ToolGuard({
    "tools.gmail.read",
    "tools.calendar.read",
    "tools.calendar.create_event",
})

guard.is_allowed("tools.gmail", "read")       # True
guard.is_allowed("tools.gmail", "send")       # False

try:
    guard.require("tools.gmail", "send")
except PermissionDeniedError as e:
    print(e.permission)  # "tools.gmail.send"

palette = guard.filter_allowed([
    ("tools.gmail", "read"),
    ("tools.gmail", "send"),
    ("tools.calendar", "create_event"),
])
# [("tools.gmail", "read"), ("tools.calendar", "create_event")]
```

`ToolGuard` is namespace-agnostic. The first argument to `require`/
`is_allowed` is the resource string — whatever shape your permissions
take. It doesn't have to start with `tools.`; we just suggest that
convention.

## MCPGuard

Same idea, but MCP-aware. MCP tools live under `mcp.<server>.<action>`
and `MCPGuard` folds the `mcp.` prefix into the check so callers pass
plain `(server, action)` pairs:

```python
from authz_sdk import MCPGuard

mcp = MCPGuard({
    "mcp.github.read_repo",
    "mcp.github.list_issues",
    "mcp.slack.post_message",
})

mcp.is_allowed("github", "read_repo")        # True
mcp.is_allowed("github", "delete_repo")      # False
mcp.allowed_tools("github")                   # ["list_issues", "read_repo"]
```

`allowed_tools(server)` is what you call when you build the per-session
MCP tool descriptor list to send back to the LLM. Filter once, and the
model literally cannot ask for tools it isn't allowed to invoke.

## How to feed the guard

The guard's permission set is just an `Iterable[str]`. Three sources:

### 1. Engine in-process

Library form, no service:

```python
perms = engine.effective_permissions(
    tenant_id=tenant.id, application_id=app.id,
    subject=Subject(type="agent", user_id=user.id, agent_id=agent.id),
)
guard = ToolGuard(perms)
```

### 2. SDK against the service

```python
perms = client.get_effective_permissions(
    tenant_id=tenant_id, application_id=application_id,
    subject=Subject(type="agent", user_id=user_id, agent_id=agent_id),
)
guard = ToolGuard(perms)
```

`get_effective_permissions` honors a TTL cache when you constructed
the client with `cache_ttl_seconds > 0`. Useful for chatty agent runs
where re-fetching every step would dominate latency.

### 3. Bulk pre-check at session start

```python
decisions = client.bulk_authorize(
    tenant_id=tenant_id, application_id=application_id,
    subject=Subject(type="agent", user_id=user_id, agent_id=agent_id),
    checks=[BulkCheck("tools.gmail", "send"), BulkCheck("mcp.github", "create_issue")],
)
allowed_perms = {f"{d.resource}.{d.action}" for d in decisions if d.allowed}
guard = ToolGuard(allowed_perms)
```

Bulk authorize is the right choice when you have a fixed catalog you
want to filter once.

## Stale snapshots and revalidation

The guard is a snapshot. If the user's role changes mid-session, the
snapshot lies. Two mitigations:

- For agent runs, use `AgentGuard(critical_actions=..., revalidate=...)`
  to opt high-stakes actions into a remote re-check (see [Agents](agents.md)).
- Limit snapshot lifetime. The SDK's TTL cache defaults to 0 (no
  caching); set it to e.g. 300s for ~5-minute freshness.

## Pattern: per-route guard in your tool runtime

The shape every agent runtime ends up with:

```python
def call_tool(server: str, name: str, args: dict) -> dict:
    mcp_guard.require(server, name)            # raises 403 on miss
    return tool_registry[server][name](**args)
```

The guard is the only authz line in the runtime. Everything else
(role math, tenant masks, ABAC) was already done by the engine. The
runtime stays ignorant of the policy model — its only job is "is this
permission in my snapshot?"

## See also

- [examples/05_tool_and_mcp_guards.py](../examples/05_tool_and_mcp_guards.py)
- [Agents](agents.md) — how to compose `AgentGuard` with `ToolGuard`/`MCPGuard`
- [Concepts: permission naming](concepts.md#permission-naming)
