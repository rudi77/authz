# Agents

Agent authorization is the platform's headline feature. Every other
PDP can do RBAC; this one knows that an agent acting on behalf of a
user must never get more permission than that user.

## The intersection rule

When the subject is an agent, the engine resolves:

```
effective_permissions = user_perms ∩ agent_perms ∩ tenant_mask
```

In words: the agent only gets the permissions held by **both**
the human user and the agent role. If the user has `contracts.read`
but the agent role doesn't, the agent can't read. If the agent role
has `mcp.github.create_issue` but the user can't issue, the agent
can't either.

This is the property that makes prompt-injected tool calls tractable.
The blast radius of "the agent went rogue" is bounded by what its
operating user could already do directly.

## Agent registry

Agents are registered against `(tenant, application)`:

```python
agent = store.create_agent(
    tenant_id=tenant.id,
    application_id=app.id,
    name="Contract Analyzer",
    role="contract_analyzer",
    created_by_user_id=user.id,
)
store.set_agent_roles(agent.id, {"contract_analyzer"})
```

Or via the admin SDK:

```python
agent = admin.create_agent(
    tenant_id, application_id,
    name="Contract Analyzer",
    role="contract_analyzer",
)
admin.set_agent_roles(agent.id, ["contract_analyzer"])
```

The `role` field on the agent is informational (used by the admin UI);
the actual role binding is via `set_agent_roles`. Agent roles should
have `scope=RoleScope.AGENT` so admins don't accidentally assign them
to humans.

## AgentContext

The runtime carries an `AgentContext` that bundles the user identity,
agent identity, and the precomputed effective permissions:

```python
from authzkit.agents.models import AgentContext

ctx = AgentContext(
    tenant_id=tenant.id,
    application_id=app.id,
    user_id=user.id,
    user_roles=frozenset(user_ctx.roles),
    user_permissions=frozenset(user_ctx.permissions),
    agent_id=agent.id,
    agent_role="contract_analyzer",
    agent_permissions=frozenset(agent_perms),
    effective_permissions=frozenset(effective),
)
```

The `effective_permissions` field is what `AgentGuard` uses for local
checks. Compute it once at the start of the run; reuse for every
subsequent tool call.

## AgentGuard

The in-process gate for tool calls during an agent run:

```python
from authzkit import AgentGuard, PermissionDeniedError

guard = AgentGuard(ctx)

guard.require("contracts", "read")            # raises if denied
allowed = guard.is_allowed("mcp.github", "create_issue")  # bool
```

`require()` raises `PermissionDeniedError` on miss. Catch it in the
agent loop and surface it back to the LLM as "tool call denied" so the
model can choose another path.

### Critical actions and revalidation

For high-stakes actions you don't want decided from a stale snapshot,
opt in to a revalidation hook:

```python
def revalidate(ctx, resource, action):
    return authz_client.authorize(
        tenant_id=ctx.tenant_id,
        application_id=ctx.application_id,
        subject=Subject(type="agent", user_id=ctx.user_id, agent_id=ctx.agent_id),
        resource=resource, action=action,
    )

guard = AgentGuard(
    ctx,
    critical_actions={"tools.gmail.send", "mcp.github.delete_repo"},
    revalidate=revalidate,
)
guard.require("tools.gmail", "send")            # local + remote check
guard.require("docs", "read")                   # local only
guard.require("docs", "read", critical=True)    # force a remote check
```

The hook is called *after* the local check passes. If the remote
check fails, the guard raises `PermissionDeniedError`. This protects
against the case where a long-running agent's snapshot has gone stale
because an admin revoked the role mid-run.

## Starting an agent session

The SDK bundles preload + guard creation:

```python
from authz_sdk.agent_session import start_agent_session

guard = start_agent_session(
    authz_client,
    tenant_id=tenant_id,
    application_id=app_id,
    user_id=user_id,
    agent_id=agent_id,
    critical_actions={"tools.gmail.send"},
)

guard.require("mcp.github", "read_repo")  # local
guard.require("tools.gmail", "send", critical=True)  # remote revalidate
```

Behind the scenes:

1. `client.get_effective_permissions(...)` fetches the snapshot.
2. An `AgentGuard` is built around the snapshot.
3. Critical actions point at `client.authorize(...)` for revalidation.

`start_agent_session` is the integration point most agent runtimes
hook in to. It's a single function call wrapping the four-step pattern
the spec describes (resolve → preload → guard → enforce).

## Bulk authorize for tool catalogs

Before the LLM sees the tool list, filter it:

```python
from authzkit.rbac.checker import BulkAuthorizeRequest

decisions = engine.bulk_authorize(BulkAuthorizeRequest(
    tenant_id=tenant_id, application_id=application_id,
    subject=Subject(type="agent", user_id=user_id, agent_id=agent_id),
    checks=[("tools.gmail", "send"), ("mcp.github", "create_issue"), ...],
))
allowed = [d.required_permission for d in decisions if d.allowed]
```

`bulk_authorize` resolves the subject set once, so the cost is the
same as a single `authorize`. Don't loop `authorize` for this; you'll
do N round-trips.

## Common patterns

### Agent that escalates to user

If the agent hits a tool it can't call, surface it to the user for
approval. The user's `authorize` call uses `Subject(type="user", ...)`
and follows the user-only intersection rule (no agent mask).

### Two agents on the same user

Each agent has its own role list; they intersect independently with
the user's permissions. There's no "agent of agent" path — an agent
can't delegate to another agent and bypass the user.

### Time-bounded permissions

Use ABAC for "this permission is only valid during business hours"
rather than encoding it into roles. See [Policies](policies.md).

## See also

- [examples/04_agent_workflow.py](../examples/04_agent_workflow.py)
- [Tools & MCP](tools-and-mcp.md) — what to do with the guard once you have it
- [Concepts: decision algorithm](concepts.md#decision-algorithm) — the
  exact intersection math
