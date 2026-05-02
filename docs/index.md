# authz Documentation

A Policy Decision Point (PDP) for multi-tenant SaaS apps, AI agents, and
MCP tool runtimes. Answers questions like:

- *Is `user_123` in `tenant_acme` allowed to run `contracts.review`?*
- *Is `agent_456`, acting on behalf of `user_123`, allowed to call
  `mcp.github.create_issue`?*
- *Which tools may this agent call right now in this session?*

The platform does **not** authenticate end-users (your IdP does that)
and does **not** execute tools (your runtime does that). It is a decision
service. Apps, agent runtimes, and tool guards stay the policy
enforcement points.

## Where to start

| If you want to… | Read |
|------------------|------|
| Understand the model | [Concepts](concepts.md) |
| Run something in 60 seconds | [Getting Started](getting-started.md) |
| Wire up your IdP | [Identity & JWT](identity.md) |
| Define roles and permissions | [RBAC](rbac.md) |
| Protect an agent run | [Agents](agents.md) |
| Gate tool calls | [Tools & MCP](tools-and-mcp.md) |
| Add per-attribute rules | [ABAC Policies](policies.md) |
| Deploy the service | [Service & Deployment](service.md) |
| Use the Python SDK | [Python SDK](sdk-python.md) |
| Manage API keys | [API Keys](api-keys.md) |
| Operate it in production | [Operations](operations.md) |
| Understand the layout | [Architecture](architecture.md) |

## Layout

The repo splits into three Python packages and one HTTP service:

```
authzkit/        Reusable core library (PDP engine, identity, guards, storage)
authz_service/   FastAPI service that wraps authzkit
authz_sdk/       HTTP client for the service (sync, with caching)
sdks/{go,ts}/    Identical SDK surface in Go and TypeScript
```

Use `authzkit` directly when your app is Python and you want the engine
in-process. Use `authz_service` + an SDK when you have multiple apps
sharing one decision point, or you need a non-Python language.

## Quickstart

```bash
pip install -e .
python examples/01_quickstart_inmemory.py
```

…or stand up the service:

```bash
docker compose up --build
# http://localhost:8080/docs (OpenAPI)
# http://localhost:8080/admin (admin SPA)
# X-API-Key: dev-key
```

## Reference

- [Permission naming convention](concepts.md#permission-naming)
- [Decision algorithm](concepts.md#decision-algorithm)
- [Reason codes](concepts.md#reason-codes)
- [Endpoint catalog](service.md#endpoints)
- [Environment variables](service.md#environment-variables)
- [Examples index](../examples/README.md)
