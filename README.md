# authz — Multi-Tenant Authorization Platform

Reusable authorization library and standalone Authorization Service for
multi-tenant SaaS apps, AI agents, and MCP tool runtimes. Implements the
spec in [`docs/spec.md`](docs/spec.md) — RBAC with optional ABAC, multi-tenant
identity normalization, and agent-aware permission intersection.

The platform answers questions like:

- *Darf user_123 in tenant_abc `contracts.review` ausführen?*
- *Darf agent_456 für user_123 `mcp.github.create_issue` ausführen?*
- *Welche Tools darf dieser Agent in dieser Session aufrufen?*

It does **not** authenticate users (that's your IdP) and it does **not**
execute tools (that's your runtime). It is a Policy Decision Point. Apps,
agent runtimes, and tool guards remain the Policy Enforcement Points.

## Repository layout

```
authzkit/        Reusable Python core library
  identity/      OIDC claim normalizers + JWT validator (Entra, Cognito, GCP, generic)
  tenancy/       Tenants, applications, users, memberships
  rbac/          Roles, permissions, AuthorizationEngine
  agents/        Agent context + AgentGuard
  tools/         ToolGuard for agent tool calls
  mcp/           MCPGuard for MCP tool calls
  policies/      Optional ABAC engine
  storage/       In-memory + SQLAlchemy/Postgres backends
  service/       Pydantic schemas shared with SDKs
  audit/         Audit logging primitives

authz_service/   FastAPI Authorization Service
  api/           REST routers
  middleware.py  Rate limit + idempotency middleware
  observability.py  structlog, Prometheus, optional OTel
  cli.py         `authz` CLI (schema, bootstrap, inspect)
  main.py        App factory + uvicorn entry point

authz_sdk/       Python SDK (AuthzClient + AuthzAdminClient + helpers)
sdks/go/         Go SDK (AuthzClient + AdminClient + ToolGuard/MCPGuard)
sdks/typescript/ TypeScript SDK (same surface, ESM, fetch-based)

migrations/      Alembic migrations (Postgres)
examples/        End-to-end usage demos
tests/           Unit + integration tests (pytest)
```

## Quick start (local, no Postgres)

```bash
pip install -e .[dev]
python examples/contract_ai_agent.py    # in-memory end-to-end demo
pytest                                    # 69 tests, ~6s
```

## CLI

```bash
# 1. Migrate schema (Postgres)
AUTHZ_DATABASE_URL=postgresql+psycopg://… authz schema upgrade

# 2. Seed a tenant + application + roles from a YAML/JSON spec
AUTHZ_BASE_URL=http://localhost:8080 AUTHZ_API_KEY=dev-key \
    authz bootstrap --spec examples/bootstrap.example.yaml

# 3. Sanity-check
authz inspect health
authz inspect decision --tenant-id … --application-id … \
    --user-id … --resource contracts --action review
```

## Running the service

### Docker

```bash
docker compose up --build
# service on http://localhost:8080
# api key: dev-key
```

### From source

```bash
pip install -e .
export AUTHZ_DATABASE_URL=postgresql+psycopg://authz:authz@localhost:5432/authz
export AUTHZ_API_KEYS=dev-key
alembic upgrade head
authz-service                            # uvicorn on :8080
```

OpenAPI docs are auto-generated at `http://localhost:8080/docs`.

## Configuration

Environment variables consumed by the service:

| Variable | Default | Purpose |
|----------|---------|---------|
| `AUTHZ_DATABASE_URL` | `sqlite+pysqlite:///./authz.db` | SQLAlchemy URL (Postgres in prod) |
| `AUTHZ_API_KEYS` | *(empty)* | Comma-separated API keys; empty = dev mode |
| `AUTHZ_LOG_LEVEL` | `INFO` | Python log level |
| `AUTHZ_AUDIT_ALL` | `false` | Audit allows in addition to denies |
| `AUTHZ_AUTO_PROVISION_USER` | `true` | Create users on first `resolve-context` |
| `AUTHZ_AUTO_PROVISION_TENANT` | `false` | Allow self-service tenant creation |

## Endpoint overview

Runtime (PEPs hit these from every request):

- `POST /v1/resolve-context` — IdentityPrincipal → UserContext
- `POST /v1/authorize` — single allow/deny decision
- `POST /v1/bulk-authorize` — many decisions in one round-trip
- `POST /v1/effective-permissions` — preload set for a session/agent run

Management (admin tools, used at provisioning time):

- `POST /v1/tenants`, `GET /v1/tenants/{id}`
- `POST /v1/tenants/{id}/mappings` — map external IdP tenant → internal
- `PUT /v1/tenants/{id}/feature-flags`
- `POST /v1/applications`, `GET /v1/applications/{id}`
- `POST /v1/applications/{id}/roles`
- `POST /v1/applications/{id}/permissions`
- `PUT /v1/roles/{id}/permissions`
- `POST /v1/tenants/{tid}/memberships`, `PATCH /v1/memberships/{id}`
- `POST /v1/tenants/{tid}/applications/{aid}/agents`
- `PUT /v1/agents/{id}/roles`

All endpoints require the `X-API-Key` header (or `Authorization: Bearer <key>`)
unless `AUTHZ_API_KEYS` is empty (dev mode).

## Python SDK

```python
from authz_sdk import AuthzClient, Subject, BulkCheck, ToolGuard, MCPGuard

with AuthzClient("https://authz.example.com", api_key="…", cache_ttl_seconds=300) as authz:
    # Single check
    authz.require(
        tenant_id="tenant_123",
        application_id="contract-ai",
        subject=Subject(type="user", user_id="user_456"),
        resource="contracts",
        action="review",
    )

    # Agent run: preload then enforce locally
    perms = authz.get_effective_permissions(
        tenant_id="tenant_123",
        application_id="agent-platform",
        subject=Subject(type="agent", user_id="user_456", agent_id="agent_789"),
    )
    tool_guard = ToolGuard(perms)
    mcp_guard = MCPGuard(perms)

    tool_guard.require("tools.gmail", "read")
    mcp_guard.require("github", "create_issue")
```

For agent runtimes, `start_agent_session` bundles the preload + revalidation
hook for critical actions:

```python
from authz_sdk.agent_session import start_agent_session

guard = start_agent_session(
    authz,
    tenant_id=tenant_id,
    application_id=app_id,
    user_id=user_id,
    agent_id=agent_id,
    critical_actions={"tools.gmail.send", "mcp.github.delete_repo"},
)
guard.require("mcp.github", "read_repo")          # local check
guard.require("tools.gmail", "send", critical=True)  # remote revalidation
```

## Authorization model

Permissions follow `<resource>.<action>` (or namespaced
`<namespace>.<resource>.<action>` such as `mcp.github.create_issue`).

The engine intersects the relevant sets so the resulting decision satisfies
all of:

- **User permissions** — from active memberships and their roles
- **Agent permissions** — from agent roles (if subject is an agent)
- **Tenant permissions** — feature-driven masks (skipped when empty)
- **ABAC conditions** — optional rules in `policies` table

> An agent never receives more permission than the acting user.

## Domain coverage

The MVP covers spec sections 19.1 + 24:

- Tenant and application registry
- User identity normalization (Entra, Cognito, GCP, generic OIDC)
- External-tenant → internal-tenant mapping
- Memberships with multi-role assignment
- Roles scoped at platform / application / tenant / agent levels
- Permissions catalog per application
- Agent registry with agent-role assignment
- Tenant feature flags + tenant permission masks
- Bulk authorization for hot-path agent runs
- Audit logging (denies always, allows opt-in via `AUTHZ_AUDIT_ALL`)
- ABAC condition evaluation (eq/ne/lt/lte/gt/gte/in/not_in/and/or/not)

Out-of-scope items per the spec stay out: no auth/login flow, no token
storage, no tool execution, no admin UI in MVP.

## Testing

```bash
pytest -q              # runs all 45 tests in <3s using SQLite
pytest tests/unit -q   # core library only (no DB)
```

The integration tests use `fastapi.testclient.TestClient` driving the SDK in
process, so no external services are needed.

## License

Apache-2.0
