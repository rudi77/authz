# authz — Multi-Tenant Authorization Platform

Reusable authorization library and standalone Authorization Service for
multi-tenant SaaS apps, AI agents, and MCP tool runtimes. RBAC with optional
ABAC, multi-tenant identity normalization, agent-aware permission
intersection, scoped API keys with rotation, invitation flow, audit
retention, Prometheus metrics, multi-process Redis backends, and SDKs for
Python / Go / TypeScript.

The platform answers questions like:

- *Darf user_123 in tenant_abc `contracts.review` ausführen?*
- *Darf agent_456 für user_123 `mcp.github.create_issue` ausführen?*
- *Welche Tools darf dieser Agent in dieser Session aufrufen?*

It does **not** authenticate users (that's your IdP) and it does **not**
execute tools (that's your runtime). It is a Policy Decision Point. Apps,
agent runtimes, and tool guards remain the Policy Enforcement Points.

## Status

**v0.2 — pilot-ready.** Core decision engine is correct and well-tested
(83 Python + 7 Go + 8 TS tests). Operational concerns (scoped API keys,
multi-process state, audit retention, observability, container hardening)
are in. Customer-readiness gaps remaining: load-tested production
deployment, SCIM, gRPC API, ReBAC, full admin console.

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

authzkit/security/  Scoped API keys + invitation flow

authz_service/   FastAPI Authorization Service
  api/           REST routers (incl. api_keys, invitations)
  middleware.py  Rate limit + idempotency (in-memory or Redis)
  observability.py  structlog, Prometheus, optional OTel
  audit_retention.py  Background pruning worker
  cli.py         `authz` CLI (schema, bootstrap, inspect)
  ui/            Static admin SPA served at /admin
  main.py        App factory + uvicorn entry point

authz_sdk/       Python SDK (AuthzClient + AuthzAdminClient + helpers)
sdks/go/         Go SDK (AuthzClient + AdminClient + ToolGuard/MCPGuard)
sdks/typescript/ TypeScript SDK (same surface, ESM, fetch-based)

migrations/      Alembic migrations (Postgres)
loadtests/       Locust + asyncio load-test harnesses
examples/        End-to-end usage demos
tests/           Unit + integration tests (pytest)
.github/         CI/CD workflows (Python/Go/TS/Docker)
```

## Quick start (local, no Postgres)

```bash
pip install -e .[dev]
python examples/contract_ai_agent.py    # in-memory end-to-end demo
pytest                                    # 83 tests, ~8s
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
| `AUTHZ_REDIS_URL` | *(empty)* | Redis URL — enables multi-process rate-limit + idempotency |
| `AUTHZ_API_KEYS` | *(empty)* | Bootstrap admin keys; once a DB key exists, DB lookup wins |
| `AUTHZ_LOG_LEVEL` | `INFO` | Python log level |
| `AUTHZ_AUDIT_ALL` | `false` | Audit allows in addition to denies |
| `AUTHZ_AUDIT_RETENTION_DAYS` | `0` | Days to retain audit rows (0 = forever) |
| `AUTHZ_AUDIT_PRUNE_INTERVAL_SECONDS` | `3600` | Pruning interval |
| `AUTHZ_RATE_LIMIT_PER_MINUTE` | `0` | Per-API-key rate limit; 0 disables |
| `AUTHZ_AUTO_PROVISION_USER` | `true` | Create users on first `resolve-context` |
| `AUTHZ_AUTO_PROVISION_TENANT` | `false` | Allow self-service tenant creation |
| `AUTHZ_AUTO_CREATE_SCHEMA` | `auto` | `true`/`false`/`auto` (auto = SQLite only) |
| `AUTHZ_OTEL_ENABLED` | `false` | Initialize OpenTelemetry exporters |
| `AUTHZ_CORS_ORIGINS` | `*` | Comma-separated origins for CORS |

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
- `POST /v1/api-keys`, `GET /v1/api-keys`, `POST /v1/api-keys/{id}/rotate`,
  `DELETE /v1/api-keys/{id}`
- `POST /v1/tenants/{tid}/invitations`, `GET /v1/tenants/{tid}/invitations`,
  `DELETE /v1/invitations/{id}`, `POST /v1/invitations/{token}/accept`

All endpoints require the `X-API-Key` header (or `Authorization: Bearer <key>`).
Two key sources are checked in order: env-configured bootstrap keys
(`AUTHZ_API_KEYS`) and DB-backed scoped keys created via the management API.
Dev mode (no env keys + no DB keys) accepts any caller and is logged at
startup; the service auto-locks down once any active DB key exists.

## API Keys

DB-backed keys are scoped:

- `admin` — full read/write on management endpoints
- `runtime` — only the four PEP endpoints
- `tenant:<id>` — runtime + management restricted to one tenant

Issue + rotate via the API or admin UI:

```bash
curl -X POST http://localhost:8080/v1/api-keys \
  -H "X-API-Key: $BOOTSTRAP" \
  -d '{"name": "prod-runtime", "scopes": ["runtime"]}'
# -> returns the plaintext key once; store it immediately

curl -X POST http://localhost:8080/v1/api-keys/$KEY_ID/rotate \
  -H "X-API-Key: $BOOTSTRAP"
# -> returns a new key with the old one's scopes; revoke the old one
# once the new is rolled out.
```

## Invitation flow

```bash
# 1. Admin creates an invite — service returns a one-time token
curl -X POST http://localhost:8080/v1/tenants/$TENANT/invitations \
  -H "X-API-Key: $ADMIN" \
  -d '{"email":"alice@acme.com","application_id":"$APP","roles":["legal_reviewer"]}'

# 2. Application emails the user a link containing $TOKEN
# 3. User logs in via your IdP, app extracts JWT claims, then:
curl -X POST http://localhost:8080/v1/invitations/$TOKEN/accept \
  -H "X-API-Key: $APP_KEY" \
  -d '{"provider":"azure_entra","issuer":"…","subject":"…","email":"alice@acme.com"}'
# -> creates user (if needed) + membership with the invited roles
```

## Admin UI

A minimal SPA is served at `/admin`. No build step — vanilla HTML + JS
talking to the same REST API. Useful for: provisioning tenants/apps,
issuing/rotating API keys, sending invitations, probing decisions. Set
your API key in the top bar; it's stored in localStorage.

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

## Documentation

In-depth docs live in [`docs/`](docs/index.md):

- [Concepts](docs/concepts.md) — model, decision algorithm, reason codes
- [Getting Started](docs/getting-started.md) — install + first decision
- [Identity & JWT](docs/identity.md) — IdP normalization, validation
- [RBAC](docs/rbac.md) — roles, permissions, memberships
- [Agents](docs/agents.md) — `user ∩ agent` intersection rule
- [Tools & MCP](docs/tools-and-mcp.md) — `ToolGuard`, `MCPGuard`
- [ABAC Policies](docs/policies.md) — declarative condition DSL
- [Service & Deployment](docs/service.md) — endpoints, env vars, CLI
- [Python SDK](docs/sdk-python.md) — `AuthzClient`, `AuthzAdminClient`
- [API Keys](docs/api-keys.md) — scopes, rotation, dev mode
- [Operations](docs/operations.md) — schema, audit, observability, runbook
- [Architecture](docs/architecture.md) — layers, protocols, dependencies

End-to-end runnable examples live in [`examples/`](examples/README.md);
all ten 0X-numbered scripts are self-contained and use the in-memory
store unless they explicitly demonstrate persistence.

## License

Apache-2.0
