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
(185 Python + 7 Go + 8 TS tests). Operational concerns (scoped API keys,
OAuth 2.0 in three roles — Resource Server, Authorization Server,
admin OIDC login — multi-process state, audit retention, observability,
container hardening, fail-closed defaults) are in. Customer-readiness
gaps remaining: load-tested production deployment, SCIM, gRPC API,
ReBAC, full admin console.

See [`SECURITY.md`](SECURITY.md) for the threat model, fail-closed
semantics, and the production hardening checklist.

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

authzkit/security/  Scoped API keys + invitation flow + OAuth 2.0
                    (oauth_clients, oauth_resource, signing_keys, sessions,
                     principal union)

authz_service/   FastAPI Authorization Service
  api/           REST routers (incl. api_keys, invitations, oauth, oauth_clients)
  middleware.py  Rate limit + idempotency (in-memory or Redis)
  observability.py  structlog, Prometheus, optional OTel
  audit_retention.py  Background pruning worker
  oauth_janitor.py    Admin-session + retiring-signing-key sweepers
  oauth_config.py     Issuer JSON parser
  cli.py         `authz` CLI (schema, bootstrap, oauth, inspect)
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
pytest                                    # 185 tests, ~40s
```

## OAuth 2.0

The service can be used in three OAuth roles, each independently toggleable
and additive to the existing API-key auth (no breaking changes):

| Role | Enable | What it gives you |
|---|---|---|
| **Resource Server** | `AUTHZ_OAUTH_RESOURCE_ISSUERS=<json>` | Accept Bearer JWTs from external IdPs (Entra, Cognito, Auth0, Keycloak, …) at all runtime + admin endpoints. Claims are mapped to internal `admin` / `runtime` / `tenant:<id>` scopes per issuer. |
| **Authorization Server** | `AUTHZ_OAUTH_AS_ENABLED=true` + `AUTHZ_OAUTH_ISSUER` | Issue OAuth 2.0 tokens via `client_credentials` (RFC 6749 §4.4) so callers without an IdP get one short-lived JWT per call. RFC 8414 metadata at `/.well-known/oauth-authorization-server`, JWKS at `/.well-known/jwks.json`. Manage clients via `authz oauth client …`. |
| **Admin-UI OIDC login** | `AUTHZ_ADMIN_OIDC_ISSUER` + `AUTHZ_ADMIN_OIDC_CLIENT_ID` + … | Admins sign in with their corporate IdP (Authorization Code + PKCE) instead of pasting API keys into the browser. Server-side sessions with CSRF; bridge to the existing admin scope via groups or email allow-list. |

Minimal env shape for a Postgres deployment with all three on:

```bash
# Resource Server — accept JWTs from one external IdP
AUTHZ_OAUTH_RESOURCE_ISSUERS='[{"issuer":"https://login.microsoftonline.com/<tid>/v2.0","audience":"api://authz","scope_claim":"scp","scope_map":{"AuthZ.Admin":"admin","AuthZ.Runtime":"runtime"},"tenant_claim":"tid"}]'

# Authorization Server — issue our own tokens too
AUTHZ_OAUTH_AS_ENABLED=true
AUTHZ_OAUTH_ISSUER=https://authz.example.com
AUTHZ_OAUTH_AUDIENCE=https://authz.example.com
AUTHZ_OAUTH_ACCESS_TOKEN_TTL_SECONDS=3600
AUTHZ_OAUTH_SIGNING_KEY_PEM=$(cat /run/secrets/authz_signing_key)

# Admin OIDC for /admin
AUTHZ_ADMIN_OIDC_ISSUER=https://login.example.com/realms/corp
AUTHZ_ADMIN_OIDC_CLIENT_ID=authz-admin-ui
AUTHZ_ADMIN_OIDC_CLIENT_SECRET=…
AUTHZ_ADMIN_OIDC_REDIRECT_URI=https://authz.example.com/oauth/callback
AUTHZ_ADMIN_OIDC_GROUPS_CLAIM=groups
AUTHZ_ADMIN_OIDC_ADMIN_GROUPS=authz-admins,platform-ops
```

Smoke test for the Authorization Server role:

```bash
# Create a client (admin auth required — bootstrap key or session)
authz oauth client create --name pep-runtime --scopes runtime

# Mint a token
curl -su "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=client_credentials -d scope=runtime \
  http://localhost:8080/oauth/token

# Use the token on a runtime endpoint
curl -H "Authorization: Bearer $TOKEN" -d '{…}' \
  http://localhost:8080/v1/authorize
```

See `SECURITY.md` for the OAuth threat model (signing-key custody, bearer
replay, scope downscoping, CSRF) and `OPEN_ITEMS.md` for the follow-ups
(RFC 7662 introspection, RFC 7009 revocation, `jti` deny-list).

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
| `AUTHZ_CORS_ORIGINS` | *(empty)* | Comma-separated origins. `*` only allowed when `AUTHZ_DEV_MODE=true` |
| `AUTHZ_DEV_MODE` | `false` | When `true`: accept any caller if no API keys are configured AND allow `AUTHZ_CORS_ORIGINS=*`. Never set in production. |

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

**Default is fail-closed:** if no key sources are configured, every
request is rejected with `401 missing_or_invalid_api_key`. To run the
service without any keys (local hacking, examples, demos) you must set
`AUTHZ_DEV_MODE=true` explicitly. In dev mode the service accepts any
caller, logs a loud warning at startup, and auto-locks down once any
active DB-backed key is provisioned. Never enable `AUTHZ_DEV_MODE` in
production.

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
issuing/rotating API keys, sending invitations, probing decisions.

> **Security note.** The admin UI is a thin developer tool, not a
> hardened admin console. The API key is stored in `localStorage`
> (XSS-sensitive) and there is no built-in user authentication or CSRF
> protection. For non-development use, place it behind an authenticated
> reverse proxy (mTLS, OIDC proxy, IP allowlist) or disable it
> entirely. See [`SECURITY.md`](SECURITY.md) for details.

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
pytest -q              # runs all 111 tests in ~12s using SQLite
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
