# Service & Deployment

The standalone HTTP service in `authz_service/`. A FastAPI app that
wraps `authzkit` and serves the same decision algorithm over REST.

## When to run the service

- You have multiple apps that should share one PDP.
- You have non-Python clients (Go, TypeScript, anything that speaks HTTP).
- You want the admin UI / invitation flow / audit trail without writing
  it yourself.
- You need horizontal scale (multiple service instances behind a load
  balancer, sharing Postgres + Redis).

If your app is one Python process, the library form is simpler. The
service buys you operational features at the cost of a network hop.

## Endpoints

### Runtime (PEPs hit these)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/resolve-context` | `IdentityPrincipal → UserContext` |
| POST | `/v1/authorize` | Single allow/deny |
| POST | `/v1/bulk-authorize` | Many allow/deny in one request |
| POST | `/v1/effective-permissions` | Preload set for a session |

### Tenants & applications

| Method | Path | Purpose |
|--------|------|---------|
| POST/GET | `/v1/tenants`, `/v1/tenants/{id}` | Tenant CRUD |
| POST | `/v1/tenants/{id}/mappings` | Map external IdP tenant → internal |
| PUT | `/v1/tenants/{id}/feature-flags` | Feature toggles |
| POST/GET | `/v1/applications`, `/v1/applications/{id}` | Application CRUD |

### RBAC

| Method | Path | Purpose |
|--------|------|---------|
| POST/GET | `/v1/applications/{id}/roles` | Role CRUD |
| POST/GET | `/v1/applications/{id}/permissions` | Permission CRUD |
| PUT | `/v1/roles/{id}/permissions` | Replace role's permissions |
| POST/GET | `/v1/tenants/{tid}/memberships` | Membership CRUD |
| PATCH | `/v1/memberships/{id}` | Update roles or status |

### Agents

| Method | Path | Purpose |
|--------|------|---------|
| POST/GET | `/v1/tenants/{tid}/applications/{aid}/agents` | Agent CRUD |
| PUT | `/v1/agents/{id}/roles` | Replace agent's role list |

### API keys

| Method | Path | Purpose |
|--------|------|---------|
| POST/GET | `/v1/api-keys` | Issue/list keys |
| POST | `/v1/api-keys/{id}/rotate` | Issue replacement, link via `rotates` |
| DELETE | `/v1/api-keys/{id}` | Revoke |

### Invitations

| Method | Path | Purpose |
|--------|------|---------|
| POST/GET | `/v1/tenants/{tid}/invitations` | Create/list |
| DELETE | `/v1/invitations/{id}` | Revoke |
| POST | `/v1/invitations/{token}/accept` | Accept |

### Meta

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/healthz` | Liveness (DB ping) |
| GET | `/readyz` | Readiness (DB ping, stricter response) |
| GET | `/metrics` | Prometheus exposition |
| GET | `/docs` | OpenAPI Swagger UI |
| GET | `/admin` | Static admin SPA (if assets present) |

## Authentication

Every endpoint requires either an `X-API-Key` header or
`Authorization: Bearer <key>`. See [API Keys](api-keys.md) for the full
model. Two key sources:

1. `AUTHZ_API_KEYS` env var — comma-separated bootstrap keys, all
   implicitly admin-scoped.
2. The `api_keys` DB table — hashed, scoped, rotatable.

DB lookup wins when both succeed. The first DB-backed key activates
the lookup path; before then, the env list is the only source. If
neither has any keys, the service starts in **dev mode** and accepts
every caller (with a `WARNING` log line at startup).

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `AUTHZ_DATABASE_URL` | `sqlite+pysqlite:///./authz.db` | SQLAlchemy URL. Use Postgres in prod. |
| `AUTHZ_REDIS_URL` | *(empty)* | Multi-process rate-limit + idempotency. |
| `AUTHZ_API_KEYS` | *(empty)* | Bootstrap admin keys, comma-separated. |
| `AUTHZ_LOG_LEVEL` | `INFO` | Python log level. |
| `AUTHZ_AUDIT_ALL` | `false` | Log allow decisions, not just denies. |
| `AUTHZ_AUDIT_RETENTION_DAYS` | `0` | Days to retain audit rows; 0 = forever. |
| `AUTHZ_AUDIT_PRUNE_INTERVAL_SECONDS` | `3600` | Background pruning interval. |
| `AUTHZ_RATE_LIMIT_PER_MINUTE` | `0` | Per-API-key cap; 0 = unlimited. |
| `AUTHZ_AUTO_PROVISION_USER` | `true` | Create users on first `resolve-context`. |
| `AUTHZ_AUTO_PROVISION_TENANT` | `false` | Self-service tenant creation. |
| `AUTHZ_AUTO_CREATE_SCHEMA` | `auto` | `true` / `false` / `auto`. Auto = SQLite only. |
| `AUTHZ_OTEL_ENABLED` | `false` | Initialize OpenTelemetry exporters. |
| `AUTHZ_CORS_ORIGINS` | `*` | Comma-separated origins. |

Dot-notation `auto` resolves: SQLite → auto-create, anything else →
defer to Alembic. The service refuses to silently `CREATE TABLE`
against Postgres because that would skirt migration discipline.

## Schema management

Run Alembic before the service starts:

```bash
alembic upgrade head
```

Migrations live in `migrations/`. The service exposes a CLI shortcut:

```bash
authz schema upgrade
```

For SQLite, the service auto-creates the schema on startup unless you
explicitly disable it.

## Running with Docker

`docker-compose.yml` brings up Postgres + Redis + the service on
port 8080:

```bash
docker compose up --build
```

The image runs as the non-root user `authz` (uid 1000) under `tini`
as PID 1. There is nothing in the runtime that needs root.

## Running from source

```bash
pip install -e .
export AUTHZ_DATABASE_URL=postgresql+psycopg://authz:authz@localhost:5432/authz
export AUTHZ_API_KEYS=dev-key
alembic upgrade head
authz-service               # uvicorn on 0.0.0.0:8080
```

For multi-worker deployment, run uvicorn with workers behind a
reverse proxy:

```bash
uvicorn authz_service.main:app --host 0.0.0.0 --port 8080 --workers 4
```

When you run multiple workers, set `AUTHZ_REDIS_URL` so rate-limiting
and idempotency state is shared across processes.

## Middleware order

Registered in reverse runtime order (FastAPI semantics):

1. **CORS** (outermost)
2. **Idempotency** — caches `X-Idempotency-Key` responses for safe retries
3. **Rate limit** — per-API-key cap when `AUTHZ_RATE_LIMIT_PER_MINUTE > 0`
4. **Request context** (innermost) — request id, structured logging context

Each can be a no-op based on configuration, so the stack is the same
shape across dev / prod. Don't reorder these without understanding the
existing test coverage in `tests/integration/test_codex_p1_fixes.py`.

## CLI

The `authz` console script ships with the package:

```bash
authz schema upgrade                 # alembic upgrade head
authz bootstrap --spec foo.yaml      # idempotent provisioning
authz inspect health                 # GET /healthz
authz inspect decision \             # POST /v1/authorize from CLI
    --tenant-id <id> --application-id <id> \
    --user-id <id> --resource docs --action read
```

`authz bootstrap` consumes a YAML spec — see
[examples/bootstrap.example.yaml](../examples/bootstrap.example.yaml).
Re-runs are safe; the CLI reconciles the existing state declaratively.

## Admin UI

A vanilla-HTML SPA is served at `/admin` when the asset directory is
present (it's bundled in the Docker image). It uses the same REST API,
so anything the UI does, your scripts can do too. Set your API key in
the top bar; it's stored in `localStorage`.

## See also

- [Operations](operations.md) — observability, retention, redis
- [API Keys](api-keys.md) — scopes, rotation, dev mode
- [Architecture](architecture.md) — how the layers fit together
