# Operations

Everything you need to run this in production: schema, audit, metrics,
shared state, and the failure modes worth knowing.

## Schema management

The service refuses to silently mutate non-SQLite schemas. For
Postgres, run Alembic before the service:

```bash
alembic upgrade head
authz-service
```

Migrations live in `migrations/`. The service exposes a CLI shortcut
that calls Alembic with the right config:

```bash
authz schema upgrade
```

For SQLite (dev/test only), `AUTHZ_AUTO_CREATE_SCHEMA=auto` (default)
auto-creates the schema on startup. Set it to `true` to force
auto-create on Postgres (don't, except for ephemeral test DBs) or
`false` to defer to Alembic everywhere.

If the service starts and `/healthz` returns 503 with a database
error, the most common cause is a missing migration. Check
`alembic current` against `alembic heads`.

## Audit logging

Every deny is written to the `audit_logs` table. Allows are skipped by
default to keep volume manageable; flip with:

```bash
AUTHZ_AUDIT_ALL=true
```

Each row carries:

- Decision (`allow` / `deny`) and reason code
- Tenant + application + user/agent ids
- Resource + action
- The full request and response envelopes
- A request id (from `X-Request-Id` header, or generated)
- Timestamp

Use it for:

- **Security investigations**: "who tried to call this and was denied?"
- **Compliance**: "show me every action that touched contract X"
- **Debugging**: "why did this deny? — read the reason code, then
  inspect the request envelope"

### Retention

```bash
AUTHZ_AUDIT_RETENTION_DAYS=90
AUTHZ_AUDIT_PRUNE_INTERVAL_SECONDS=3600
```

A background `AuditRetentionWorker` is started on FastAPI's `startup`
hook and stopped on `shutdown` when retention is enabled. It deletes
rows older than the cutoff at the configured interval.

`AUTHZ_AUDIT_RETENTION_DAYS=0` disables pruning (rows kept forever).
That's the default; set it when you have a real retention policy.

## Observability

### Structured logging

`structlog` configured at startup. Every request gets a request id,
attached to every log line in the request scope. The log level comes
from `AUTHZ_LOG_LEVEL` (`DEBUG` / `INFO` / `WARNING` / `ERROR`).

Log keys you'll see:

| Key | Meaning |
|-----|---------|
| `event` | The log message |
| `request_id` | Stable per-request |
| `path`, `method`, `status_code` | Standard HTTP context |
| `decision`, `reason`, `tenant_id`, `application_id` | Authz outcome |
| `permission_required`, `subject_type` | What the caller asked for |

### Prometheus

`/metrics` exposes the standard process metrics plus:

| Metric | Type | Labels |
|--------|------|--------|
| `authz_decision_latency_seconds` | Histogram | `endpoint` (`authorize` / `bulk-authorize`) |
| `authz_decision_total` | Counter | `application_id`, `subject_type`, `decision`, `reason` |
| `authz_idempotency_hits_total` | Counter | — |
| `authz_rate_limit_hits_total` | Counter | — |

Scrape the endpoint with your existing Prometheus / Datadog agent. The
metrics aren't tenant-labeled because cardinality blows up; if you
need per-tenant breakdowns, query the audit log instead.

### OpenTelemetry

Optional, off by default:

```bash
AUTHZ_OTEL_ENABLED=true
# Plus the standard OTel env vars:
OTEL_EXPORTER_OTLP_ENDPOINT=https://...
OTEL_SERVICE_NAME=authz
```

Auto-instruments FastAPI and SQLAlchemy. Spans cover request handling,
DB roundtrips, and authz decision evaluation.

## Shared state for multi-process deployments

When you run more than one service worker, two stateful pieces need
shared storage: rate-limiting counters and idempotency keys. Both
default to in-memory (per-process) and switch to Redis when
`AUTHZ_REDIS_URL` is set:

```bash
AUTHZ_REDIS_URL=redis://localhost:6379/0
AUTHZ_RATE_LIMIT_PER_MINUTE=60
```

The same `Protocol` interface backs both implementations. Code that
calls them sees no difference.

If you forget to set `AUTHZ_REDIS_URL`, the service still runs but
rate limits and idempotency are per-process — N workers means N×
the configured limit, and replays land on whichever worker grabs the
next request. Always set Redis when running multi-worker.

## Health probes

| Endpoint | Use for | Behavior |
|----------|---------|----------|
| `/healthz` | Liveness | DB ping. 503 with body on failure. |
| `/readyz` | Readiness | DB ping. 5xx if unhealthy. |

Wire both into your platform: liveness restart policy on `/healthz`,
load-balancer rotation on `/readyz`.

## Capacity sizing

A few rules of thumb from the load tests in `loadtests/`:

- A single worker on a 2-core VM handles ~500 RPS of `authorize`
  against an in-memory store, ~200 RPS against Postgres.
- `bulk-authorize` is roughly the same RPS regardless of the number
  of checks per request, because the subject permission set is
  resolved once.
- DB connection pool is the bottleneck before CPU. Tune
  `pool_size` / `max_overflow` if you see connection-acquire spikes
  in traces.

For the agent hot path, prefer `bulk-authorize` + cached
`effective-permissions` over loops of `authorize`. The math is
asymmetric: O(1) of the former is much cheaper than O(N) of the
latter.

## Runbook: common failures

### Service starts in dev mode unexpectedly

This requires **all three** of: `AUTHZ_DEV_MODE=true` set in the
environment, `AUTHZ_API_KEYS` empty, and the `api_keys` table with
no active rows. Check the env in your container, and
`SELECT count(*) FROM api_keys WHERE status='active'`. Unset
`AUTHZ_DEV_MODE` to make the service fail-closed; the first key you
provision also flips the service into locked-down mode automatically.

### Service refuses to start with a CORS error

The startup check rejects `AUTHZ_CORS_ORIGINS=*` unless
`AUTHZ_DEV_MODE=true`. Replace `*` with the explicit list of origins
that need browser access (e.g. `https://admin.example.com`), or
leave the variable unset. See [`SECURITY.md`](../SECURITY.md).

### Every request returns 401 missing_or_invalid_api_key

The service is fail-closed and no key sources are configured. Either
set `AUTHZ_API_KEYS` to a bootstrap key, provision a DB-backed key
through another admin client, or — for local development only — set
`AUTHZ_DEV_MODE=true` and restart.

### Authorize returns `tenant_not_active`

The tenant row's `status` is not `active`. Either it's been suspended
intentionally or someone tested an admin path in prod. Flip it back
with `PATCH /v1/tenants/{id}` or directly in the DB.

### Cache is stale after a role change

The SDK caches `effective-permissions` for `cache_ttl_seconds`. After
an admin role change, call `client.cache_invalidate(tenant_id=...,
application_id=...)` from the long-running process, or set the TTL
short enough that staleness is bounded.

### Audit table grew too large

Set `AUTHZ_AUDIT_RETENTION_DAYS` to an actual retention value. If you
need to drain a large backlog, the worker prunes in batches; you can
also run a one-off `DELETE FROM audit_logs WHERE created_at < ...`
during a maintenance window.

### Postgres schema out of sync

Run `alembic upgrade head`. If `alembic heads` reports multiple heads,
your migration history has diverged — investigate before merging.
Never `--force` a migration on a populated database.

## Testing operations

The integration suite covers:

- DB persistence (`tests/integration/test_sqlalchemy_store.py`)
- API key issuance + rotation + scope binding (`test_api_keys.py`)
- Cross-app isolation properties (`test_cross_app_isolation.py`)
- Health / metrics endpoints (`test_observability_and_health.py`)
- Redis-backed rate limit + idempotency (`test_redis_backends.py`)

Run the full suite before promoting any operational change:

```bash
pytest -q
```

## See also

- [Service & Deployment](service.md) — env var reference, middleware order
- [API Keys](api-keys.md) — rotation, scope binding
- [Architecture](architecture.md) — what each layer is responsible for
- `OPEN_ITEMS.md` — explicit list of known gaps for v0.2 → v1.0
