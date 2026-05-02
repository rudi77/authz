# Changelog

## v0.2.0 — pilot-ready hardening (2026-05)

The MVP from v0.1 had correct decision logic but lacked the operational
+ security pieces a real deployment needs. This release closes those
gaps. Five themes:

### 1. Scoped API keys + rotation

- New `api_keys` table with hashed storage, key prefixes for log
  scrubbing, scopes (`admin` / `runtime` / `tenant:<id>`), expiry, and
  `rotates` link for audit trail.
- `POST/GET/DELETE /v1/api-keys` + `POST /v1/api-keys/{id}/rotate`.
- Constant-time hash comparison in the auth middleware.
- The legacy env-var key list (`AUTHZ_API_KEYS`) becomes a bootstrap
  mechanism; once a DB key is provisioned the service auto-locks down.
- Admin and runtime endpoints now enforce scopes via FastAPI deps —
  runtime keys are explicitly rejected from management endpoints.

### 2. Multi-process state (Redis)

- `_RedisRateLimiter` — sliding-window via ZSET + Lua.
- `_RedisIdempotencyStore` — hash + PEXPIRE.
- Backend factories pick Redis when `AUTHZ_REDIS_URL` is set; fall back
  to in-memory otherwise. No code changes for callers.
- docker-compose now ships a Redis service.

### 3. Invitation flow

- `Invitation` model + `InvitationService` with token hashing, expiry,
  revoke, accept-creates-membership semantics.
- `POST /v1/tenants/{id}/invitations`, `GET .../invitations`,
  `DELETE /v1/invitations/{id}`, `POST /v1/invitations/{token}/accept`.
- Accepting an invite resolves / provisions the user via the same
  IdentityPrincipal pathway used for `resolve-context`.

### 4. Minimal admin UI

- Static SPA served from `/admin` (no build step). Tabs: tenants,
  applications, API keys, invitations, decision probe.
- Live health pill, request-ID display, one-time secrets banner, LRU
  client-side caching of created resources.

### 5. Audit retention + load tests

- `AuditRetentionWorker` — background thread, configurable retention
  window, idempotent pruning helper exposed for cron use.
- `loadtests/asyncio_load.py` — single-file p50/p95/p99 sweep.
- `loadtests/locustfile.py` — full traffic-mix scenario.

### Operational hardening

- Multi-stage Dockerfile, non-root `authz` user, tini PID 1, baked-in
  HEALTHCHECK against `/healthz`.
- GitHub Actions CI workflow: ruff + pytest + Go test + npm test +
  docker build + smoke test.
- README sections on API keys, invitations, admin UI, and config.

### Tests

- 83 Python tests (was 50 in v0.1; +33 covering API keys, invitations,
  audit retention, Redis backends, scope enforcement).
- 7 Go tests, 8 TypeScript tests — unchanged.

## v0.1.0 — MVP (2026-05)

Initial release. Spec section 24 DoD met: identity normalization,
tenant + application registry, RBAC + agent intersection,
ToolGuard/MCPGuard, audit logging for denies, Python SDK,
end-to-end example.
