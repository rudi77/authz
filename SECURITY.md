# Security

This document describes the threat model, fail-closed semantics, and the
production hardening checklist for the AuthZ platform. If you are
operating this service in front of real user data, read this in full
before going live.

## Reporting a vulnerability

Open a private security advisory on GitHub
(`Security` → `Report a vulnerability`) or email the maintainer listed in
the repository metadata. Please do not file public issues for
suspected vulnerabilities.

We aim to acknowledge reports within two business days and ship a fix
or mitigation within 14 days for high-severity issues.

## Scope

The AuthZ service is a **Policy Decision Point** (PDP). It does not
authenticate end users, does not execute tools, and does not hold
end-user credentials. The threat model below covers the service, the
admin UI, and the SDKs.

In scope:

- The HTTP service (`authz_service/`) and its REST API
- The static admin SPA at `/admin`
- The Python / Go / TypeScript SDKs
- Storage backends shipped in this repo (SQLite, Postgres via
  SQLAlchemy, Redis-backed shared state)
- The CLI (`authz`)

Out of scope:

- End-user authentication and session management — your IdP owns this
- Tool execution and MCP server runtimes — your agent runtime owns this
- Network transport security (TLS) — your reverse proxy owns this
- Operating-system or container runtime hardening beyond the shipped
  Dockerfile

## Threat model

| Threat | Mitigation |
|--------|------------|
| Unauthenticated access to the service | API-key auth on every endpoint; default fail-closed when no keys exist (see below). |
| Stolen API key | Hashed-at-rest scoped keys; rotation + revocation endpoints; `last_used_at` for stale-key detection; `key_prefix` (not full key) in logs. |
| Tenant-scoped key probing other tenants | `enforce_tenant_scope_binding` runs per request after the body is parsed; mismatch returns 403. |
| Cross-tenant data leak via cached idempotency replay | Idempotency cache key includes the full credential fingerprint, not just the body. |
| Privilege escalation via agent | Agent permissions are intersected with the user's permissions; an agent never gets more rights than the human who initiated the session. |
| Stale cached permissions after revocation | SDK exposes `cache_ttl_seconds` (default short); revocation in the service is immediate, but PEP-side caches are eventually consistent. Use `critical=True` (Python SDK `start_agent_session`) to force re-validation for destructive actions. |
| Timing oracle on key comparison | `hmac.compare_digest` and a constant-iteration loop in `_env_key_record`. |
| Permissive CORS allowing browser-based attacks | `AUTHZ_CORS_ORIGINS=*` is rejected at startup unless `AUTHZ_DEV_MODE=true`. |
| Audit log gap obscuring attack | Denies are always written; allows are opt-in via `AUTHZ_AUDIT_ALL=true`; retention worker enforces `AUTHZ_AUDIT_RETENTION_DAYS`. |
| Schema drift from operator surprise | Non-SQLite databases never auto-migrate; the service refuses to mutate the schema and defers to Alembic. |
| Admin UI as an XSS staging point | UI is documented as a developer tool; API key default storage is `sessionStorage` (per-tab); a banner spells out the trade-off. |
| Replay of an old request with a new credential | Idempotency cache fingerprint encodes which header carried the credential, so X-API-Key and Authorization: Bearer cannot collide. |
| Resource exhaustion via runaway client | Per-key `AUTHZ_RATE_LIMIT_PER_MINUTE`; Redis-backed when running multi-process. |

## Fail-closed semantics

The service treats *missing configuration* as a hostile state and
refuses to serve traffic in a permissive way unless explicitly told to.
The flags:

- `AUTHZ_DEV_MODE=true` is the **only** way to opt into permissive
  behaviour. It allows two things:
  1. Accept any caller when neither `AUTHZ_API_KEYS` nor any active
     DB-backed key is configured.
  2. Use `AUTHZ_CORS_ORIGINS=*`.
- Without `AUTHZ_DEV_MODE`, missing keys → every request returns
  `401 missing_or_invalid_api_key`.
- Without `AUTHZ_DEV_MODE`, `AUTHZ_CORS_ORIGINS=*` → the service
  refuses to start.
- The first DB-backed key auto-locks the service even if
  `AUTHZ_DEV_MODE=true` is still set; after that, real keys are
  required regardless of the flag. This is intentional so a forgotten
  test deployment locks itself down on first real provisioning.
- Schema management on non-SQLite databases is fail-closed:
  `AUTHZ_AUTO_CREATE_SCHEMA=auto` (the default) skips auto-create; you
  must run `alembic upgrade head` explicitly.

## Production hardening checklist

Tick each item before exposing the service to non-developer traffic.

### Mandatory

- [ ] `AUTHZ_DEV_MODE` is **unset** or `false` in the deployment
      environment.
- [ ] `AUTHZ_API_KEYS` is set to at least one strong bootstrap key, or
      the `api_keys` table contains at least one active key. Treat the
      bootstrap key as break-glass, not a daily driver.
- [ ] Issue scoped DB keys for each consumer (`runtime`,
      `tenant:<id>`, etc.) instead of sharing the bootstrap admin key.
- [ ] `AUTHZ_CORS_ORIGINS` is set to the explicit list of origins that
      need browser access — never `*`.
- [ ] Postgres URL is in `AUTHZ_DATABASE_URL`; `alembic upgrade head`
      has run; `AUTHZ_AUTO_CREATE_SCHEMA` is left at `auto` (or set
      `false`).
- [ ] TLS terminated by your reverse proxy; the service itself never
      handles plaintext credentials over the network.
- [ ] Per-key rate limit configured (`AUTHZ_RATE_LIMIT_PER_MINUTE`)
      sized for your expected traffic; Redis backend (`AUTHZ_REDIS_URL`)
      enabled if running more than one process.
- [ ] `/admin` is either disabled (remove the `ui/` directory from the
      image) or placed behind an authenticated reverse proxy
      (mTLS / OIDC proxy / IP allowlist). The shipped UI is a
      developer tool, not a hardened admin console.

### Strongly recommended

- [ ] `AUTHZ_AUDIT_ALL=true` for at least the first weeks of operation
      so you have a complete record while permissions stabilise.
- [ ] `AUTHZ_AUDIT_RETENTION_DAYS` set to your retention policy
      (e.g. `90`); confirm the `AuditRetentionWorker` started in logs.
- [ ] Prometheus scrape configured against `/metrics`; alerts on
      `authz_decisions_total{decision="error"}` and `/healthz` failures.
- [ ] Log sink captures the structured `authz` logger including
      `request_id` and `key_prefix` (never the full key).
- [ ] PEP-side cache TTLs (`cache_ttl_seconds` in the SDKs) sized for
      your tolerance for stale revocations. Default is short
      (300s); shorten further if revocations must propagate fast.
- [ ] For destructive actions in agent runtimes, use the
      `critical=True` revalidation hook
      (`start_agent_session(..., critical_actions={...})`) so a freshly
      revoked permission cannot be used from an in-flight session.
- [ ] Container runs as non-root (the shipped image uses uid 1000).
      Verify your orchestrator does not override this.

### Optional, depending on environment

- [ ] OpenTelemetry exporters wired up (`AUTHZ_OTEL_ENABLED=true`).
- [ ] Idempotency-key support enabled in your callers for any non-GET
      management endpoint that retries.
- [ ] Bootstrap key revoked once a DB-backed admin key is in place
      (delete the env var, restart) — keeps the audit trail honest
      because `env-bootstrap-key` records can't be linked to a person.

## Key rotation runbook

```bash
# 1. Issue the new key alongside the old.
NEW=$(curl -X POST $URL/v1/api-keys/$KEY_ID/rotate \
      -H "X-API-Key: $ADMIN_KEY" | jq -r .key)

# 2. Roll the new key out to every consumer (deploy / config update).

# 3. Confirm the new key is live with a smoke test.
authz inspect health --api-key "$NEW"

# 4. Revoke the old key only after consumers confirm uptake.
curl -X DELETE $URL/v1/api-keys/$KEY_ID -H "X-API-Key: $ADMIN_KEY"
```

Never revoke before the new key is in service for every consumer; the
old and new key both authenticate during the overlap window. This is
documented at `docs/api-keys.md`.

## Cache invalidation expectations

PEP-side caches (Python SDK `cache_ttl_seconds`, Go SDK
`EffectivePermissions` cache, in-process `ToolGuard` snapshots) are
**eventually consistent** with the service. Concrete consequences:

- A revoked permission may still be honoured by a PEP for up to one
  cache TTL.
- A newly granted permission may not be visible to a PEP until the
  next refresh.
- For destructive or irreversible actions, do **not** rely on cached
  decisions. Use the SDK's revalidation hook (Python:
  `guard.require(..., critical=True)`) which forces a round trip to
  the service.
- After bulk permission changes (mass revocation, role rewrite) you
  may want to bounce long-running agent runtimes to clear their
  in-process snapshots.

## Audit-log guarantees

- Every **deny** is written, synchronously, in the same transaction as
  the decision response. A deny without a corresponding audit row
  indicates a bug — please report it.
- **Allows** are written when `AUTHZ_AUDIT_ALL=true`. Most operators
  start with this on and turn it off once their permission model is
  stable; the audit table grows fast.
- The audit row contains: tenant id, application id, subject,
  resource, action, decision, reason code, request id, and the
  `key_prefix` of the calling API key. The full key is never logged.
- The retention worker (`AuditRetentionWorker`) prunes rows older than
  `AUTHZ_AUDIT_RETENTION_DAYS` once per `AUTHZ_AUDIT_PRUNE_INTERVAL_SECONDS`.
  `0` means infinite retention.

## Cryptography notes

- API keys: 32 bytes of `secrets.token_urlsafe`, prefixed with a
  short non-secret tag. Hashed with SHA-256 at rest. Compared with
  `hmac.compare_digest`.
- Invitation tokens: 32 bytes of `secrets.token_urlsafe`, hashed at
  rest, single-use, expiring.
- No bespoke crypto. We do not roll our own primitives; we use the
  Python standard library.

## Known limitations

These are tracked in `OPEN_ITEMS.md`; calling them out here so they
are not surprises:

- gRPC API not yet shipped (REST only).
- ReBAC (relationship-based access) is not implemented; this is RBAC
  with optional ABAC conditions.
- Real-Redis integration test is currently skipped pending
  infrastructure; behaviour is exercised via `fakeredis` in CI.
- The admin UI is intentionally minimal and is not a substitute for a
  full admin console with its own authentication.

## Versioning and deprecation

The service follows semantic versioning starting at v0.2. Breaking
changes to the wire format, env-var names, or scope semantics will be
called out in `CHANGELOG.md` with at least one minor-version
deprecation window. Until v1.0, expect occasional adjustments; pin
the SDK and service versions together in production.
