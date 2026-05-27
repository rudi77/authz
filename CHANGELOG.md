# Changelog

## Unreleased — OAuth 2.0 in three roles

Adds full OAuth 2.0 compatibility to the service, additive to the
existing API-key authentication. Single-PR landing of three previously
roadmap'd items (see OPEN_ITEMS.md "Recently closed 2026-05 OAuth 2.0
rollout").

### New — Resource Server

- The service accepts Bearer JWTs on every endpoint, validated against
  configured external OIDC issuers. Multi-issuer config via
  `AUTHZ_OAUTH_RESOURCE_ISSUERS` (JSON array, env or file).
- Per-issuer claim mapping: which claim carries the scope
  (`scope` / `scp` / `roles`), how external scope names translate to
  internal `admin` / `runtime` / `tenant:<id>` vocabulary, which
  claim carries the tenant id.
- Resolution order at the auth dependency: `X-API-Key` →
  `Authorization: Bearer <api-key>` (legacy) → `Authorization: Bearer <jwt>` →
  admin session cookie. Sniffed by token shape, not by configuration.

### New — Authorization Server

- `POST /oauth/token` issues RS256-signed JWTs for the
  `client_credentials` grant (RFC 6749 §4.4); accepts both
  `client_secret_basic` and `client_secret_post` (RFC 6749 §3.2.1).
- `GET /.well-known/oauth-authorization-server` (RFC 8414 metadata).
- `GET /.well-known/jwks.json` (active + retiring public keys).
- Signing-key custody: `AUTHZ_OAUTH_SIGNING_KEY_PEM` takes precedence
  over the DB-backed `oauth_signing_keys` table. Dev-mode + SQLite
  auto-generates an ephemeral RSA-2048 key; refused on any Postgres
  DSN.
- Signing-key rotation: `POST /v1/oauth/signing-keys/rotate` demotes
  the current active to `retiring`. JWKS exposes both until a
  background janitor revokes them after `2 × max_token_ttl`.
- Self-trust loop: tokens minted by this service validate on its own
  runtime endpoints in the same process without HTTP loopback (the
  resolver reads JWKS directly from `SigningKeyService`).
- Tenant-bound OAuth clients cannot mint cross-tenant tokens —
  `invalid_scope` if requested. Explicit regression test.

### New — Admin OIDC login

- `GET /oauth/login` → `GET /oauth/callback` → `POST /oauth/logout` /
  `GET /admin/session` implement Authorization Code + PKCE (S256)
  against any standard OIDC IdP.
- Server-side sessions in the new `admin_sessions` table; CSRF token
  is per-session and required on mutating session-authenticated calls.
- Group / email allow-list maps the IdP identity to the internal
  `admin` scope (`AUTHZ_ADMIN_OIDC_ADMIN_GROUPS`,
  `AUTHZ_ADMIN_OIDC_EMAIL_ALLOWLIST`).
- The admin SPA is now session-aware: shows "Sign in with SSO" when
  admin OIDC is configured; falls back to "Developer mode" API-key
  panel (hidden by default).

### New — schema, CLI, ops

- Alembic migration `0003_oauth_clients_signing_keys_sessions` adds
  four tables (`oauth_clients`, `oauth_signing_keys`, `admin_sessions`,
  `admin_login_attempts`).
- `authz oauth client create|list|revoke|rotate` and
  `authz oauth signing-key generate|rotate|list` CLI subcommands.
- `RateLimitMiddleware` buckets `POST /oauth/token` per `client_id`
  rather than per source IP, so one rogue client cannot crowd out the
  rest.

### Changed

- `_extract_key` (`authz_service/dependencies.py`) renamed internally
  to `_extract_credential` returning a tagged credential; the old
  function name is preserved as a thin shim.
- `require_admin_scope` / `require_runtime_scope` are now thin
  back-compat wrappers around the new union-aware `require_admin` /
  `require_runtime` (which admit `ApiKeyRecord` / `TokenPrincipal` /
  `SessionPrincipal`). All in-repo routers migrated to the new names;
  external callers that imported the old names still work.
- `enforce_tenant_scope_binding` now accepts the union.
- Dev-mode auto-bypass disengages as soon as **any** auth source is
  configured — API keys, DB keys, OAuth issuers, or admin OIDC.
- `pyproject.toml`: `pyjwt[crypto]>=2.8`, `cryptography>=42.0`, and
  `python-multipart>=0.0.9` are now required runtime dependencies.

### Fixes

- `JWTValidator.validate` used a private PyJWT API
  (`PyJWKClient._jwk_set_to_key`) that was removed in PyJWT 2.6+.
  Replaced with the public `jwt.PyJWK(...).key`.

### Tests

- 74 new tests (34 unit + 40 integration) covering scope mapping,
  multi-issuer routing, signing-key bootstrap + rotation + ephemeral
  guard, client_credentials happy + error paths, self-trust loop,
  admin OIDC happy + state-mismatch + group-deny + CSRF + logout,
  and dev-bypass auto-lock for the new auth surfaces.
- Total: **185 Python tests** pass; 0 failures.

## Unreleased — code review fixes

Bug-fix sweep from a focused code review (see OPEN_ITEMS.md "Recently
closed"). All five items are correctness or security fixes; no API
changes.

### Fixes

- **Invitation accept race**: two concurrent acceptors of the same
  token could both pass the in-Python status check and both create
  memberships. `InvitationService.accept` now atomically claims the
  invitation via `UPDATE ... WHERE status='pending'` and reverts to
  `pending` if membership creation fails.
- **SDK cache leak between service accounts**: `AuthzClient`'s
  effective-permissions cache key omitted `service_account_id`, so two
  service accounts sharing the same `(type, user_id, agent_id)` saw
  each other's permissions. The key now includes `service_account_id`.
- **/healthz JSON corruption**: the 503 body was built with an
  unescaped f-string; quotes or braces in the exception message
  produced invalid JSON. Now uses `JSONResponse`.
- **JWKS / OIDC discovery hardening**: a malformed or HTML response
  from a misconfigured / compromised IdP raised raw `ValueError` and
  could leave the validator half-initialised. Decode errors are now
  surfaced as `JWTValidationError` and payload shapes are validated.
- **CORS wildcard methods/headers**: production deployments allowed
  any HTTP method and any header even when `cors_allow_origins` was
  restricted. Non-dev mode now restricts to the methods/headers the
  service serves; dev mode keeps the wildcards.

### Internal

- New constants `INVITATION_STATUS_PENDING/ACCEPTED/EXPIRED/REVOKED`
  in `authzkit/security/invitations.py`; replaces scattered string
  literals.
- `_decode_json` is a module-level helper in `authzkit/identity/
  jwt_validation.py`; was previously a static method on `JWTValidator`.

### Tests

- 12 new tests covering all five fixes (concurrent invitation accept,
  membership-creation rollback, SDK service-account cache, /healthz
  exception escaping, four CORS preflight scenarios, and four
  JWKS-decode hardening cases). 123 tests pass; 4 skip when PyJWT's
  cryptography backend is unavailable.

## Unreleased — security hardening

Closes the most production-hostile defaults that survived v0.2.

### Breaking changes

- **Dev mode is now opt-in.** The previous behaviour ("if no API keys
  are configured, accept any caller") required no flag. It now
  requires `AUTHZ_DEV_MODE=true`. Without it, missing keys → every
  request returns `401 missing_or_invalid_api_key`. The first
  DB-backed key still auto-locks the service regardless of the flag.
- **`AUTHZ_CORS_ORIGINS=*` is rejected at startup** unless
  `AUTHZ_DEV_MODE=true`. Previous default was `*`; new default is
  empty. Set the explicit list of origins your browser clients use.

### Other changes

- New `SECURITY.md` with threat model, fail-closed semantics, key
  rotation runbook, audit-log guarantees, cache-invalidation
  expectations, and a production hardening checklist.
- Admin UI: API key now defaults to `sessionStorage` (per-tab,
  cleared on tab close) instead of `localStorage`. A "Remember in
  this browser" checkbox restores the old behaviour. A persistent
  banner explains the trade-off and points to `SECURITY.md`.
- README + docs: corrected test counts (111 Python, 7 Go, 8 TS) and
  updated all references to the dev-mode behaviour.

### Migration

- If you ran the service intentionally with no keys configured (local
  development, examples, demos), set `AUTHZ_DEV_MODE=true`.
- If you depended on `AUTHZ_CORS_ORIGINS` defaulting to `*`, set
  `AUTHZ_CORS_ORIGINS` explicitly to the origins you serve, or set
  `AUTHZ_DEV_MODE=true` for local hacking.
- Production deployments that already configured `AUTHZ_API_KEYS` and
  scoped DB keys are unaffected.

## v0.2.1 — structured authorize result (2026-05)

Adds the structured ``AuthorizeResult`` SDK type that PEP integrations
need for audit-grade decision data, while keeping the bool-shaped
``AuthzClient.authorize(...)`` /``.require(...)`` calls
backwards-compatible.

### Additions

- **``AuthorizeResult``** — frozen dataclass mirroring
  ``authzkit.service.schemas.AuthorizeResponseSchema``. Exposes
  ``allowed``, ``decision``, ``reason``, ``required_permission`` and
  ``matched_permissions`` so PEPs can audit denies without a second
  round-trip.
- **``AuthzClient.authorize_decision(...)``** — the new entry point
  for PEPs that want the full record. ``authorize`` and ``require``
  now both delegate to it internally; their public signatures and
  return types are unchanged.

### Compatibility

- ``AuthzClient.authorize(...)`` still returns ``bool``; existing
  call sites do not need to change.
- ``AuthzClient.require(...)`` still raises ``PermissionDeniedError``
  on deny; the raised permission name now reflects the decision's
  ``required_permission`` instead of being recomputed locally.

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

- 111 Python tests (was 50 in v0.1; +61 covering API keys, invitations,
  audit retention, Redis backends, scope enforcement, security
  hardening).
- 7 Go tests, 8 TypeScript tests — unchanged.

## v0.1.0 — MVP (2026-05)

Initial release. Spec section 24 DoD met: identity normalization,
tenant + application registry, RBAC + agent intersection,
ToolGuard/MCPGuard, audit logging for denies, Python SDK,
end-to-end example.
