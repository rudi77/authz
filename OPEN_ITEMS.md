# Open Items / Roadmap

Living list of what's **not** yet in the platform, grouped by why a customer
or operator would notice. Everything here is deliberately deferred — the
core decision logic, security model, and operational surface are in.

Status legend: 🟥 blocker for GA · 🟧 needed for first paying customer ·
🟨 nice-to-have / iteration · 🟦 explicitly out of scope per spec.

---

## Recently closed (2026-05 code review)

Bug-fix sweep prompted by a focused code review (see CHANGELOG.md
"Unreleased — code review fixes"). None of these were on the roadmap
above; all were latent issues found by reading the code. Listed here
so the next reviewer doesn't re-flag them.

| Item | File | Fix |
|---|---|---|
| Race condition in `InvitationService.accept` allowed two concurrent acceptors to create duplicate memberships | `authzkit/security/invitations.py` | Atomic `UPDATE ... WHERE status='pending'` claim; rollback to `pending` if membership creation fails |
| `AuthzClient` cache leaked permissions between distinct service accounts (cache key omitted `service_account_id`) | `authz_sdk/client.py` | Cache key now includes `service_account_id`; regression test in `tests/unit/test_sdk_cache.py` |
| `/healthz` 503 body was built with an unescaped f-string; quotes/braces in the exception corrupted the JSON | `authz_service/main.py` | Switched to `JSONResponse` so escaping is handled by Starlette |
| OIDC discovery / JWKS fetch raised raw `ValueError` on HTML or malformed JSON, leaving the validator half-initialised | `authzkit/identity/jwt_validation.py` | New `_decode_json` helper wraps decode errors as `JWTValidationError`; payload-shape guards added |
| CORS allowed any HTTP method and any header in production (`allow_methods=["*"]`, `allow_headers=["*"]`) | `authz_service/main.py` | Non-dev mode restricts to the methods/headers the service actually serves; dev mode keeps the wildcards |

Test count after fixes: **123 Python tests** (4 skipped — PyJWT-cryptography
unavailable in CI sandbox; tests run when PyJWT is installed). Update the
"83 Python" reference in CLAUDE.md when noticed.

---

## Security & Compliance

| Status | Item | Notes |
|---|---|---|
| 🟥 | **Threat model document** | One-pager covering trust boundaries, token flow, abuse cases. Required for any external security review. |
| 🟥 | **Dependency scanning in CI** | Add `pip-audit`, `govulncheck`, and `npm audit` jobs. Fail on high-severity findings. |
| 🟥 | **Container image scanning** | Trivy or Grype scan on the published image; gate `latest` tag on a clean scan. |
| 🟧 | **mTLS for service-to-service** | Spec §15.1 mentions it as the enterprise tier. Right now everything is API-key based. |
| 🟧 | **OAuth client-credentials flow** | Alternative to API keys for callers that already have an IdP. |
| 🟧 | **Tenant-scoped API keys end-to-end** | The scope value `tenant:<id>` is supported in the model but the management routers don't enforce per-tenant scoping yet — admin scope still passes everywhere. |
| 🟧 | **Audit-log query API** | Currently audit rows are written but only queryable via direct DB access. Compliance requires `GET /v1/audit-log?tenant_id=...&from=...&to=...` with pagination. |
| 🟧 | **Audit-log archival to object storage** | Retention pruning deletes; some compliance regimes require export-then-delete. |
| 🟨 | **CSP / security headers middleware** | Lock down the admin SPA with strict CSP, X-Frame-Options, etc. |
| 🟨 | **Rate-limit per-tenant rather than per-API-key** | Today abuse from one tenant's runtime key affects only that key. A noisy tenant should also be capped tenant-wide. |
| 🟨 | **Secret-aware logging** | Currently structlog logs JSON; no scrubbing for accidental key leaks. |
| 🟨 | **Sign effective-permissions tokens** | Spec §22 #5 — return signed JWT-like blob so PEPs don't have to re-validate via the service. |

## Identity & Auth

| Status | Item | Notes |
|---|---|---|
| 🟧 | **SCIM provisioning endpoint** | Enterprise customers expect SCIM 2.0 for user lifecycle. Without it, onboarding 1k users requires 1k API calls. |
| 🟧 | **Bulk membership operations** | `POST /v1/tenants/{tid}/memberships:batch`. |
| 🟧 | **JWT validation as first-class middleware** | `JWTValidator` exists in authzkit but is opt-in; the service itself accepts pre-resolved IdentityPrincipals from callers. Optional middleware that validates JWTs at the AuthZ-service edge would simplify thin PEPs. |
| 🟨 | **Token introspection endpoint** | RFC 7662 — apps without JWT verification can ask the service to verify. |
| 🟦 | **Password / login flow** | Out of scope per spec §3.2. |
| 🟦 | **Refresh token storage** | Out of scope per spec §3.2. |

## Authorization features

| Status | Item | Notes |
|---|---|---|
| 🟧 | **Role inheritance / hierarchy** | Currently flat. Enterprise typically wants `senior_admin > admin`. |
| 🟧 | **Policy simulation** | "What changes if I give Alice this role?" — read-only probe that lists added/removed permissions across her memberships. |
| 🟨 | **ReBAC (Zanzibar-style)** | Spec §19.2 explicitly defers. Useful when permissions depend on object graphs (`document.editor` for documents Alice owns or was shared with). |
| 🟨 | **ABAC condition library expansion** | Current operators: eq/ne/lt/gt/in/and/or/not. Add regex, time-of-day, IP-range. |
| 🟨 | **Deny rules at policy level** | Engine only intersects allow sets. Deny rules supported in PolicyEngine but no UI/API for managing them. |
| 🟨 | **Permission templates** | Today permissions are flat per-app. Templates would let `application:create` instantiate `app.<id>.read`, `app.<id>.write`. |

## Service quality

| Status | Item | Notes |
|---|---|---|
| 🟥 | **Production-tested SLO targets** | Numbers in `loadtests/README.md` are aspirational. Need a dedicated load run on a Postgres-backed deploy with results recorded. |
| 🟥 | **Backup + restore runbook** | Postgres dump + restore tested end-to-end, including the `audit_log` retention edge case. |
| 🟧 | **Connection-pool tuning knobs** | `AUTHZ_DATABASE_POOL_SIZE`, `_POOL_TIMEOUT`, `_POOL_RECYCLE` env vars wired to SQLAlchemy. |
| 🟧 | **Graceful shutdown** | Current uvicorn config does not drain in-flight requests on SIGTERM with a configurable timeout. |
| 🟧 | **Per-query timeouts** | Long-running ABAC condition evaluations should be capped. |
| 🟧 | **SDK circuit breaker** | When the service is down, `AuthzClient` retries once then errors. PEPs need a circuit-breaker so a service outage doesn't fail every downstream request. Could fall back to last cached effective-permissions set. |
| 🟨 | **gRPC API** | Spec §19.2 — useful for very high-frequency PEPs. REST is fine for most. |

## Operations

| Status | Item | Notes |
|---|---|---|
| 🟥 | **Helm chart** | `deploy/helm/` with values for: replica count, Postgres URL secret, Redis URL secret, ingress, resource limits, PDB, HPA. |
| 🟥 | **k8s deployment manifests (non-Helm)** | For shops that don't use Helm: plain YAML with kustomize overlays. |
| 🟧 | **Container image release process** | Tagged releases (`v0.2.0`, `v0.2.1`, …) with semver and changelog; today CI only pushes `latest` and the commit SHA. |
| 🟧 | **Production deployment guide** | Docs covering: Postgres sizing, Redis sizing, key rotation cadence, log shipping, metrics scraping, alerting rules. |
| 🟧 | **Standard alerting rules** | Prometheus alert rules: `authz_decisions_denied_total` rate spike, p95 latency, audit-prune failures, DB connection saturation. |
| 🟨 | **CLI: `authz keys rotate-all-due`** | Operator command that rotates any key whose `expires_at` is within N days. |
| 🟨 | **CLI: `authz audit export`** | Stream the audit log to JSON / Parquet for offline analytics. |

## Multi-tenancy edge cases

| Status | Item | Notes |
|---|---|---|
| 🟧 | **Tenant deletion / hard delete** | Status flag exists; cascade-delete of all dependent rows (memberships, agents, audit) needs an explicit operation. |
| 🟧 | **Data residency / region-aware routing** | For customers under data-locality contracts. Large undertaking. |
| 🟨 | **Cross-tenant impersonation for support** | "Tenant Admin asks for a support session, AuthZ admin steps in for 30 minutes" — needs a separate impersonation primitive with its own audit trail. |

## Admin UI

| Status | Item | Notes |
|---|---|---|
| 🟧 | **Server-side tenant/application listing endpoints** | The current SPA stores created resources in localStorage because the service has no `GET /v1/tenants` (list). Adding pagination'd list endpoints unblocks better admin UX. |
| 🟨 | **Role-permission matrix view** | Visual editor for "which permissions does each role have, side-by-side". |
| 🟨 | **Audit log viewer** | Filter by tenant / decision / reason / time range. Depends on the audit query API above. |
| 🟨 | **Bulk membership upload** | CSV / JSON drop into the UI. |
| 🟨 | **Auth in the SPA** | Today the API key sits in localStorage. A real admin UI would offer SSO + scoped sessions. |

## Documentation

| Status | Item | Notes |
|---|---|---|
| 🟥 | **Architecture decision records (ADRs)** | Spec §22 lists 10 open design questions. The codebase made calls on all of them; need one ADR per decision. |
| 🟧 | **Migration guide v0.1 → v0.2** | What env vars changed, what's new in the schema, how to roll the API key system. |
| 🟧 | **Operator runbook** | "What to do when": p95 spike, DB outage, key compromise, runaway agent. |
| 🟧 | **API reference (beyond auto-generated OpenAPI)** | Per-endpoint usage notes, error code table, request/response examples. |
| 🟨 | **End-user docs for the admin UI** | Walkthrough screenshots. |

## Tests we owe

| Status | Item | Notes |
|---|---|---|
| 🟥 | **Real Redis integration test in CI** | Today CI uses fakeredis (Lua test skipped). Spin up a real Redis service container in the CI job and unset the skip. |
| 🟧 | **Concurrent / race tests** | Audit retention worker + active writes; rate limiter under contention. |
| 🟧 | **Schema upgrade test** | Migrate `0001 → 0002` against a seeded DB and verify decisions still match. |
| 🟨 | **Property-based tests for the AuthorizationEngine** | hypothesis: random role-permission graphs; verify intersection semantics. |
| 🟨 | **Mutation testing** | `mutmut` over the engine to confirm the test suite catches behavior changes. |

## Known minor issues

These are real but small and not on the critical path.

- The `authzkit` ruff config disables `E501` so long-line strings in
  examples can stay readable. Some are over 100 chars; harmless but
  noisy in editors.
- `docker-compose.yml` health checks for Redis use `redis-cli ping`
  which fails if `redis-cli` isn't on PATH in the alpine image — works
  today but pin the version explicitly.
- The Python admin SDK accepts both id and slug for tenants/apps, but
  the model classes type those fields as `id`, which can confuse users
  passing slugs.
- TS SDK doesn't expose admin invitations / API key endpoints yet —
  Python SDK does. Should reach feature parity.

---

## When to revisit

- **After first external pilot:** crystal-clear picture of which 🟧 items
  are actually blockers vs nice-to-haves. Promote / demote accordingly.
- **Before GA:** all 🟥 done, 🟧 either done or explicitly punted with
  written rationale.
- **Before "free tier":** rate limiting per-tenant is non-negotiable.
- **Before SOC 2 audit:** audit-log query + archival, dependency
  scanning, threat model.
