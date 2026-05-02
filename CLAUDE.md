# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Python (run from repo root):

```bash
pip install -e .[dev]                # install package + dev tooling
pytest -q                            # full suite (~83 tests, SQLite, no external deps)
pytest tests/unit -q                 # core library only, no DB
pytest tests/integration/test_api_keys.py::test_rotate -q   # single test
pytest --cov=authzkit --cov=authz_service --cov=authz_sdk
ruff check authzkit authz_service authz_sdk tests           # lint (CI gate)
ruff check --fix authzkit ...                               # auto-fix
mypy authzkit authz_service authz_sdk                       # types (non-strict)
alembic upgrade head                 # apply Postgres migrations
authz-service                        # uvicorn entry on :8080
authz schema upgrade | bootstrap --spec ... | inspect health|decision
```

Go SDK (`sdks/go/authz/`): `go vet ./... && go test -race -count=1 ./...`

TypeScript SDK (`sdks/typescript/`): `npm install && npm run lint && npm test && npm run build`

Docker / end-to-end: `docker compose up --build` brings up Postgres + Redis + service on :8080 with bootstrap key `dev-key`. Auto-runs `alembic upgrade head` before launch.

In-memory demo without any infra: `python examples/contract_ai_agent.py`.

## Architecture

This is a Policy Decision Point (PDP), not an authenticator and not a tool runtime. The service answers "is this subject allowed to do this action?" — apps and agent runtimes remain the PEPs.

**Three-layer Python package layout** (all in repo root):

1. `authzkit/` — reusable library, no service or HTTP. Importable from any Python app.
   - `identity/` normalizes OIDC claims (Entra/Cognito/GCP/generic) into a single `IdentityPrincipal` — the boundary at which provider-specific shapes disappear.
   - `tenancy/`, `rbac/`, `agents/` — domain models + repositories.
   - `rbac/checker.py` is the central `AuthorizationEngine` (PDP). All decision logic lives here.
   - `tools/`, `mcp/` — `ToolGuard` / `MCPGuard` for in-process enforcement against a preloaded permission set.
   - `policies/` — optional ABAC engine layered after RBAC.
   - `storage/` — `memory.py` (tests), `sqlalchemy.py` (prod). Both implement the same repository protocols.
   - `security/` — hashed scoped API keys + invitations.
2. `authz_service/` — FastAPI app wrapping authzkit.
   - `main.py` is the app factory. Middleware stack registered in reverse runtime order: `RequestContextMiddleware` (innermost) → `RateLimitMiddleware` → `IdempotencyMiddleware` → `CORSMiddleware`.
   - `dependencies.py` is the DI hub: lazy global `_engine` / `_store`, API-key resolution, audit sink.
   - `api/` holds REST routers; `cli.py` is the `authz` CLI; `ui/` is a static admin SPA mounted at `/admin`.
3. `authz_sdk/` — Python client (`AuthzClient`, `AuthzAdminClient`, `start_agent_session`). Re-exports `ToolGuard` / `MCPGuard` so apps don't need to import authzkit directly. `sdks/go/authz/` and `sdks/typescript/src/` mirror the same surface in their respective languages.

**Decision algorithm** (`AuthorizationEngine.authorize`, `bulk_authorize`, `effective_permissions`):

1. Reject if tenant or application is inactive.
2. Resolve the subject's permission set. For agents this is `user_perms ∩ agent_perms` — **an agent never gets more permission than the acting user**. Spec §2.5.
3. Apply tenant feature mask: `effective = subject_perms ∩ tenant_perms` (only when `tenant_perms` is non-empty; empty means "no mask"). Mismatches return `tenant_feature_disabled` to distinguish from `missing_permission`.
4. Run ABAC conditions (`PolicyEngine.evaluate`) per request because they depend on resource attributes.

`bulk_authorize` resolves the subject set once and reuses it across N checks — the optimization the agent-runtime hot path depends on. Don't regress this when touching the engine.

**API key auth** (`authz_service/dependencies.py`):

- Two key sources, checked in order: env-var bootstrap list (`AUTHZ_API_KEYS`, implicit `admin` scope) and DB-backed `api_keys` table (hashed, scoped: `admin` / `runtime` / `tenant:<id>`, rotatable). DB lookup wins.
- **Dev mode**: when both sources are empty the service accepts every caller and logs a warning at startup. The first DB-backed key auto-locks the service — there is no flag to flip; this is intentional so a forgotten test deployment locks itself down on first real provisioning.
- Tenant-scoped keys must be re-checked once the request body is parsed (`enforce_tenant_scope_binding`); per-route `Depends(require_admin_scope|require_runtime_scope)` only verifies the surface.
- Use `hmac.compare_digest` for any new key-comparison code; the existing flow loops over candidates rather than dict-lookup so timing doesn't leak prefix matches.

**Schema management**: production must run `alembic upgrade head`. The service refuses to silently mutate non-SQLite schemas. `AUTHZ_AUTO_CREATE_SCHEMA=auto` (default) means: SQLite → auto-create, anything else → defer to Alembic. Force with `true`/`false`.

**Backends pluggable via env**: `RateLimiter` and `IdempotencyStore` each have an in-memory and a Redis variant; `build_rate_limiter` / `build_idempotency_store` pick based on `AUTHZ_REDIS_URL`. Callers see the same `Protocol`. New shared-state primitives should follow this pattern instead of branching at call sites.

**Audit policy**: denies always written; allows only when `AUTHZ_AUDIT_ALL=true`. Retention is a background `AuditRetentionWorker` started on FastAPI `startup` and stopped on `shutdown` when `AUTHZ_AUDIT_RETENTION_DAYS > 0`.

**Permissions naming convention**: `<resource>.<action>` or namespaced `<namespace>.<resource>.<action>` (e.g. `mcp.github.create_issue`). Encoded everywhere as a flat string; the engine never parses the dots.

## Conventions specific to this repo

- Python ≥3.11. Ruff line-length 100 with `E501` ignored — long doc strings/examples are fine, but new code should still wrap.
- `pytest-asyncio` runs in `auto` mode; don't decorate async tests with `@pytest.mark.asyncio`.
- Integration tests drive the service via `fastapi.testclient.TestClient` against an in-memory SQLite — no external services in CI for the Python suite. Real Redis is mocked via `fakeredis`; the Lua-dependent path is currently skipped (see `OPEN_ITEMS.md` "Real Redis integration test").
- Repository globals (`_engine`, `_store`, `_settings`) are module-level singletons — call `reset_engine()` / `override_settings()` from tests rather than monkeypatching.
- The Docker image runs as non-root user `authz` (uid 1000) with `tini` as PID 1; don't add anything that needs root at runtime.
- `OPEN_ITEMS.md` is the living roadmap with explicit 🟥/🟧/🟨/🟦 status flags; consult it before proposing "missing" features — many are deliberately deferred.
- Status: v0.2 "pilot-ready". 83 Python + 7 Go + 8 TS tests must stay green; CI runs ruff + pytest + go test + npm test + docker build + smoke test.
