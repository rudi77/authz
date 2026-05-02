# Architecture

The shape of the codebase, the boundaries between layers, and why
they're drawn where they are.

## Three layers

```
authzkit/         Reusable Python core library — no service, no HTTP
authz_service/    FastAPI app that wraps authzkit
authz_sdk/        HTTP client for the service (sync, with caching)
sdks/{go,ts}/     Identical SDK surface in Go and TypeScript
```

Each layer is consumed independently:

- An app embedding `authzkit` doesn't pull in FastAPI.
- An app using only the SDK doesn't import the engine.
- The service depends on `authzkit` but the dependency goes one way —
  `authzkit` never imports anything from `authz_service`.

This separation is what lets you run the engine in-process for one
deployment shape and behind HTTP for another, with the same algorithm
and the same tests proving it.

## authzkit submodules

```
authzkit/
  identity/        OIDC claim normalizers + optional JWT validator
  tenancy/         Tenants, applications, users, memberships, resolver
  rbac/            Roles, permissions, AuthorizationEngine
  agents/          Agent context + AgentGuard
  tools/           ToolGuard for application-scoped tool calls
  mcp/             MCPGuard for MCP-namespaced tool calls
  policies/        Optional ABAC engine + expression evaluator
  storage/         InMemoryStore + SqlAlchemyStore (same protocols)
  service/         Pydantic schemas shared with the SDKs
  audit/           AuditEntry + AuditLogger protocol
  security/        Scoped API keys + invitations
```

### The hierarchy

```
identity/        # boundary normalization
   |
   v
tenancy/  -->  rbac/  -->  agents/
   |             |          |
   |             v          v
   |          policies/   tools/, mcp/
   |
   v
storage/         # repository protocols satisfied by both backends
   |
   v
audit/, security/  # ancillary services
```

Two design rules keep this clean:

1. **Domain models are frozen dataclasses.** `Tenant`, `Application`,
   `User`, `Membership`, `Role`, `Permission`, `Agent`, `AgentContext`
   — none mutate after construction. State lives in repositories.
2. **Storage is a `Protocol`, not a base class.** `InMemoryStore` and
   `SqlAlchemyStore` both implement the same surface; the engine
   never inspects the type. Tests run on the in-memory variant; prod
   uses SQLAlchemy. Same code, same tests, two backends.

## The decision engine

`authzkit.rbac.checker.AuthorizationEngine` is the central PDP. It's
stateless across requests; everything stateful lives in the repository
it was constructed with. Three public methods:

| Method | Use |
|--------|-----|
| `authorize(request)` | One allow/deny decision |
| `bulk_authorize(request)` | N decisions, subject set resolved once |
| `effective_permissions(...)` | The set the subject can use right now (no ABAC) |

Internally, all three share the same primitives:

- `is_tenant_active`, `is_application_active`
- `is_user_membership_active`, `is_agent_active`
- `resolve_user_permissions`, `resolve_agent_permissions`,
  `resolve_tenant_permissions`

Subject-type branches (`SUBJECT_USER`, `SUBJECT_AGENT`) live in the
engine and only emit the agent intersection rule. This keeps repository
implementations free of policy logic.

## authz_service layout

```
authz_service/
  main.py          App factory, middleware stack, health endpoints
  config.py        Settings dataclass, env-var loading
  dependencies.py  DI hub: engine, store, audit sink, API-key auth
  middleware.py    Rate limit + idempotency (in-memory or Redis)
  observability.py structlog, Prometheus, optional OTel
  audit_retention.py  Background pruning worker
  cli.py           `authz` console script
  ui/              Static admin SPA (vanilla HTML/JS)
  api/
    authorize.py   /v1/authorize, /v1/bulk-authorize, /v1/effective-permissions
    context.py     /v1/resolve-context
    tenants.py     Tenant + mappings + feature flags
    applications.py
    permissions.py
    roles.py
    policies.py    Memberships (named for ABAC future-work)
    agents.py
    api_keys.py
    invitations.py
```

Routers are thin — they accept Pydantic schemas, call `authzkit`,
return Pydantic responses. Business logic stays in `authzkit`.

### Middleware

In runtime order (innermost first):

1. **Request context** — request id, structlog binding, timing
2. **Rate limit** — per-API-key, in-memory or Redis
3. **Idempotency** — `X-Idempotency-Key` deduplication
4. **CORS**

Each can be a no-op based on configuration; the stack shape stays the
same across dev / prod.

### DI hub

`authz_service/dependencies.py` is the single place where global
state lives — the SQLAlchemy engine, the store, the API-key service.
Module-level singletons are exposed via `Depends(get_engine)` etc.,
and tests reset them via `reset_engine()`. **Don't monkeypatch around
the singletons in tests** — call the reset function.

## authz_sdk layout

```
authz_sdk/
  client.py         AuthzClient: 4 PEP endpoints + LRU cache
  admin.py          AuthzAdminClient: every management endpoint
  agent_session.py  start_agent_session helper
  fastapi_dependency.py  require_permission FastAPI integration
  __init__.py       Re-exports ToolGuard / MCPGuard from authzkit
```

The SDK re-exports `ToolGuard` and `MCPGuard` from `authzkit` so apps
that depend on the SDK don't need a separate `authzkit` import. This
is the *only* upward dependency from the SDK; everything else is
HTTP.

## Storage protocols

`authzkit.storage` defines the protocols that `InMemoryStore` and
`SqlAlchemyStore` satisfy. There's no abstract base class; Python's
structural typing does the work:

```python
class TenancyRepository(Protocol):
    def get_tenant(self, tenant_id: str) -> Tenant | None: ...
    def is_tenant_active(self, tenant_id: str) -> bool: ...
    ...
```

This means a future Redis-backed or DynamoDB-backed store can be
introduced without touching the engine. As long as the new store
implements the protocol, it slots in.

## Pluggable backends

Two pieces are pluggable today:

- **`RateLimiter`** and **`IdempotencyStore`** each have an in-memory
  and a Redis variant. `build_rate_limiter` / `build_idempotency_store`
  pick based on `AUTHZ_REDIS_URL`. The engine sees only the `Protocol`.
- **`AuditLogger`** has `NullAuditLogger` (tests), the default
  SQLAlchemy-backed logger, and your own implementations are welcome.
  Set the audit sink via `dependencies.get_audit_sink`.

The pattern: when adding a new shared-state primitive, follow the
same shape — `Protocol` + concrete impls + `build_X` factory keyed off
config. Don't branch in call sites.

## SDK parity across languages

Python, Go, and TypeScript SDKs all expose:

- `AuthzClient` / `AdminClient`
- `Subject` / `BulkCheck` data types
- `ToolGuard` / `MCPGuard`

Functional differences are documented at the Go / TS source. The
target is "one bug fix in one SDK is a port-to-the-others, not a
re-design." Test suites in each language are kept in sync with the
Python integration tests.

## Things deliberately not in this codebase

- A user-token validator. JWT validation lives in the optional
  `authzkit.identity.jwt_validation` module so the service container
  doesn't carry pyjwt; the service itself never sees user tokens.
- A token exchange / OAuth server. The PDP is downstream of your IdP.
- A tool runtime. Guards return ALLOW; your runtime calls the tool.
- A UI framework. The admin SPA is hand-written vanilla HTML/JS so
  the operator can audit what the page does.

If a feature looks "obviously missing", check `OPEN_ITEMS.md` first —
many are deliberately deferred and the rationale is recorded there.

## See also

- [Concepts](concepts.md) — the model the architecture serves
- [Operations](operations.md) — what to monitor, what to tune
- `OPEN_ITEMS.md` — roadmap with explicit status flags
