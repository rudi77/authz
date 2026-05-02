# Python SDK

`authz_sdk` — the HTTP client for the AuthZ service. Sync, fetch-based,
ships with both a runtime client (`AuthzClient`) and an admin client
(`AuthzAdminClient`).

## Install

The SDK is part of the `authz-platform` package:

```bash
pip install -e .
```

## Two clients, two surfaces

| Client | Use for | Endpoints covered |
|--------|---------|-------------------|
| `AuthzClient` | The hot path. PEP integrations. | `resolve-context`, `authorize`, `bulk-authorize`, `effective-permissions` |
| `AuthzAdminClient` | Provisioning, admin tooling, scripts. | tenants, applications, roles, permissions, memberships, agents, api-keys, invitations |

The split is deliberate: runtime clients should be pinned, cached, and
loaded with retry policy. Admin clients should be short-lived and
authoritative. Conflating them would force one of those models on the
wrong call site.

## AuthzClient

```python
from authz_sdk import AuthzClient, BulkCheck, Subject

with AuthzClient(
    "https://authz.example.com",
    api_key="...",
    cache_ttl_seconds=300,        # caches effective-permissions
    timeout=5.0,
    max_retries=2,
    retry_backoff_seconds=0.1,
) as client:
    ...
```

### resolve-context

Maps an `IdentityPrincipal` to a `UserContext`:

```python
ctx = client.resolve_context(
    application_id="docs",            # slug or id
    provider="azure_entra",
    issuer="https://login.microsoftonline.com/<tid>/v2.0",
    subject="<oid>",
    email="alice@acme.com",           # optional
    external_tenant_id="<tid>",       # optional
    explicit_tenant_id=None,          # optional override
    claims={...},                     # optional, for ABAC
)
# ctx.tenant_id, ctx.application_id, ctx.user_id, ctx.roles, ctx.permissions
```

Auto-provisions the user when `AUTHZ_AUTO_PROVISION_USER=true`. Returns
404 with `reason=no_active_membership` if the user has no membership
yet — call your invitation flow or admin API in that case.

### authorize / require

Single decision:

```python
allowed = client.authorize(
    tenant_id=ctx.tenant_id,
    application_id=ctx.application_id,
    subject=Subject(type="user", user_id=ctx.user_id),
    resource="docs",
    action="read",
    context={...},                    # optional, for ABAC
)
```

`require()` is the same call but raises `PermissionDeniedError` on
deny — handy for FastAPI dependencies:

```python
client.require(
    tenant_id=tenant_id, application_id=app_id,
    subject=Subject(type="user", user_id=user_id),
    resource="docs", action="read",
)
```

### bulk-authorize

```python
decisions = client.bulk_authorize(
    tenant_id=tenant_id, application_id=app_id,
    subject=Subject(type="agent", user_id=user_id, agent_id=agent_id),
    checks=[
        BulkCheck("tools.gmail", "send"),
        BulkCheck("mcp.github", "create_issue"),
    ],
)
for d in decisions:
    print(d.resource, d.action, d.allowed, d.reason)
```

Use this to filter a tool catalog at session start. Cost is one round
trip regardless of `len(checks)`.

### effective-permissions (cached)

```python
perms = client.get_effective_permissions(
    tenant_id=tenant_id, application_id=app_id,
    subject=Subject(type="agent", user_id=user_id, agent_id=agent_id),
)
guard = ToolGuard(perms)
```

When `cache_ttl_seconds > 0`, the result is cached per
`(tenant_id, application_id, subject)`. Pass `bypass_cache=True` to
force a fresh fetch. Drop cached entries with
`client.cache_invalidate(tenant_id=..., application_id=...)` after an
admin role change.

### Retries and errors

The client retries `httpx` transport errors and 5xx responses up to
`max_retries` times with exponential backoff. 4xx responses are
immediate fatal — you wouldn't fix `400 Bad Request` by retrying.

Two exception types:

- `AuthzClientError` — transport or validation problem on our side
- `AuthzServiceError` — non-2xx from the service. Carries
  `status_code` and `body`.

Catch them at your application boundary:

```python
try:
    client.require(...)
except PermissionDeniedError:
    return 403
except AuthzServiceError as e:
    log.error("authz service rejected: %s %s", e.status_code, e.body)
    raise
except AuthzClientError as e:
    log.error("authz transport error: %s", e)
    raise
```

## AuthzAdminClient

Same construction story, separate class:

```python
from authz_sdk import AuthzAdminClient

with AuthzAdminClient("https://authz.example.com", api_key="...") as admin:
    tenant = admin.create_tenant(slug="acme", name="ACME")
    app = admin.create_application(slug="contracts", name="Contracts")
    admin.create_permission(app.id, name="contracts.review")
    admin.upsert_role_with_permissions(
        app.id, name="reviewer", permissions=["contracts.review"]
    )
    admin.create_membership(
        tenant.id, user_id=user_id, application_id=app.id,
        roles=["reviewer"],
    )
```

The admin SDK mirrors every management endpoint as a typed method.
Notable convenience helpers:

- `upsert_role_with_permissions` — idempotent role + permission set.
- `map_tenant_external` — link an IdP tenant id to your internal tenant.
- `set_feature_flag` — tenant-scoped feature toggle.
- `issue_api_key` / `rotate_api_key` / `revoke_api_key` — full key
  lifecycle.
- `create_invitation` / `accept_invitation` — invitation flow.

See `authz_sdk/admin.py` for the full surface.

## FastAPI integration

`authz_sdk.fastapi_dependency.require_permission` builds a dependency
that gates a route:

```python
from authz_sdk.fastapi_dependency import require_permission

dep = require_permission(
    client_factory=lambda: AuthzClient(...),
    tenant_id_getter=lambda: current_tenant().id,
    application_id="docs",
    user_id_getter=lambda: current_user().id,
    resource="docs", action="read",
)

@app.get("/docs/{id}", dependencies=[Depends(dep)])
def get_doc(id: str): ...
```

Or roll your own — see [examples/09_fastapi_pep.py](../examples/09_fastapi_pep.py)
for a hand-written version.

## In-process testing

Pass FastAPI's `TestClient` as the SDK's `http_client` to drive an
in-process service without a real socket:

```python
from fastapi.testclient import TestClient
from authz_service.main import create_app

service = TestClient(create_app())
client = AuthzClient("http://test", api_key="dev-key", http_client=service)
```

This is what the integration test suite does. It's also the pattern
the FastAPI example uses.

## Connection lifetime

Both clients are `AbstractContextManager`s. Use `with` if the lifetime
is bounded; otherwise hold them as long-lived singletons in your
application. Don't construct one per request — the underlying
`httpx.Client` opens a connection pool that's expensive to throw away.

## See also

- `authz_sdk/client.py` — `AuthzClient` source
- `authz_sdk/admin.py` — `AuthzAdminClient` source
- `authz_sdk/agent_session.py` — `start_agent_session` helper
- [Tools & MCP](tools-and-mcp.md) — using the SDK output with a guard
- [Agents](agents.md) — `start_agent_session`
