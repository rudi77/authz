# Getting Started

The fastest path from clone to "I have an authz check working."

## Prerequisites

- Python 3.11+
- Optional: Docker, if you want to run the service rather than embed
  the library

## Install

```bash
git clone <repo>
cd authz
pip install -e .[dev]
```

## Path A — Library only (no service)

Use this when your app is Python and one process. No Postgres, no
HTTP, no extra deployment.

```python
from authzkit import AuthorizationEngine, AuthorizeRequest, Subject
from authzkit.rbac.models import RoleScope
from authzkit.storage.memory import InMemoryStore

store = InMemoryStore()
tenant = store.create_tenant(slug="acme", name="ACME")
app = store.create_application(slug="docs", name="Docs")
store.create_permission(name="docs.read", application_id=app.id)
role = store.create_role(name="reader", scope=RoleScope.APPLICATION,
                         application_id=app.id)
store.set_role_permissions(role.id, {"docs.read"})

user, _ = store.upsert_user_from_identity(
    provider="generic_oidc", issuer="https://idp", subject="alice",
    email="alice@acme.com", external_tenant_id=None,
)
store.create_membership(tenant_id=tenant.id, application_id=app.id,
                        user_id=user.id, roles={"reader"})

engine = AuthorizationEngine(store)
decision = engine.authorize(AuthorizeRequest(
    tenant_id=tenant.id, application_id=app.id,
    subject=Subject(type="user", user_id=user.id),
    resource="docs", action="read",
))
print(decision.allowed, decision.reason)
```

Swap `InMemoryStore` for `SqlAlchemyStore` to persist to SQLite or
Postgres. The rest of the code is unchanged.

See: [examples/01_quickstart_inmemory.py](../examples/01_quickstart_inmemory.py).

## Path B — Run the HTTP service

Use this when multiple apps share one PDP, when you have non-Python
clients, or when you want the admin UI.

### Docker (recommended)

```bash
docker compose up --build
```

The service comes up at `http://localhost:8080` with a bootstrap admin
key of `dev-key`. Postgres + Redis are included in the compose file.

### From source

```bash
pip install -e .
export AUTHZ_DATABASE_URL=postgresql+psycopg://authz:authz@localhost:5432/authz
export AUTHZ_API_KEYS=dev-key
alembic upgrade head
authz-service       # uvicorn on :8080
```

For SQLite (dev only):

```bash
export AUTHZ_DATABASE_URL=sqlite+pysqlite:///./authz.db
export AUTHZ_API_KEYS=dev-key
authz-service
```

### Probe it

```bash
curl http://localhost:8080/healthz
curl -H "X-API-Key: dev-key" http://localhost:8080/v1/tenants
```

### Bootstrap a tenant

```bash
AUTHZ_BASE_URL=http://localhost:8080 AUTHZ_API_KEY=dev-key \
    authz bootstrap --spec examples/bootstrap.example.yaml
```

This is idempotent: re-runs reconcile against the existing state
declaratively.

### Probe a decision

```bash
authz inspect health
authz inspect decision \
    --tenant-id <id> --application-id <id> \
    --user-id <id> --resource docs --action read
```

## Path C — Use a non-Python language

Pick the SDK for your runtime:

```bash
# Go
cd sdks/go/authz
go test ./...

# TypeScript
cd sdks/typescript
npm install && npm test
```

The Python, Go, and TS SDKs expose the same surface: `AuthzClient`,
`AuthzAdminClient`, `ToolGuard`, `MCPGuard`, plus `BulkCheck` /
`Subject` data types.

## Next steps

- Skim [Concepts](concepts.md) so the model isn't a surprise.
- Run all ten examples: `for f in examples/0*.py; do python "$f"; done`.
- Read [Service & Deployment](service.md) to plan a real deployment.
- Read [Operations](operations.md) before turning on production traffic.
