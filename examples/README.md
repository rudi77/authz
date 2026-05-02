# Examples

Runnable, self-contained examples that exercise every major capability of
the authz platform. Each script is independent and prints what it does.

Install once, then run any script:

```bash
pip install -e .[dev]
python examples/01_quickstart_inmemory.py
```

## Numbered tour

| # | Script | What it shows |
|---|--------|---------------|
| 01 | `01_quickstart_inmemory.py` | Smallest possible authz check: tenant + app + role + user, single ALLOW/DENY |
| 02 | `02_rbac_basics.py` | Multiple roles, role union, role updates, `effective_permissions` |
| 03 | `03_multi_tenant.py` | Two tenants with different feature plans, permission masks, suspended tenant |
| 04 | `04_agent_workflow.py` | The `user ∩ agent` intersection, `AgentGuard` with critical actions |
| 05 | `05_tool_and_mcp_guards.py` | `ToolGuard` + `MCPGuard` for in-process tool gating |
| 06 | `06_abac_policies.py` | ABAC: amount caps, region rules, fraud-signal deny |
| 07 | `07_bulk_authorize.py` | Hot-path bulk check that filters an agent's tool catalog |
| 08 | `08_identity_providers.py` | Normalizing claims from Entra / Cognito / GCP / generic OIDC |
| 09 | `09_fastapi_pep.py` | FastAPI route gated by `AuthzClient.require()` |
| 10 | `10_persistence_sqlalchemy.py` | Same engine, persistent SQLite (drop-in for Postgres) |

## Original walk-throughs

Three end-to-end stories that ship with the platform:

- `contract_ai_agent.py` — full spec §21.1 flow: JWT claims → user
  context → agent setup → guard checks
- `sdk_quickstart.py` — using the Python SDK against a running service
- `jwt_resolve_recipe.py` — JWT validation + `resolve-context` +
  `authorize`, the production application shape
- `bootstrap.example.yaml` — declarative tenant/role/permission spec
  consumed by `authz bootstrap --spec`

## Running everything at once

```bash
for f in examples/0*.py; do
    echo "=== $f ==="
    python "$f"
done
```

All ten scripts are smoke-tested as part of CI; if you add a new example,
keep it self-contained and runnable with a bare `pip install -e .`.
