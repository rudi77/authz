# WP authz-az2 — current state

Lane AZ2 of the authz-integration program (repo `authz`, branch `lane/authz-az2`,
from `feat/dtm-integration` @ 1582f3b). Contract: DTM `docs/security/authz-integration-vertraege.md` §5.

## Status per item

| Item | Status | Notes |
|---|---|---|
| Existence probe | done | `require_bound_tenant` (authz_service/references.py): tenant scope binding on the resolved tenant (or the raw ref when unknown) before user/agent resolution and before the 404. Applied to `POST /v1/delegations`, `POST /v1/delegations/revoke`, `GET /v1/applications/{app}/tenants/{tenant}/roles`. Test `tests/integration/test_tenant_existence_probe.py` (10 of 23 failed before the fix). |
| Z-6 image + deployment docs | in progress | |
| CHANGELOG / README / OPEN_ITEMS | pending | |

## Tests

- Baseline 1582f3b: 302 passed, 2 skipped (orchestrator figure)
