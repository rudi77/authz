# WP authz-az2 — current state

Lane AZ2 of the authz-integration program (repo `authz`, branch `lane/authz-az2`,
from `feat/dtm-integration` @ 1582f3b). Contract: DTM `docs/security/authz-integration-vertraege.md` §5.

## Status per item

| Item | Status | Notes |
|---|---|---|
| Existence probe | done | `require_bound_tenant` (authz_service/references.py): tenant scope binding on the resolved tenant (or the raw ref when unknown) before user/agent resolution and before the 404. Applied to `POST /v1/delegations`, `POST /v1/delegations/revoke`, `GET /v1/applications/{app}/tenants/{tenant}/roles`. Test `tests/integration/test_tenant_existence_probe.py` (10 of 23 failed before the fix). |
| Z-6 image + deployment docs | done, verified in Docker | Image `ghcr.io/rudi77/authz:<tag>` (existing CI scheme kept: `vX.Y.Z` on `v*` tags, `latest`/SHA from main; no tag cut yet → OPEN_ITEMS). `deploy/docker-compose.yml` (authz + Postgres, Redis via `--profile ha`, no host port, healthcheck), `deploy/README.md` (env, first start, clients, DTM `Authz:*`, TLS, HA), `deploy/verify.py` (build → keygen → up --wait → CLI clients → tokens, catalog/managed_by, tenant state, authorize with refs, delegation on Postgres, 403s → down -v). Entrypoint: `AUTHZ_OAUTH_SIGNING_KEY_PEM_FILE`. Two full runs PASSED. |
| CHANGELOG / README / OPEN_ITEMS | done | |

## Notes for the orchestrator

- DTM validates `Authz:BaseUrl` as HTTPS in `Production`; authz is plain HTTP → a TLS proxy (e.g. DTM's Caddy) is needed in front of authz for production. Documented in deploy/README.md "TLS".
- DTM's `deploy/docker-compose.yml` authz profile is outdated (image name, only `DATABASE_URL`); deploy/README.md lists what it needs.
- `GET /v1/delegations` (admin) applies no tenant binding at all; an admin-scoped principal with a tenant pin could list other tenants' grants. Not changed (admin routes generally do not bind; out of scope).
- `GET/DELETE /v1/delegations/{id}` still answer 404 vs 403 by grant id; ids are random UUIDs, so no practical probe. Not changed.

## Tests

- Baseline 1582f3b: 302 passed, 2 skipped (orchestrator figure)
- Final: 325 passed, 2 skipped (+23 in test_tenant_existence_probe.py). ruff clean (incl. deploy/, contract/). mypy 19 errors, all pre-existing.
