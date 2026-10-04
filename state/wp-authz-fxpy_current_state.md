# WP authz-fxpy — current state

Fix lane FXPY of the authz-integration program (repo `authz`, branch `lane/authz-fxpy`,
based on `feat/dtm-integration` @ db934c3). Applies the wave-1 /simplify findings.
Contract: `docs/security/authz-integration-vertraege.md` §5 incl. §5.8 (DTM repo).

## Status per item

| Item | Status | Notes |
|---|---|---|
| 1 managed_by at one place | done | `ManagementGuard` (`authz_service/management.py`) + dependencies `managed_application`, `manager_application`, `catalog_application`, `managed_role`, `managed_agent`, `managed_membership`, body-based ones for memberships/invitations. Test `test_management_guard.py` enumerates all mounted write routes: each is app-scoped (must depend on `ManagementGuard`) or listed as exempt with a reason |
| 2 validation in the store | open | |
| 3 reference resolution in authzkit | open | |
| 4 N+1 in tenant-state apply | open | |
| 5 reuse | partly | `require_application`/`require_tenant` now used by roles, permissions, agents, memberships, invitations, provisioning, applications (`_resolve_application`, `_resolve_pair`, `_application`, `_tenant` removed) |
| 6 simplifications | open | |
| 7 claim-management | done | `POST /v1/applications/{app}/claim-management`, atomic (`UPDATE … WHERE managed_by IS NULL`), audited `management_claimed`, 409 `application_managed_externally` while someone else manages, no-op for the current manager |

## Behaviour notes (orchestrator)

- The guard runs as a FastAPI dependency, i.e. before the handler. Only
  multi-error orders change: an unknown application is now reported before an
  unknown tenant on `POST /v1/tenants/{t}/memberships|invitations|…/agents`, and
  a 403 `application_managed_externally` is reported before a 422 body error.
  Single-error responses are unchanged.
- `DELETE /v1/invitations/{id}` stays unguarded (revoking only removes access;
  invitations to managed apps cannot be created) — listed as exempt.
- 409 body of claim-management reuses `application_managed_externally` + `managed_by`.

## Tests

Windows: `PYTHONPATH=D:/Source/tmp/winplug .venv/Scripts/python.exe -m pytest -q -p win_dispose`.

- Baseline: 283 passed, 2 skipped
- ruff clean; mypy 26 → 20 errors (6 pre-existing ones in `policies.update_membership` gone, none new)

## Commits

- batch 1: item 1 + 7 (+ part of 5)
