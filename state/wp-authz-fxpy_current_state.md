# WP authz-fxpy — current state

Fix lane FXPY of the authz-integration program (repo `authz`, branch `lane/authz-fxpy`,
based on `feat/dtm-integration` @ db934c3). Applies the wave-1 /simplify findings.
Contract: `docs/security/authz-integration-vertraege.md` §5 incl. §5.8 (DTM repo).

## Status per item

| Item | Status | Notes |
|---|---|---|
| 1 managed_by at one place | done | `ManagementGuard` (`authz_service/management.py`) + dependencies `managed_application`, `manager_application`, `catalog_application`, `managed_role`, `managed_agent`, `managed_membership`, body-based ones for memberships/invitations. Test `test_management_guard.py` enumerates all mounted write routes: each is app-scoped (must depend on `ManagementGuard`) or listed as exempt with a reason |
| 2 validation in the store | done | `set_role_permissions`, `set_agent_roles` (SQL + memory), `set_tenant_role_override` raise `UnknownNamesError(ProvisioningError)`; one app-level exception handler maps it to the unchanged 422 bodies. Shared predicate: `Permission.active` (domain property) / `orm.Permission.active` (hybrid, `deprecated IS false`) used by every query |
| 3 reference resolution in authzkit | done | `SqlAlchemyStore.resolve_references` (one session; tenant/app one query each `id = ref OR slug = ref`, id compared only if `ref` parses as UUID; user via `select(ExternalIdentity.user_id)`; agent `(id, status)` by name) → `ResolvedReferences` passed to the engine (`AuthorizeRequest.references`, `BulkAuthorizeRequest.references`, `effective_permissions(references=)`). Engine uses the statuses instead of re-reading tenant/application/agent; unknown refs fail the engine's own checks. `references.DecisionRefs`/deny-vocabulary mirror removed. Resolution still before tenant-scope binding and delegation match |
| 4 N+1 in tenant-state apply | done | `_apply_members`/`_apply_agents` prefetch identities (tuple-IN), users, memberships, membership roles, agents, internal roles, agent links, role permissions; diff in memory; `_replace_links` (diff-based delete + executemany insert) for role-permissions / membership-roles / agent-roles everywhere; `_links` bulk read; `_upsert_identity` shared with `upsert_user_from_identity`; `_named_roles`/`_role_by_name` (agent_id IS NULL) used by override set/delete/list and catalog; `get_role_by_name` delegates. `list_tenant_roles` reads all permissions in one query. No-op apply: constant 11 statements for 2 and 20 members/agents |
| 5 reuse | done | `require_application`/`require_tenant` everywhere (roles, permissions, agents, memberships, invitations, provisioning, applications incl. release-management, tenants, audit); `find_tenant`/`find_application` delegate to one-query store methods; `UserRefIn` → `UserRefSchema`; catalog name check via `PermissionModel.from_name`; `contract/keygen.py` uses `signing_keys._generate_rsa_keypair`; `schemas.one_form` for `SubjectSchema`, `DelegationIn` (`required=True`), `RevokeIn` |
| 6 simplifications | done | `list_delegations`: validation produces the typed `user_ref` / `agent_ref` used afterwards (no re-checks); `create_delegation`: agent id in one expression, asserts dropped |
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
- Decisions with an unknown reference: deny reasons per §5.1/§5.8 unchanged
  (tests `test_references.py`, `test_reference_resolution.py`). Only nonsense
  combinations differ: a subject with neither `user_id` nor `user_ref` plus an
  unknown `agent_name` now gets `invalid_subject` (before: `agent_not_active`);
  a non-user/agent subject type with an unknown `user_ref` gets
  `invalid_subject` (before: `no_active_user_membership`).
- authzkit library: memory store `set_role_permissions` now validates and only
  links permissions of the role's application (as the SQL store / API did).

## Tests

Windows: `PYTHONPATH=D:/Source/tmp/winplug .venv/Scripts/python.exe -m pytest -q -p win_dispose`.

- Baseline: 283 passed, 2 skipped
- Final (full suite): 298 passed, 2 skipped (+15 new: guard 2, claim 4, reference resolution 9)
- After shared-row fix: 302 passed, 2 skipped (+4)
- ruff clean; mypy 26 → 19 errors (pre-existing ones removed, none new)

## Commits

- ef6f2ac: item 1 + 7 (+ part of 5)
- batch 2: items 2, 3, 4, 5, 6

## Follow-up (orchestrator, after merge of 38d2a6f): shared tenant/user rows

`apply_tenant_state` overwrote an existing tenant's name/status and existing
users' display_name/email — rows shared by all applications. Now: a missing
tenant is created (`name`, status `active`), missing users with
display_name/email; existing tenant and user rows are never modified; a
tenant `status` other than `active` → 422 `invalid_state` with
`{"path": "status", "code": "tenant_status_not_managed"}` (field kept, so
DTM's `"status": "active"` keeps working). Test:
`tests/integration/test_tenant_state_shared_rows.py` (written first, 3 of 4
failed before the fix). The users prefetch in `_apply_members` is gone (only
`ExternalIdentity.user_id` is needed). CHANGELOG, README, docs/service.md updated.
