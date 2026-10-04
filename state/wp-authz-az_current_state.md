# WP authz-az — current state

Lane AZ of the authz-integration program (repo `authz`, branch `lane/authz-az`).
Contract: `docs/security/authz-integration-vertraege.md` §5 (DTM repo).

## Status per item

| Item | Status | Notes |
|---|---|---|
| Z-1 references | done | tenant/app id-or-slug, `user_ref`, `agent_name` on authorize, bulk-authorize, effective-permissions, POST delegations, POST delegations/revoke, GET delegations filters |
| Z-2 tenant state | done | `PUT /v1/applications/{app}/tenants/{tenant}/state`, atomic, error list |
| Z-3 catalog | done | `PUT /v1/applications/{app}/catalog`, deprecation, default roles |
| Z-4 managed_by | API done; UI pending | enforcement on all permission/role/membership/agent write routes + invitations; release-management |
| Z-5 no silent success | done | |
| Z-7 contract fixture | pending | Docker daemon currently unresponsive on this machine |
| Z-8 tenant roles + cross-tenant fix | done | regression test `tests/integration/test_tenant_role_resolution.py` failed before the fix (9 of 10) |

## Tests

Windows runs need a local shim (`-p win_dispose`, outside the repo) because SQLite
files stay locked until engines are disposed; without it ~120 teardown errors
(WinError 32) appear, before and after this lane's changes.

- Baseline (HEAD 54f84c1): 232 passed, 2 skipped
- After batch A: 283 passed, 2 skipped
- ruff: clean. mypy: 26 errors before and after (all pre-existing, none new)

## Commits

- (batch A) Z-1, Z-2, Z-3, Z-4 (API), Z-5, Z-8

## Decisions / deviation requests for the orchestrator

1. **404 body key.** Contract §5 says new errors use `{"detail": {"error": ...}}`. All existing
   `*_not_found` 404s in authz use `{"detail": {"reason": ...}}`; the new 404s
   (`user_not_found`, `agent_not_found`, `role_not_found`, …) follow that existing convention.
   Non-404 errors use `error` (`unknown_role`, `unknown_permission`, `invalid_state`,
   `invalid_catalog`, `application_managed_externally`). DTM should read `reason` on 404.
2. **Unknown `user_ref` for an agent subject** denies with `no_active_user_membership`
   (what the engine says for an agent whose user has no membership); for a user subject
   `no_active_membership`. Contract names only `no_active_membership`.
3. **"Exactly one form"** is enforced as "not both" on decision subjects (422); a missing
   user/agent keeps the old behaviour (`invalid_subject`, or filled from a delegation grant).
   On `POST /v1/delegations` exactly one form per field is required (422 otherwise).
4. **Revoke/list by `agent_name`** needs `application_id` (agent names are unique per
   tenant × application). `RevokeIn` gained optional `application_id`. GET filters:
   `user_provider` + `user_issuer` + `user_subject`, `agent_name` + `application_id`;
   unknown references give an empty list. Revoke with an unknown reference: 404.
5. **`managed_by` labels:** `apikey:<id>`, `client:<client_id>` (only for tokens issued by
   this authz itself), `token:<issuer>#<client_id|sub>` (external IdP), `session:<sub>`.
6. **Tenant state / role overrides on an unmanaged application** (managed_by null) → 403
   `application_not_managed`. Catalog on an existing unmanaged application does not claim it
   (contract: managed_by only on first creation). There is no way to re-claim after
   `release-management` except creating a new application — open question.
7. **Null/default response fields are omitted** on existing application/permission/agent
   responses (`response_model_exclude_defaults`): `managed_by` only appears when set,
   `deprecated`/`critical` only when true. Reason: released Python SDKs build strict
   dataclasses from these responses and would crash on unknown keys. DTM must treat a
   missing `managed_by` as null.
8. **Deprecated permissions** are treated as unknown for every assignment (role permissions,
   tenant state, overrides) and count in no decision. Re-listing a permission in the catalog
   reactivates it (not counted as `created`).
9. **Agents are unique by `(tenant, application, name)`** (migration 0005 adds a unique
   index; fails on existing duplicates — documented in the migration). Creating a duplicate
   via the admin route now returns 409 `agent_name_taken`.
10. **Membership status `disabled`** is a new status value written by tenant state; tenant
    status must be `active|suspended|deleted`, member/agent status `active|disabled`.
11. **Invitations** for a managed application are blocked (they create memberships on accept).

## Open

- Z-4 admin UI read-only screens
- Z-7 fixture (needs a working Docker daemon)
- CHANGELOG / README / docs / OPEN_ITEMS
