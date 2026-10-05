# WP authz-fxpy2 — empty delegation grants

Branch `lane/authz-fxpy2` (from `feat/dtm-integration` @ 19bc16e). Status: **done**.

## Decision (orchestrator, DTM AD-4)

A grant binds user, agent, run and time; its rights are evaluated live.
`POST /v1/delegations` therefore issues a grant even when the delegable set
(`user ∩ agent ∩ mask`) is empty.

Refinement (orchestrator, 2nd round): empty grants only between ACTIVE
parties; an inactive user or agent fails explicitly.

| Request | Delegable set | Result |
|---|---|---|
| any | user has no active membership | 409 `no_active_user_membership` (was 409 `nothing_to_delegate`) |
| any | agent not active (e.g. disabled) | 409 `agent_not_active` (was 409 `nothing_to_delegate`) |
| `permissions` omitted | empty, both active | 201, `permissions: []` (was 409 `nothing_to_delegate`) |
| `permissions: []` | any | 201, `permissions: []` (was 409) — consistent with the omitted case: an empty request is trivially within the delegable set |
| explicit permissions outside the set | any | 403 `permissions_not_delegable` (unchanged) |

Decisions with an empty grant deny every check (`not_delegated` /
`missing_permission`, or the usual membership/agent reason if a party turns
inactive later). `nothing_to_delegate` no longer exists.

Error names: the orchestrator asked for `user_not_active` / `agent_not_active`
"reusing the engine's reason names". The engine has no `user_not_active`; for
an agent subject it denies with `no_active_user_membership` (and
`agent_not_active`). The engine names were used. Rename on request.

Order of checks: agent unknown → 404 `agent_not_found`; then user membership →
agent status → TTL → delegable set. Inactive tenant/application is not
checked here (out of scope); such a request still yields an empty grant.

## DTM contract note

- 201 with `permissions: []` is a valid grant: bind it to the run, every check
  with it denies. Expect it for tool-less agents.
- 409 `no_active_user_membership` / `agent_not_active`: no grant — the run
  must not start (the user lost access or the agent is disabled). Body:
  `{"detail": {"error": "<reason>"}}`.
- 403 `permissions_not_delegable` unchanged (explicit list only).

## Changed tests (approved spec change)

- `tests/integration/test_delegations.py::test_issue_validations` — suspended
  membership now asserts 409 `no_active_user_membership` instead of 409
  `nothing_to_delegate`.
- New: `test_empty_delegable_set_still_issues_a_grant` (agent without roles;
  implicit + explicit `[]`; explicit permission → 403),
  `test_explicit_empty_list_issues_an_empty_grant`,
  `test_inactive_agent_gets_no_grant` (disabled agent → 409
  `agent_not_active`, with and without `permissions: []`).

## Docs

CHANGELOG (Unreleased — Managed applications, Changed), README delegation
section, SDK `create_delegation` docstring, `DelegationIn.permissions` field
description. `docs/service.md` does not document delegations — nothing to change.

## Not changed / follow-up

- Admin UI (`authz_service/ui/app.js` issue-delegation modal) still requires
  at least one selected permission. Left as is (admin UX choice); empty grants
  are an API/runtime concern.

## Verification

Full suite 328 passed, 2 skipped (baseline 325 + 3 new). Ruff: only the 3
pre-existing findings in `examples/`. Mypy on changed files: 16 errors before
and after (pre-existing, none new).
