# Core Concepts

Read this before you wire anything up. The model is small but every
piece carries weight.

## PDP vs. PEP

The authz platform is a **Policy Decision Point**. It owns the
permission model, the decision algorithm, and the audit trail. It
returns ALLOW or DENY when asked.

Your application is the **Policy Enforcement Point**. It calls the PDP
at a request boundary, and either executes the requested action or
returns 403 based on the answer. The PDP never executes business code.

```
+------+      JWT       +-----+   IdentityPrincipal   +------+
| User | -------------> | App | --------------------> | PDP  |
+------+                |     | <-------------------- |      |
                        |     |   ALLOW / DENY        +------+
                        |     |
                        |     |  ALLOW -> run the action
                        |     |  DENY  -> 403
                        +-----+
```

This separation is deliberate. It lets one PDP serve many apps, and it
keeps "what's authorized" decoupled from "how it runs". The library
form (`authzkit`) and the service form (`authz_service`) implement
the same decision algorithm; the only difference is the call boundary.

## Tenancy primitives

| Primitive | Purpose |
|-----------|---------|
| **Tenant** | Customer, workspace, org. Top-level isolation unit. |
| **Application** | A product / project that consumes the PDP. Owns its permission catalog and roles. |
| **User** | Internal record bound to one or more external IdP identities. |
| **External Identity** | A `(provider, issuer, subject)` triple from an IdP, joined to a User. |
| **Tenant Identity Mapping** | Maps an external IdP tenant id to an internal Tenant. Lets the PDP route claims-to-tenant without app code. |
| **Membership** | The link that scopes a user to a tenant (and optionally to one application within that tenant). Carries the role list. |
| **Agent** | An executable AI unit registered against `(tenant, application)`. Has its own role list. |

Memberships are the atomic unit of access — no membership means no
access. A user may have memberships in many tenants; each membership
carries its own role list.

## RBAC primitives

| Primitive | Purpose |
|-----------|---------|
| **Permission** | A flat string like `contracts.review` or `mcp.github.create_issue`. Defined per application. |
| **Role** | A named bundle of permissions. Has a scope: `platform`, `application`, `tenant`, or `agent`. |
| **Role Permissions** | The set of permissions a role grants. Mutable at any time. |

### Permission naming

`<resource>.<action>` is the canonical form. `mcp.github.create_issue`
is `(resource=mcp.github, action=create_issue)`. The engine never
parses dots itself — it compares full strings. The split exists only
so the SDK helpers can take `(resource, action)` arguments.

Pick names that describe **what is allowed**, not who has it. Don't
encode roles into permission names (`admin.contracts.read` is wrong;
`contracts.read` plus an `admin` role is right).

### Role scopes

| Scope | Use for |
|-------|---------|
| `platform` | System-wide roles (rare, e.g. tenant-creators) |
| `application` | The default. Roles grant permissions for one app. |
| `tenant` | Tenant-specific roles (e.g. customer-defined). |
| `agent` | Roles meant to be assigned to agents, not users. |

Scope is metadata; the engine doesn't gate on it. It exists for the
admin UI and for keeping role catalogs from accidentally mixing.

## Decision algorithm

The engine's `authorize()` runs:

1. **Tenant active?** No → `tenant_not_active`.
2. **Application active?** No → `application_not_active`.
3. **Resolve subject permissions**:
   - User: union of role permissions across active memberships.
   - Agent: `user_perms ∩ agent_perms`. **An agent never gets more
     permission than the acting user.** This is the safety property
     that makes the agent path tractable.
4. **Apply tenant mask**: `effective = subject_perms ∩ tenant_perms`
   (only when `tenant_perms` is non-empty; an empty mask means
   "no mask configured", not "deny all").
5. **Permission required in `effective`?** No → `missing_permission`,
   unless the permission *was* in `subject_perms` but not in
   `tenant_perms`, in which case → `tenant_feature_disabled` (so
   the UX layer can show a billing prompt instead of "you're not
   authorized").
6. **Run ABAC conditions**: any matching `deny` rule with a satisfied
   condition → `policy_condition_failed`; any matching `allow` rule
   that fails → `policy_condition_failed`.

`bulk_authorize` runs steps 1–4 *once* and then evaluates each check
against the cached effective set. ABAC still runs per check because
it depends on resource attributes.

`effective_permissions` performs steps 1–4 only and returns the set;
ABAC isn't evaluated because it's request-shaped.

### Reason codes

Every deny carries a stable reason string. The full set:

| Reason | Cause |
|--------|-------|
| `permission_granted` | Allow path |
| `tenant_not_active` | Tenant suspended/deleted |
| `application_not_active` | Application disabled |
| `invalid_subject` | Missing user_id / agent_id for the claimed subject type |
| `no_active_membership` | User has no membership in this tenant + application |
| `no_active_user_membership` | Agent path: the acting user has no active membership |
| `agent_not_active` | Agent path: the agent itself is disabled or wrong tenant |
| `missing_permission` | Subject's role set doesn't include the required permission |
| `tenant_feature_disabled` | Subject has the permission but tenant mask blocks it |
| `policy_condition_failed` | RBAC matched but ABAC said no |

Use the reason in the response body so the calling app can decide
between "show 403" and "show upgrade banner". Don't conflate them.

## Tenant masks

A tenant permission mask is a set of permission strings the tenant is
*allowed to use*. The engine intersects every subject's permissions
with the mask before checking. This is how feature flags become
authorization concerns:

- ACME paid for AI features → mask includes `ai.*`.
- Globex didn't → mask omits `ai.*`. The AI role still grants those
  permissions; the tenant mask filters them out, returning a
  distinct `tenant_feature_disabled` reason.

Empty mask = "unrestricted". Set a non-empty mask only when you
actually want to restrict.

## Auditing

Every deny is written to `audit_logs`. Allows are skipped by default
because they dominate volume; flip `AUTHZ_AUDIT_ALL=true` to log them
too. Retention is enforced by a background pruning worker controlled
by `AUTHZ_AUDIT_RETENTION_DAYS`.

The audit row carries: tenant id, application id, user/agent id,
resource, action, decision, reason, and the request envelope. Use it
for compliance, security investigations, and debugging "why did this
deny?".

## What the platform does NOT do

- It does not authenticate users. Tokens are validated by the
  application; the PDP trusts a normalized `IdentityPrincipal`.
- It does not execute tools. Guards return ALLOW; the runtime calls
  the tool.
- It does not store secrets, refresh tokens, or anything else issued
  by your IdP.
- It is not a token-exchange or OAuth server.

Knowing what's *out of scope* is as important as knowing what's in.
