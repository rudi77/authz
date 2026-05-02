# RBAC

Roles, permissions, memberships — the three primitives that make up
authz's role-based core.

## Permissions

A permission is a flat string. The convention is `<resource>.<action>`:

```
docs.read
docs.write
contracts.review
contracts.approve
```

For namespaced surfaces — MCP servers, third-party tools — prepend the
namespace:

```
mcp.github.read_repo
mcp.github.create_issue
tools.gmail.send
tools.calendar.create_event
```

### Defining a permission

Permissions are scoped to an application:

```python
store.create_permission(name="docs.read", application_id=app.id)
```

…or via the admin SDK:

```python
admin.create_permission(app.id, name="docs.read")
```

Two applications may share a permission name (e.g. both have
`docs.read`); they're distinct because each is filed under a different
application.

### Naming guidance

- Use lowercase, ASCII, dots as separators. No camelCase, no slashes.
- Resource is a noun; action is a verb. `docs.read`, not `read.docs`.
- Don't bake roles into permission names. `admin.users.delete` is wrong
  — make a `users.delete` permission and assign it to an `admin` role.
- Don't bake tenants in either. Tenancy is enforced via memberships;
  permissions are catalog-level.
- For tool-style permissions, the action is the tool name:
  `tools.gmail.send`, not `tools.gmail.email.send`.

## Roles

A role is a named set of permissions, scoped to one of:

| Scope | Role applies to |
|-------|------------------|
| `application` | Users in any tenant using this app (default) |
| `tenant` | Users in a specific tenant only |
| `agent` | Agents acting in this app |
| `platform` | System-wide constructs (rare) |

```python
from authzkit.rbac.models import RoleScope

role = store.create_role(
    name="reviewer",
    scope=RoleScope.APPLICATION,
    application_id=app.id,
)
store.set_role_permissions(role.id, {"contracts.read", "contracts.review"})
```

Admin SDK convenience that does both in one go:

```python
admin.upsert_role_with_permissions(
    app.id,
    name="reviewer",
    permissions=["contracts.read", "contracts.review"],
)
```

`upsert_role_with_permissions` is idempotent — re-running it reconciles
the permission list against the role declaratively. This is what the
`authz bootstrap --spec ...` CLI uses.

### Updating a role

Permissions are reassigned wholesale, not patched:

```python
store.set_role_permissions(role.id, {"contracts.read"})  # narrows the role
```

The change takes effect on the next decision; there's no cache to
invalidate inside the engine. If you're using the SDK with a TTL
cache, call `client.cache_invalidate(tenant_id=..., application_id=...)`
on a long-running agent runtime.

## Memberships

A membership scopes a user to a tenant + (optional) application, with
a role list:

```python
store.create_membership(
    tenant_id=tenant.id,
    application_id=app.id,        # None = tenant-wide membership
    user_id=user.id,
    roles={"reviewer", "manager"},
)
```

Application-scoped memberships win over tenant-wide ones when both
exist. Permissions from a membership are filtered to those scoped to
this app or unscoped (platform) permissions, so a user with the
`reviewer` role in app X can't accidentally use it in app Y.

### Memberships are how access happens

The user record is just an identity. A user with no memberships sees
zero permissions. To grant access:

1. Create the user (or let `resolve-context` auto-provision them).
2. Create the membership with the right roles.

Use one of:

- The admin API / SDK: `admin.create_membership(...)`
- The invitation flow: `admin.create_invitation` → user clicks link →
  `accept_invitation` (creates the membership atomically)
- A SCIM-style provisioner that calls the admin API

Never create memberships from runtime code paths; that's a privilege
escalation surface.

### Updating a membership

```python
admin.update_membership(membership_id, roles=["manager"])  # replace
admin.update_membership(membership_id, status="suspended") # block access
```

Suspending a membership denies every check with `no_active_membership`.

## Effective permissions

Given a tenant + application + subject, `effective_permissions` returns
the set of permissions the subject can use *right now*:

```python
perms = engine.effective_permissions(
    tenant_id=tenant.id,
    application_id=app.id,
    subject=Subject(type="user", user_id=user.id),
)
```

It runs steps 1–4 of the [decision algorithm](concepts.md#decision-algorithm)
but skips ABAC (which depends on the resource attributes of a specific
request). Use it to:

- Pre-render a UI tool palette
- Cache for the duration of an agent run
- Diff what a user can do before vs. after a role change

## Cross-app isolation

Two design rules keep applications from leaking permissions:

1. A role is scoped to its application; a tenant-wide membership only
   sees roles for the requesting app or unscoped platform roles.
2. A permission filed under app A is invisible to checks run against
   app B, even if a tenant-wide role is bound to it.

Test coverage for this lives in
`tests/integration/test_cross_app_isolation.py`. The properties to
keep are: changing one app's permission catalog never affects another
app's decisions, and a user invited to app A cannot use that
membership to act in app B.

## See also

- [examples/02_rbac_basics.py](../examples/02_rbac_basics.py) — multiple
  roles, role union, role updates
- [Concepts: decision algorithm](concepts.md#decision-algorithm)
