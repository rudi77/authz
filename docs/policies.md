# ABAC Policies

ABAC (attribute-based access control) layers per-request conditions on
top of RBAC. After the role check matches, the `PolicyEngine` evaluates
declarative expressions against the request's attributes — resource
fields, subject info, request context — and can deny what RBAC allowed.

ABAC is opt-in. With no rules configured, every request that passed
RBAC also passes ABAC.

## When to use ABAC

Use it when:

- A permission is conditional on resource state ("approve only if
  amount ≤ €100k")
- Geographic / regulatory rules apply ("EU-only data access")
- Time- or context-bounded rules apply ("only during business hours",
  "block if fraud signal raised")
- Resource ownership matters ("delete only your own documents")

Don't use it when a static role split would do. A `senior_approver`
role with extra permissions is simpler than an ABAC condition that
inspects job titles.

## The expression DSL

A condition is a JSON-shaped tree of operators:

```json
{
  "and": [
    {"lte": ["resource.amount", 100000]},
    {"eq": ["resource.region", "EU"]}
  ]
}
```

### Operators

| Operator | Operands | Returns |
|----------|----------|---------|
| `eq`, `ne` | `[a, b]` | `a == b`, `a != b` |
| `lt`, `lte`, `gt`, `gte` | `[a, b]` | numeric ordering (None-safe: false on nulls) |
| `in`, `not_in` | `[needle, haystack]` | membership in a list |
| `and`, `or` | `[expr, expr, ...]` | short-circuiting boolean |
| `not` | `expr` *or* `[expr]` | inversion |

### Path operands

Strings starting with one of `resource.`, `subject.`, `context.`,
`agent.`, `user.`, `tenant.` are treated as dotted paths into the
request variables. Anything else is a literal:

```json
{"in": ["resource.cost_center", "subject.cost_centers"]}
```

This compares the resource's `cost_center` field against the subject's
list of allowed cost centers. If either is missing, the expression is
false.

Available variables:

| Variable | Source |
|----------|--------|
| `resource` | `request.context.resource` (you supply when calling) |
| `subject` | `{type, user_id, agent_id}` |
| `context` | the full `request.context` |
| `agent`, `user` | `request.context.agent`, `request.context.user` |
| `tenant` | `{id: tenant_id}` |

`request.context` is whatever you pass in:

```python
engine.authorize(AuthorizeRequest(
    ...,
    context={
        "resource": {"amount": 50000, "region": "EU"},
        "user":     {"job_level": 7},
        "fraud_signal": False,
    },
))
```

## PolicyRule

Rules carry a name, an effect (`allow` or `deny`), the resource +
action they apply to (`*` matches anything), an optional tenant /
application filter, and the condition expression.

```python
from authzkit.policies.engine import PolicyEngine, PolicyRule

rules = [
    PolicyRule(
        name="approval-cap",
        effect="allow",
        resource="contracts",
        action="approve",
        condition={"lte": ["resource.amount", 100_000]},
    ),
    PolicyRule(
        name="block-fraud",
        effect="deny",
        resource="*",
        action="*",
        condition={"eq": ["context.fraud_signal", True]},
    ),
]

engine = AuthorizationEngine(store, policy_engine=PolicyEngine(rules))
```

### Rule semantics

For each request, the policy engine:

1. Filters rules by target match (resource/action/tenant/application).
2. Returns false if **any matching `deny` rule's condition is satisfied**.
3. Returns false if **any matching `allow` rule's condition is *not*
   satisfied** — every allow-rule must hold for the action to pass.
4. Otherwise returns true.

Two implications worth understanding:

- An `allow` rule **adds a constraint**. Don't think of it as "and now
  this is allowed"; think of it as "for this RBAC permission to apply,
  also this condition must hold".
- A `deny` rule **vetoes**. Even if RBAC and every allow-rule pass,
  one matching deny rule with a satisfied condition kills the request.

If the rule list is empty, every request passes through. If no rule
*matches the target*, every request passes through (the engine doesn't
require explicit allow rules).

### Wildcards

`resource="*"` matches any resource; same for `action="*"`. Both
together (`*`/`*`) is the way to write a tenant-wide veto:

```python
PolicyRule(
    name="freeze-tenant",
    effect="deny",
    resource="*", action="*",
    condition={"eq": ["tenant.id", "tenant_under_investigation"]},
)
```

## Storage and management

The current MVP wires ABAC rules in code (when constructing the
`PolicyEngine`). The DB-backed `policies` table exists but the MVP
service uses an in-process rule list — see `OPEN_ITEMS.md` for the
roadmap. For now, define rules in your application's bootstrap path
and pass them to the engine.

## Common patterns

### Spending caps

```python
PolicyRule(
    name="approver-cap",
    effect="allow",
    resource="contracts", action="approve",
    condition={"lte": ["resource.amount", "subject.cap"]},
)
# pass context={"resource": {"amount": 50000}, "subject": {"cap": 100000}}
```

### Region restriction

```python
PolicyRule(
    name="eu-only",
    effect="allow",
    resource="contracts", action="approve",
    condition={"in": ["resource.region", ["EU", "UK", "EEA"]]},
)
```

### Owner-only delete

```python
PolicyRule(
    name="own-docs",
    effect="allow",
    resource="docs", action="delete",
    condition={"eq": ["resource.owner_id", "subject.user_id"]},
)
```

### Time window

Pass the current hour into context, then:

```python
PolicyRule(
    name="business-hours",
    effect="allow",
    resource="*", action="approve",
    condition={
        "and": [
            {"gte": ["context.hour_utc", 8]},
            {"lt":  ["context.hour_utc", 18]},
        ]
    },
)
```

## See also

- [examples/06_abac_policies.py](../examples/06_abac_policies.py)
- `authzkit/policies/expressions.py` — the evaluator (small, self-contained)
- `tests/unit/test_policies.py` — operator behavior, edge cases
