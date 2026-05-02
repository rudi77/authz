"""ABAC: attribute-based conditions layered on top of RBAC.

After an RBAC check passes, the ``PolicyEngine`` evaluates declarative
condition expressions against the request context. Operators supported:
``eq``, ``ne``, ``lt``, ``lte``, ``gt``, ``gte``, ``in``, ``not_in``,
``and``, ``or``, ``not``. Operands are either literals or paths like
``resource.amount``, ``subject.user_id``, ``context.ip``.

Demonstrates:
- Spending-cap allow rule (``contracts.approve`` only if amount <= cap)
- Region-restricted allow rule
- A deny rule that fires when a fraud signal is set in the context

Run with::

    python examples/06_abac_policies.py
"""

from __future__ import annotations

from authzkit import AuthorizationEngine, AuthorizeRequest, Subject
from authzkit.policies.engine import PolicyEngine, PolicyRule
from authzkit.rbac.models import RoleScope
from authzkit.storage.memory import InMemoryStore


def main() -> None:
    store = InMemoryStore()
    tenant = store.create_tenant(slug="acme", name="ACME")
    app = store.create_application(slug="finance", name="Finance")
    store.create_permission(name="contracts.approve", application_id=app.id)

    approver = store.create_role(name="approver", scope=RoleScope.APPLICATION, application_id=app.id)
    store.set_role_permissions(approver.id, {"contracts.approve"})

    user, _ = store.upsert_user_from_identity(
        provider="generic_oidc", issuer="https://idp", subject="alice",
        email="alice@acme.com", external_tenant_id=None,
    )
    store.create_membership(
        tenant_id=tenant.id, application_id=app.id, user_id=user.id, roles={"approver"},
    )

    rules = [
        # Allow contracts.approve only when amount <= 100k AND region is EU.
        PolicyRule(
            name="approval-cap",
            effect="allow",
            resource="contracts",
            action="approve",
            condition={
                "and": [
                    {"lte": ["resource.amount", 100_000]},
                    {"eq": ["resource.region", "EU"]},
                ]
            },
        ),
        # Deny outright when the request carries a fraud flag, regardless of role.
        PolicyRule(
            name="fraud-block",
            effect="deny",
            resource="*",
            action="*",
            condition={"eq": ["context.fraud_signal", True]},
        ),
    ]

    engine = AuthorizationEngine(store, policy_engine=PolicyEngine(rules))
    subject = Subject(type="user", user_id=user.id)

    cases = [
        ("Within cap, EU",     {"resource": {"amount": 50_000, "region": "EU"}}),
        ("Within cap, US",     {"resource": {"amount": 50_000, "region": "US"}}),
        ("Above cap, EU",      {"resource": {"amount": 250_000, "region": "EU"}}),
        ("Fraud signal raised", {
            "resource": {"amount": 1_000, "region": "EU"},
            "fraud_signal": True,
        }),
    ]

    for label, ctx in cases:
        decision = engine.authorize(
            AuthorizeRequest(
                tenant_id=tenant.id, application_id=app.id, subject=subject,
                resource="contracts", action="approve",
                context=ctx,
            )
        )
        verdict = "ALLOW" if decision.allowed else f"DENY ({decision.reason})"
        print(f"{label:<22} -> {verdict}")


if __name__ == "__main__":
    main()
