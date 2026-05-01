"""PolicyEngine — optional ABAC layer applied after RBAC has matched."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from authzkit.policies.expressions import evaluate_expression

if TYPE_CHECKING:
    from authzkit.rbac.checker import AuthorizeRequest


@dataclass(frozen=True)
class PolicyRule:
    """One ABAC rule. ``effect`` is "allow" or "deny" (deny wins when matched)."""

    name: str
    effect: str
    resource: str
    action: str
    condition: dict[str, Any] | None = None
    tenant_id: str | None = None
    application_id: str | None = None


class PolicyEngine:
    """Evaluates ABAC rules in MVP mode.

    For the MVP we only support ``effect="allow"`` rules acting as additional
    constraints (spec section 8.7 + 23). A request that matched RBAC must
    also satisfy every applicable allow-rule, and must not be blocked by any
    matching deny-rule. With an empty ruleset, every request passes through.
    """

    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        self.rules: list[PolicyRule] = list(rules or [])

    def add_rule(self, rule: PolicyRule) -> None:
        self.rules.append(rule)

    def evaluate(self, request: "AuthorizeRequest", _matched: set[str]) -> bool:
        if not self.rules:
            return True

        applicable = [r for r in self.rules if self._matches_target(r, request)]
        if not applicable:
            return True

        variables = {
            "resource": request.context.get("resource", {}),
            "subject": {
                "type": request.subject.type,
                "user_id": request.subject.user_id,
                "agent_id": request.subject.agent_id,
            },
            "context": request.context,
            "agent": request.context.get("agent", {}),
            "user": request.context.get("user", {}),
            "tenant": {"id": request.tenant_id},
        }

        # Deny rules win when their condition is satisfied.
        for rule in applicable:
            if rule.effect == "deny" and evaluate_expression(rule.condition, variables):
                return False

        # Every applicable allow-rule must hold.
        for rule in applicable:
            if rule.effect == "allow" and not evaluate_expression(rule.condition, variables):
                return False
        return True

    def _matches_target(self, rule: PolicyRule, request: "AuthorizeRequest") -> bool:
        if rule.tenant_id is not None and rule.tenant_id != request.tenant_id:
            return False
        if rule.application_id is not None and rule.application_id != request.application_id:
            return False
        if rule.resource != "*" and rule.resource != request.resource:
            return False
        if rule.action != "*" and rule.action != request.action:
            return False
        return True
