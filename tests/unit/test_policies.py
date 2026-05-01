"""ABAC expression and PolicyEngine tests."""

from authzkit.policies.engine import PolicyEngine, PolicyRule
from authzkit.policies.expressions import evaluate_expression
from authzkit.rbac.checker import AuthorizeRequest, Subject


def test_eq_expression():
    assert evaluate_expression({"eq": ["resource.amount", 100]}, {"resource": {"amount": 100}})
    assert not evaluate_expression(
        {"eq": ["resource.amount", 99]}, {"resource": {"amount": 100}}
    )


def test_lte_expression():
    assert evaluate_expression(
        {"lte": ["resource.amount", 100000]}, {"resource": {"amount": 50}}
    )
    assert not evaluate_expression(
        {"lte": ["resource.amount", 100]}, {"resource": {"amount": 1000}}
    )


def test_in_expression():
    assert evaluate_expression(
        {"in": ["resource.cost_center", "subject.cost_centers"]},
        {"resource": {"cost_center": "CC-1"}, "subject": {"cost_centers": ["CC-1", "CC-2"]}},
    )


def test_and_or_expression():
    expr = {
        "and": [
            {"lte": ["resource.amount", 100000]},
            {"eq": ["resource.region", "EU"]},
        ]
    }
    assert evaluate_expression(
        expr, {"resource": {"amount": 1000, "region": "EU"}}
    )
    assert not evaluate_expression(
        expr, {"resource": {"amount": 1000, "region": "US"}}
    )


def test_engine_with_no_rules_passes():
    engine = PolicyEngine()
    request = AuthorizeRequest(
        tenant_id="t",
        application_id="a",
        subject=Subject(type="user", user_id="u"),
        resource="contracts",
        action="approve",
    )
    assert engine.evaluate(request, {"contracts.approve"})


def test_engine_allow_rule_blocks_when_condition_fails():
    engine = PolicyEngine(
        [
            PolicyRule(
                name="amount-cap",
                effect="allow",
                resource="contracts",
                action="approve",
                condition={"lte": ["resource.amount", 100000]},
            )
        ]
    )
    request = AuthorizeRequest(
        tenant_id="t",
        application_id="a",
        subject=Subject(type="user", user_id="u"),
        resource="contracts",
        action="approve",
        context={"resource": {"amount": 200000}},
    )
    assert not engine.evaluate(request, {"contracts.approve"})


def test_engine_deny_rule_blocks_when_condition_satisfied():
    engine = PolicyEngine(
        [
            PolicyRule(
                name="block-suspicious",
                effect="deny",
                resource="contracts",
                action="approve",
                condition={"eq": ["context.fraud", True]},
            )
        ]
    )
    request = AuthorizeRequest(
        tenant_id="t",
        application_id="a",
        subject=Subject(type="user", user_id="u"),
        resource="contracts",
        action="approve",
        context={"fraud": True},
    )
    assert not engine.evaluate(request, {"contracts.approve"})
