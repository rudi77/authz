"""Tiny declarative expression evaluator for ABAC conditions.

Supported operators (per spec section 8.7): ``eq``, ``ne``, ``lt``, ``lte``,
``gt``, ``gte``, ``in``, ``not_in``, ``and``, ``or``, ``not``.

Operands are either:
- a literal scalar (number, string, bool, list)
- a path string starting with ``resource.`` or ``subject.`` or ``context.``
  which is resolved against the variables mapping passed to ``evaluate``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_PATH_PREFIXES = ("resource.", "subject.", "context.", "agent.", "user.", "tenant.")


def _resolve(operand: Any, variables: Mapping[str, Any]) -> Any:
    if isinstance(operand, str) and operand.startswith(_PATH_PREFIXES):
        # Walk a dotted path against the variables mapping. Missing nodes
        # collapse to None rather than raising — policies should treat absent
        # data as "condition can't be satisfied" elsewhere.
        parts = operand.split(".")
        current: Any = variables.get(parts[0])
        for key in parts[1:]:
            if current is None:
                return None
            if isinstance(current, Mapping):
                current = current.get(key)
            else:
                current = getattr(current, key, None)
        return current
    return operand


def evaluate_expression(expr: Any, variables: Mapping[str, Any]) -> bool:
    if expr is None or expr is True:
        return True
    if expr is False:
        return False
    if not isinstance(expr, Mapping):
        raise ValueError(f"unsupported expression: {expr!r}")
    if len(expr) != 1:
        raise ValueError(f"expression must have exactly one operator: {expr!r}")
    op, operands = next(iter(expr.items()))

    if op == "and":
        return all(evaluate_expression(e, variables) for e in operands)
    if op == "or":
        return any(evaluate_expression(e, variables) for e in operands)
    if op == "not":
        # Accept either {"not": expr} or {"not": [expr]}; both seen in JSON.
        target = operands[0] if isinstance(operands, list) else operands
        return not evaluate_expression(target, variables)

    if not isinstance(operands, list) or len(operands) != 2:
        raise ValueError(f"binary operator '{op}' expects 2 operands: {expr!r}")

    left = _resolve(operands[0], variables)
    right = _resolve(operands[1], variables)

    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    if op == "lt":
        return left is not None and right is not None and left < right
    if op == "lte":
        return left is not None and right is not None and left <= right
    if op == "gt":
        return left is not None and right is not None and left > right
    if op == "gte":
        return left is not None and right is not None and left >= right
    if op == "in":
        return left in (right or [])
    if op == "not_in":
        return left not in (right or [])
    raise ValueError(f"unknown operator: {op}")
