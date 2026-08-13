# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Canonical invariant conjunctions shared by deterministic V2 serializers."""
from __future__ import annotations

from .domain_v2 import BinaryExpr, FieldExpr, IntegerExpr, IntStateVariable


def _normalize_comparison(expression):
    """Give equivalent integer comparisons one deterministic representation."""
    if not isinstance(expression, BinaryExpr):
        return expression
    left = _normalize_comparison(expression.left)
    right = _normalize_comparison(expression.right)
    kind = expression.kind
    if kind in {"gte", "gt"}:
        left, right = right, left
        kind = "lte" if kind == "gte" else "lt"
    if kind == "lt" and isinstance(right, IntegerExpr):
        kind = "lte"
        right = IntegerExpr(value=right.value - 1)
    elif kind == "lt" and isinstance(left, IntegerExpr):
        kind = "lte"
        left = IntegerExpr(value=left.value + 1)
    return expression.model_copy(update={"kind": kind, "left": left, "right": right})


def _conjuncts(expression):
    normalized = _normalize_comparison(expression)
    if isinstance(normalized, BinaryExpr) and normalized.kind == "and":
        yield from _conjuncts(normalized.left)
        yield from _conjuncts(normalized.right)
    else:
        yield normalized


def canonical_invariant_expressions(reviewed) -> list:
    """Flatten conjunctions and remove semantically equivalent integer bounds."""
    expressions = []
    for variable in reviewed.state_variables:
        if isinstance(variable, IntStateVariable):
            lower, upper = variable.bound
            expressions.extend([
                BinaryExpr(kind="lte", left=IntegerExpr(value=lower),
                           right=FieldExpr(name=variable.name)),
                BinaryExpr(kind="lte", left=FieldExpr(name=variable.name),
                           right=IntegerExpr(value=upper)),
            ])
    for invariant in reviewed.tlc_invariants:
        expressions.extend(_conjuncts(invariant.expression))

    result, seen = [], set()
    for expression in expressions:
        normalized = _normalize_comparison(expression)
        key = normalized.model_dump_json()
        if key not in seen:
            seen.add(key)
            result.append(normalized)
    return result
