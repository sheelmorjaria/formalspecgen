# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic bounded evaluator for isolated V2 candidate domains."""
from __future__ import annotations

from collections import deque
from typing import Any

from .domain_v2 import (
    BinaryExpr, BooleanExpr, BoolStateVariable, DomainSpecV2, FieldExpr,
    IntegerExpr, NotExpr, OldExpr, Operation,
)

MAX_STATE_SPACE = 100_000


class UnsupportedV2Boundary(ValueError):
    pass


class V2ValidationError(ValueError):
    pass


def evaluate_expression(node, state: dict[str, Any]) -> Any:
    if isinstance(node, FieldExpr):
        if node.name not in state:
            raise V2ValidationError(f"unknown state field {node.name!r}")
        return state[node.name]
    if isinstance(node, (IntegerExpr, BooleanExpr)):
        return node.value
    if isinstance(node, OldExpr):
        return evaluate_expression(node.expression, state)
    if isinstance(node, NotExpr):
        return not bool(evaluate_expression(node.expression, state))
    if isinstance(node, BinaryExpr):
        left, right = evaluate_expression(node.left, state), evaluate_expression(node.right, state)
        functions = {
            "eq": lambda: left == right, "neq": lambda: left != right,
            "lt": lambda: left < right, "lte": lambda: left <= right,
            "gt": lambda: left > right, "gte": lambda: left >= right,
            "add": lambda: left + right, "sub": lambda: left - right,
            "implies": lambda: (not left) or bool(right),
            "and": lambda: bool(left) and bool(right),
            "or": lambda: bool(left) or bool(right),
        }
        return functions[node.kind]()
    raise V2ValidationError(f"unsupported expression node {type(node).__name__}")


def guards_hold(operation: Operation, state: dict[str, Any]) -> bool:
    return all(bool(evaluate_expression(item.expression, state)) for item in operation.guards)


def apply_effects(operation: Operation, pre_state: dict[str, Any]) -> dict[str, Any]:
    """Evaluate every RHS against the same pre-state, then commit simultaneously."""
    computed = {item.target: evaluate_expression(item.value, pre_state)
                for item in operation.effects}
    post_state = dict(pre_state)
    post_state.update(computed)
    return post_state


def state_space_upper_bound(spec: DomainSpecV2) -> int:
    result = 1
    for variable in spec.state_variables:
        result *= 2 if isinstance(variable, BoolStateVariable) else (
            variable.bound[1] - variable.bound[0] + 1)
    if any(item.failure_semantics == "false_and_stutter" for item in spec.operations):
        result *= 3 ** spec.actors
    return result


def _check_bounds(spec: DomainSpecV2, state: dict[str, Any], operation: str) -> None:
    for variable in spec.state_variables:
        value = state[variable.name]
        valid = (isinstance(value, bool) if isinstance(variable, BoolStateVariable) else
                 isinstance(value, int) and not isinstance(value, bool) and
                 variable.bound[0] <= value <= variable.bound[1])
        if not valid:
            raise V2ValidationError(
                f"{operation} produces out-of-bounds {variable.name}={value!r}")


def _check_invariants(spec: DomainSpecV2, state: dict[str, Any], operation: str) -> None:
    for invariant in spec.tlc_invariants:
        if not bool(evaluate_expression(invariant.expression, state)):
            raise V2ValidationError(f"{operation} violates invariant {invariant.id}")


def _freeze(state: dict[str, Any]) -> tuple:
    return tuple(sorted((key, tuple(value) if isinstance(value, list) else value)
                        for key, value in state.items()))


def validate_transitions_and_invariants(
        spec: DomainSpecV2, *, max_states: int = MAX_STATE_SPACE) -> tuple[int, int]:
    upper = state_space_upper_bound(spec)
    if upper > max_states:
        raise UnsupportedV2Boundary(
            f"state space upper bound {upper} exceeds maximum {max_states}")
    initial = {item.name: item.initial for item in spec.state_variables}
    has_results = any(item.failure_semantics == "false_and_stutter" for item in spec.operations)
    if has_results:
        initial["callResult"] = tuple("none" for _ in range(spec.actors))
    _check_bounds(spec, initial, "Init")
    _check_invariants(spec, initial, "Init")
    queue, visited, transitions = deque([initial]), set(), 0
    while queue:
        state = queue.popleft()
        key = _freeze(state)
        if key in visited:
            continue
        visited.add(key)
        for operation in spec.operations:
            enabled = guards_hold(operation, state)
            if enabled:
                domain_post = apply_effects(operation, state)
                actors = range(spec.actors) if operation.return_type == "boolean" else (None,)
                for actor in actors:
                    post = dict(domain_post)
                    if actor is not None and has_results:
                        results = list(state["callResult"]); results[actor] = "true"
                        post["callResult"] = tuple(results)
                    _check_bounds(spec, post, operation.name)
                    _check_invariants(spec, post, operation.name)
                    transitions += 1; queue.append(post)
            elif operation.failure_semantics == "false_and_stutter":
                for actor in range(spec.actors):
                    post = dict(state)
                    results = list(state["callResult"]); results[actor] = "false"
                    post["callResult"] = tuple(results)
                    transitions += 1; queue.append(post)
    if transitions == 0:
        raise V2ValidationError(
            "initial state has no enabled transition; add the missing environment/controller "
            "operations or explicitly redesign the initial state (deadlock checking remains on)")
    return len(visited), transitions
