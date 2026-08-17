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
    if (spec.concurrency is not None and
            spec.concurrency.linearization_points is not None):
        # Each actor has IDLE plus four in-flight phases for each operation.
        result *= (1 + 4 * len(spec.operations)) ** spec.actors
    return result


class _Unknown:
    """Three-valued logic marker: the guard depends on fields we have not
    fixed, so its truth at this valuation is undecided."""


UNKNOWN = _Unknown()


def _evaluate3(node, env: dict[str, Any]):
    """Partial (three-valued) evaluation of a typed expression.

    ``env`` maps the field under analysis to a concrete value and every
    other field to UNKNOWN; the result is True, False, or UNKNOWN.
    """
    if isinstance(node, FieldExpr):
        return env.get(node.name, UNKNOWN)
    if isinstance(node, (IntegerExpr, BooleanExpr)):
        return node.value
    if isinstance(node, OldExpr):
        return _evaluate3(node.expression, env)
    if isinstance(node, NotExpr):
        value = _evaluate3(node.expression, env)
        return UNKNOWN if isinstance(value, _Unknown) else (not value)
    if isinstance(node, BinaryExpr):
        op = node.kind                      # the operator IS the kind literal
        left = _evaluate3(node.left, env)
        right = _evaluate3(node.right, env)
        if op in {"add", "sub"}:
            if isinstance(left, _Unknown) or isinstance(right, _Unknown):
                return UNKNOWN
            return left + right if op == "add" else left - right
        if isinstance(left, _Unknown) or isinstance(right, _Unknown):
            if op == "and" and (left is False or right is False):
                return False
            if op == "or" and (left is True or right is True):
                return True
            if op == "implies" and left is False:
                return True
            if op == "implies" and right is True:
                return True
            return UNKNOWN
        return {"eq": lambda: left == right, "neq": lambda: left != right,
                "lt": lambda: left < right, "lte": lambda: left <= right,
                "gt": lambda: left > right, "gte": lambda: left >= right,
                "and": lambda: bool(left) and bool(right),
                "or": lambda: bool(left) or bool(right),
                "implies": lambda: (not left) or bool(right)}[op]()
    raise V2ValidationError(f"unsupported expression node {type(node).__name__}")


def static_deadlock_findings(spec: DomainSpecV2) -> list[str]:
    """Pre-TLC graph analysis: values that can be entered but never left.

    For each int state variable, a value is a DEADLOCK_RISK when
      * it is the initial value or some effect assigns it as a literal, AND
      * no operation's guards provably admit it (out-degree 0), AND
      * it is not exempted via the variable's ``terminal_states`` list.
    This is the cheap deterministic net for the missing-recycle()/reset()
    class of review error (the Tomcat EOF state); TLC remains the judge for
    values the static analysis cannot decide.
    """
    int_variables = [v for v in spec.state_variables if v.kind == "int"]
    findings: list[str] = []
    for variable in int_variables:
        field = variable.name
        reachable_values = {variable.initial}
        for operation in spec.operations:
            for effect in operation.effects:
                if effect.target == field and isinstance(effect.value, IntegerExpr):
                    reachable_values.add(effect.value.value)
        terminal = set(variable.terminal_states or [])
        for value in sorted(reachable_values):
            if value in terminal:
                continue
            can_leave = any(
                _operation_admits(operation, field, value, spec)
                for operation in spec.operations)
            if not can_leave:
                findings.append(
                    f"DEADLOCK_RISK: state {field} == {value} has no outgoing "
                    "transition. Missing a 'recycle()' or 'reset()' transition? "
                    "(If it is a legitimate end state, list it in "
                    f"{field}'s terminal_states.)")
    return findings


def _operation_admits(operation: Operation, field: str, value: int,
                      spec: DomainSpecV2) -> bool:
    env = {v.name: UNKNOWN for v in spec.state_variables}
    env[field] = value
    for guard in operation.guards:
        if _evaluate3(guard.expression, env) is False:
            return False
    return True


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
    # The cap binds on ACTUAL exploration, not the worst-case estimate:
    # hardware capacities produce wide bounds but sparse reachable sets (a
    # counter set to a literal then decremented explores one axis, not the
    # product). Genuinely exploding machines still fail closed here.
    initial = {item.name: item.initial for item in spec.state_variables}
    if (spec.concurrency is not None and
            spec.concurrency.linearization_points is not None):
        initial["__pc"] = tuple("IDLE" for _ in range(spec.actors))
        initial["__pending"] = tuple("none" for _ in range(spec.actors))
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
        if len(visited) > max_states:
            raise UnsupportedV2Boundary(
                f"reachable states exceed maximum {max_states}")
        if (spec.concurrency is not None and
                spec.concurrency.linearization_points is not None):
            transitions += _enqueue_lock_protocol_successors(spec, state, queue)
            continue
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


def _enqueue_lock_protocol_successors(spec: DomainSpecV2, state: dict[str, Any],
                                      queue: deque) -> int:
    """Explore invocation, acquisition, commit/reject, release, and response."""
    metadata = spec.concurrency
    assert metadata is not None and metadata.actor_lock_values is not None
    assert metadata.unlocked_value is not None
    count = 0
    lock = metadata.lock_variable
    for actor in range(spec.actors):
        pc = state["__pc"][actor]
        pending = state["__pending"][actor]
        if pc == "IDLE":
            for operation in spec.operations:
                post = dict(state)
                pcs = list(state["__pc"]); pcs[actor] = "INVOKED"
                pending_ops = list(state["__pending"]); pending_ops[actor] = operation.name
                post["__pc"], post["__pending"] = tuple(pcs), tuple(pending_ops)
                queue.append(post); count += 1
        elif pc == "INVOKED":
            operation = next(item for item in spec.operations if item.name == pending)
            if state[lock] == metadata.unlocked_value:
                post = dict(state); post[lock] = metadata.actor_lock_values[actor]
                pcs = list(state["__pc"]); pcs[actor] = "ACQUIRED"
                post["__pc"] = tuple(pcs)
                _check_bounds(spec, post, operation.name + "Acquire")
                _check_invariants(spec, post, operation.name + "Acquire")
                queue.append(post); count += 1
        elif pc == "ACQUIRED":
            operation = next(item for item in spec.operations if item.name == pending)
            if guards_hold(operation, state):
                post = apply_effects(operation, state)
                phase, step = "LINEARIZED", "Linearize"
            else:
                # Native unavailable semantics returns after observing a false
                # guard while holding the mutex; no reviewed domain field changes.
                post = dict(state); post[lock] = metadata.unlocked_value
                phase, step = "RELEASED", "Reject"
            pcs = list(state["__pc"]); pcs[actor] = phase
            post["__pc"] = tuple(pcs)
            _check_bounds(spec, post, operation.name + step)
            _check_invariants(spec, post, operation.name + step)
            queue.append(post); count += 1
        elif pc == "LINEARIZED":
            post = dict(state); post[lock] = metadata.unlocked_value
            pcs = list(state["__pc"]); pcs[actor] = "RELEASED"
            post["__pc"] = tuple(pcs)
            _check_bounds(spec, post, str(pending) + "Release")
            _check_invariants(spec, post, str(pending) + "Release")
            queue.append(post); count += 1
        elif pc == "RELEASED":
            post = dict(state)
            pcs = list(state["__pc"]); pcs[actor] = "IDLE"
            pending_ops = list(state["__pending"]); pending_ops[actor] = "none"
            post["__pc"], post["__pending"] = tuple(pcs), tuple(pending_ops)
            queue.append(post); count += 1
    return count
