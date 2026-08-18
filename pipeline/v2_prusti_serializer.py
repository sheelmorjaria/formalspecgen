# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic reviewed-V2 to Rust/Prusti serialization.

Mirrors the JML serializer's single-contract-source discipline for the Rust
lane: every #[requires]/#[ensures]/#[invariant] clause is derived from the
promoted V2 typed expression trees, and method bodies transcribe the reviewed
effects (pre-captured locals preserve simultaneous-assignment semantics).
No LLM is involved.  Unsupported semantics fail closed.
"""
from __future__ import annotations

import re
from pathlib import Path

from .domain_v2 import (
    BinaryExpr, BooleanExpr, BoolStateVariable, FieldExpr, IntStateVariable,
    IntegerExpr, NotExpr, OldExpr, _referenced_fields,
)
from .domain_v2_promotion import ReviewedDomainSpecV2
from .v2_jml_serializer import _OPS
from .v2_invariants import canonical_invariant_expressions


class UnsupportedPrustiBoundary(ValueError):
    """The reviewed semantics leave the deterministic Prusti subset."""


def _unparenthesized(text: str) -> str:
    return text[1:-1] if text.startswith("(") and text.endswith(")") else text


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def _rust_type(variable) -> str:
    return "i32" if isinstance(variable, IntStateVariable) else "bool"


def render_prusti_expression(node, *, pre_state: bool = False,
                             receiver: str = "self") -> str:
    """Render a reviewed V2 expression in Prusti macro syntax."""
    if isinstance(node, FieldExpr):
        base = f"{receiver}.{node.name}"
        return f"old({base})" if pre_state else base
    if isinstance(node, IntegerExpr):
        return str(node.value)
    if isinstance(node, BooleanExpr):
        return "true" if node.value else "false"
    if isinstance(node, OldExpr):
        return f"old({render_prusti_expression(node.expression, receiver=receiver)})"
    if isinstance(node, NotExpr):
        return "!(" + _unparenthesized(
            render_prusti_expression(node.expression, pre_state=pre_state, receiver=receiver)) + ")"
    if isinstance(node, BinaryExpr):
        operator = _OPS.get(node.kind)
        if operator is None:
            raise UnsupportedPrustiBoundary(
                f"unsupported V2 expression kind {node.kind!r}")
        left = render_prusti_expression(node.left, pre_state=pre_state, receiver=receiver)
        right = render_prusti_expression(node.right, pre_state=pre_state, receiver=receiver)
        return f"({left} {operator} {right})"
    raise UnsupportedPrustiBoundary(
        f"unsupported V2 expression node {type(node).__name__}")


def _body_expression(node, field_map: dict[str, str]) -> str:
    """Render a body term over pre-captured locals (OldExpr collapses to them)."""
    if isinstance(node, FieldExpr):
        if node.name not in field_map:
            raise UnsupportedPrustiBoundary(
                f"reviewed expression references undeclared field {node.name!r}")
        return field_map[node.name]
    if isinstance(node, IntegerExpr):
        return str(node.value)
    if isinstance(node, BooleanExpr):
        return "true" if node.value else "false"
    if isinstance(node, OldExpr):
        return _body_expression(node.expression, field_map)
    if isinstance(node, NotExpr):
        return "!(" + _unparenthesized(_body_expression(node.expression, field_map)) + ")"
    if isinstance(node, BinaryExpr):
        operator = _OPS.get(node.kind)
        if operator is None:
            raise UnsupportedPrustiBoundary(
                f"unsupported V2 expression kind {node.kind!r}")
        left = _body_expression(node.left, field_map)
        right = _body_expression(node.right, field_map)
        return f"({left} {operator} {right})"
    raise UnsupportedPrustiBoundary(
        f"unsupported V2 expression node {type(node).__name__}")


def _effect_ensures(operation) -> str:
    if not operation.effects:
        return "true"
    return " && ".join(
        f"self.{effect.target} == " +
        _unparenthesized(render_prusti_expression(effect.value, pre_state=True))
        for effect in operation.effects)


def _invariant_contract(reviewed, *, receiver: str = "self") -> str:
    conjuncts = [render_prusti_expression(expression, receiver=receiver)
                 for expression in canonical_invariant_expressions(reviewed)]
    # Parenthesize each conjunct: ==> binds looser than && in Prusti
    # and ACSL, so an unparenthesized implication would swallow the
    # entire preceding conjunction and silently weaken the invariant.
    return " && ".join(f"({_unparenthesized(conjunct)})" for conjunct in conjuncts) or "true"


def _counter_step(effect) -> int | None:
    """+1/-1 when the effect is exactly `target = target ± 1`, else None."""
    value = effect.value
    if not isinstance(value, BinaryExpr) or value.kind not in {"add", "sub"}:
        return None
    if (not isinstance(value.left, FieldExpr) or value.left.name != effect.target
            or not isinstance(value.right, IntegerExpr)
            or value.right.value != 1):
        return None
    return 1 if value.kind == "add" else -1


def _pool_counter(reviewed) -> str | None:
    """The one silicon-bounded counter the static pool can materialize.

    Pool mode engages only when a single int field sits exactly at the
    capacity bound AND every effect that writes it moves it by exactly ±1 —
    the reviewed counter-machine shape whose occupancy `[bool; CAP]`
    deterministically shadows. A non-counter write (literal/clear) or a
    second counter refuses the pool rather than inventing a sharing design;
    the machine still lowers and its bounds still prove via the reviewed
    guards and invariants.
    """
    if getattr(reviewed, "capacity_bound", None) is None:
        return None
    counters: list[str] = []
    for variable in reviewed.state_variables:
        if (not isinstance(variable, IntStateVariable)
                or variable.bound[1] != reviewed.capacity_bound):
            continue
        touched = False
        for operation in reviewed.operations:
            for effect in operation.effects:
                if effect.target != variable.name:
                    continue
                if _counter_step(effect) is None:
                    return None
                touched = True
        if touched:
            counters.append(variable.name)
    return counters[0] if len(counters) == 1 else None


def _pool_field_name(reviewed) -> str:
    return "slots_pool" if any(v.name == "slots" for v in reviewed.state_variables) else "slots"


def _render_operation(operation, variables_by_name: dict, reviewed,
                      pool_counter: str | None = None) -> list[str]:
    if operation.failure_semantics == "exception":
        raise UnsupportedPrustiBoundary(
            f"operation {operation.name!r} uses exception semantics; the "
            "deterministic Prusti subset supports void/unavailable and "
            "boolean/false_and_stutter only")
    name = _snake(operation.name)
    referenced = sorted(set().union(
        *(_referenced_fields(effect.value) for effect in operation.effects))
        if operation.effects else set())
    pre_map = {field: f"pre_{field}" for field in referenced}
    decl_map = {field: f"self.{field}" for field in variables_by_name}
    pre_locals = [f"        let pre_{field} = self.{field};"
                  for field in referenced]
    assignments = [
        f"        self.{effect.target} = " +
        _unparenthesized(_body_expression(effect.value, pre_map)) + ";"
        for effect in operation.effects]
    invariant = _invariant_contract(reviewed)
    # Static-pool occupancy maintenance: one line per ±1 effect on the
    # silicon-bounded counter (push marks pre_size occupied, pop releases
    # pre_size - 1). Index safety follows from the reviewed invariant
    # (0 <= size <= CAP) plus the op's own guards — Prusti discharges it.
    pool_lines: list[str] = []
    if pool_counter is not None:
        pool_name = _pool_field_name(reviewed)
        for effect in operation.effects:
            if effect.target != pool_counter:
                continue
            if _counter_step(effect) == 1:
                pool_lines.append(f"        self.{pool_name}[pre_{pool_counter} as usize] = true;")
            else:
                pool_lines.append(f"        self.{pool_name}[(pre_{pool_counter} - 1) as usize] = false;")
    lines: list[str] = [
        f"    #[requires({invariant})]",
    ]
    if operation.return_type == "void":
        lines.extend(
            f"    #[requires({_unparenthesized(render_prusti_expression(guard.expression))})]"
            for guard in operation.guards)
        lines.append(f"    #[ensures({_unparenthesized(_effect_ensures(operation))})]")
        lines.append(f"    #[ensures({invariant})]")
        lines.append(f"    pub fn {name}(&mut self) {{")
        lines.extend(pre_locals)
        lines.extend(assignments)
        lines.extend(pool_lines)
    else:
        guard_old = " && ".join(
            _unparenthesized(render_prusti_expression(guard.expression,
                                                      pre_state=True))
            for guard in operation.guards) or "true"
        stutter = " && ".join(
            f"self.{field} == old(self.{field})"
            for field in variables_by_name) or "true"
        lines.extend([
            f"    #[ensures(result == ({guard_old}))]",
            f"    #[ensures(result ==> ({_effect_ensures(operation)}))]",
            f"    #[ensures(!result ==> ({stutter}))]",
            f"    #[ensures({invariant})]",
            f"    pub fn {name}(&mut self) -> bool {{",
        ])
        lines.extend(pre_locals)
        if operation.guards:
            guard_now = " && ".join(
                _unparenthesized(_body_expression(guard.expression, decl_map))
                for guard in operation.guards)
            lines.append(f"        if !({guard_now}) {{")
            lines.append("            return false;")
            lines.append("        }")
        lines.extend(assignments)
        lines.extend(pool_lines)
        lines.append("        true")
    lines.append("    }")
    return lines


def render_struct(reviewed: ReviewedDomainSpecV2) -> str:
    """Assemble the complete deterministic Rust/Prusti source file."""
    if reviewed.execution_model == "async_message_passing":
        from .v2_async_serializer import render_tokio_scaffold
        return render_tokio_scaffold(reviewed)
    if reviewed.concurrency is not None:
        from .v2_lock_serializer import render_rust_mutex
        return render_rust_mutex(reviewed)
    variables_by_name = {variable.name: variable
                         for variable in reviewed.state_variables}
    pool_counter = _pool_counter(reviewed)
    pool_name = _pool_field_name(reviewed)
    lines = ["use prusti_contracts::*;", ""]
    lines.append(f"pub struct {reviewed.domain_name} {{")
    lines.extend(f"    pub {variable.name}: {_rust_type(variable)},"
                 for variable in reviewed.state_variables)
    if pool_counter is not None:
        # The silicon-derived static pool: one occupancy bit per element of
        # the hardware capacity — the reviewed counter semantics made
        # physical. No values are invented; empty is `false`.
        lines.append(f"    pub {pool_name}: [bool; {reviewed.capacity_bound}],")
    lines.extend(["}", "", f"impl {reviewed.domain_name} {{" ])
    initial = " && ".join(
        f"result.{variable.name} == " +
        (("true" if variable.initial else "false")
         if isinstance(variable, BoolStateVariable) else str(variable.initial))
        for variable in reviewed.state_variables) or "true"
    constructor_contract = f"{initial} && {_invariant_contract(reviewed, receiver='result')}"
    lines.extend([
        f"    #[ensures({constructor_contract})]",
        "    pub fn new() -> Self {",
        "        Self { " +
        ", ".join(
            f"{variable.name}: " +
            (("true" if variable.initial else "false")
             if isinstance(variable, BoolStateVariable) else str(variable.initial))
            for variable in reviewed.state_variables) +
        (f", {pool_name}: [false; {reviewed.capacity_bound}]"
         if pool_counter is not None else "") + " }",
        "    }",
    ])
    for variable in reviewed.state_variables:
        lines.extend([
            "",
            "    #[pure]",
            f"    #[ensures(result == self.{variable.name})]",
            f"    pub fn get_{variable.name}(&self) -> {_rust_type(variable)} {{",
            f"        self.{variable.name}",
            "    }",
        ])
    for operation in reviewed.operations:
        lines.append("")
        lines.extend(_render_operation(operation, variables_by_name, reviewed,
                                       pool_counter=pool_counter))
    lines.extend(["}", ""])
    return "\n".join(lines)


def render_reviewed_v2_prusti_file(path: str | Path) -> tuple[ReviewedDomainSpecV2, str]:
    """Load only a promoted artifact and serialize its exact reviewed semantics."""
    reviewed = ReviewedDomainSpecV2.model_validate_json(
        Path(path).read_text(encoding="utf-8"))
    return reviewed, render_struct(reviewed)
