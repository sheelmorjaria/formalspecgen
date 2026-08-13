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


class UnsupportedPrustiBoundary(ValueError):
    """The reviewed semantics leave the deterministic Prusti subset."""


def _unparenthesized(text: str) -> str:
    return text[1:-1] if text.startswith("(") and text.endswith(")") else text


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def _rust_type(variable) -> str:
    return "i32" if isinstance(variable, IntStateVariable) else "bool"


def render_prusti_expression(node, *, pre_state: bool = False) -> str:
    """Render a reviewed V2 expression in Prusti macro syntax."""
    if isinstance(node, FieldExpr):
        base = f"self.{node.name}"
        return f"old({base})" if pre_state else base
    if isinstance(node, IntegerExpr):
        return str(node.value)
    if isinstance(node, BooleanExpr):
        return "true" if node.value else "false"
    if isinstance(node, OldExpr):
        return f"old({render_prusti_expression(node.expression)})"
    if isinstance(node, NotExpr):
        return "!(" + _unparenthesized(
            render_prusti_expression(node.expression, pre_state=pre_state)) + ")"
    if isinstance(node, BinaryExpr):
        operator = _OPS.get(node.kind)
        if operator is None:
            raise UnsupportedPrustiBoundary(
                f"unsupported V2 expression kind {node.kind!r}")
        left = render_prusti_expression(node.left, pre_state=pre_state)
        right = render_prusti_expression(node.right, pre_state=pre_state)
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


def _render_operation(operation, variables_by_name: dict) -> list[str]:
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
    lines: list[str] = []
    if operation.return_type == "void":
        lines.extend(
            f"    #[requires({_unparenthesized(render_prusti_expression(guard.expression))})]"
            for guard in operation.guards)
        lines.append(f"    #[ensures({_unparenthesized(_effect_ensures(operation))})]")
        lines.append(f"    pub fn {name}(&mut self) {{")
        lines.extend(pre_locals)
        lines.extend(assignments)
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
        lines.append("        true")
    lines.append("    }")
    return lines


def _bounds_invariant(variable) -> BinaryExpr:
    lower, upper = variable.bound
    return BinaryExpr(
        kind="and",
        left=BinaryExpr(kind="lte", left=IntegerExpr(value=lower),
                        right=FieldExpr(name=variable.name)),
        right=BinaryExpr(kind="lte", left=FieldExpr(name=variable.name),
                         right=IntegerExpr(value=upper)),
    )


def render_struct(reviewed: ReviewedDomainSpecV2) -> str:
    """Assemble the complete deterministic Rust/Prusti source file."""
    variables_by_name = {variable.name: variable
                         for variable in reviewed.state_variables}
    lines = ["use prusti_contracts::*;", ""]
    invariants = [
        _bounds_invariant(variable)
        for variable in reviewed.state_variables
        if isinstance(variable, IntStateVariable)
    ] + [item.expression for item in reviewed.tlc_invariants]
    for expression in invariants:
        lines.append(
            f"#[invariant({_unparenthesized(render_prusti_expression(expression))})]")
    lines.append(f"pub struct {reviewed.domain_name} {{")
    lines.extend(f"    pub {variable.name}: {_rust_type(variable)},"
                 for variable in reviewed.state_variables)
    lines.extend(["}", "", f"impl {reviewed.domain_name} {{" ])
    initial = " && ".join(
        f"result.{variable.name} == " +
        (("true" if variable.initial else "false")
         if isinstance(variable, BoolStateVariable) else str(variable.initial))
        for variable in reviewed.state_variables) or "true"
    lines.extend([
        f"    #[ensures({initial})]",
        "    pub fn new() -> Self {",
        "        Self { " +
        ", ".join(
            f"{variable.name}: " +
            (("true" if variable.initial else "false")
             if isinstance(variable, BoolStateVariable) else str(variable.initial))
            for variable in reviewed.state_variables) + " }",
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
        lines.extend(_render_operation(operation, variables_by_name))
    lines.extend(["}", ""])
    return "\n".join(lines)


def render_reviewed_v2_prusti_file(path: str | Path) -> tuple[ReviewedDomainSpecV2, str]:
    """Load only a promoted artifact and serialize its exact reviewed semantics."""
    reviewed = ReviewedDomainSpecV2.model_validate_json(
        Path(path).read_text(encoding="utf-8"))
    return reviewed, render_struct(reviewed)
