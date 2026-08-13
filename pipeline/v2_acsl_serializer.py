# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic reviewed-V2 to C/ACSL serialization.

Completes the polyglot single-contract-source discipline: every ACSL
requires/assigns/ensures clause is derived from the promoted V2 typed
expression trees and function bodies transcribe the reviewed effects
(pre-captured locals preserve simultaneous-assignment semantics).  ACSL has no
persistent struct invariants, so reviewed invariants are assumed by
`requires` on entry and re-established by `ensures` on exit of every mutator.
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


class UnsupportedAcslBoundary(ValueError):
    """The reviewed semantics leave the deterministic ACSL subset."""


def _unparenthesized(text: str) -> str:
    return text[1:-1] if text.startswith("(") and text.endswith(")") else text


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def _c_type(variable) -> str:
    return "int" if isinstance(variable, IntStateVariable) else "_Bool"


def _literal(variable) -> str:
    if isinstance(variable, BoolStateVariable):
        return "1" if variable.initial else "0"
    return str(variable.initial)


def render_acsl_expression(node, *, pre_state: bool = False) -> str:
    """Render a reviewed V2 expression in ACSL syntax over the state pointer."""
    if isinstance(node, FieldExpr):
        base = f"counter->{node.name}"
        return rf"\old({base})" if pre_state else base
    if isinstance(node, IntegerExpr):
        return str(node.value)
    if isinstance(node, BooleanExpr):
        return "1" if node.value else "0"
    if isinstance(node, OldExpr):
        return rf"\old({render_acsl_expression(node.expression)})"
    if isinstance(node, NotExpr):
        return "!(" + _unparenthesized(render_acsl_expression(
            node.expression, pre_state=pre_state)) + ")"
    if isinstance(node, BinaryExpr):
        operator = _OPS.get(node.kind)
        if operator is None:
            raise UnsupportedAcslBoundary(
                f"unsupported V2 expression kind {node.kind!r}")
        left = render_acsl_expression(node.left, pre_state=pre_state)
        right = render_acsl_expression(node.right, pre_state=pre_state)
        return f"({left} {operator} {right})"
    raise UnsupportedAcslBoundary(
        f"unsupported V2 expression node {type(node).__name__}")


def _body_expression(node, field_map: dict[str, str]) -> str:
    """Render a body term over pre-captured locals (OldExpr collapses to them)."""
    if isinstance(node, FieldExpr):
        if node.name not in field_map:
            raise UnsupportedAcslBoundary(
                f"reviewed expression references undeclared field {node.name!r}")
        return field_map[node.name]
    if isinstance(node, IntegerExpr):
        return str(node.value)
    if isinstance(node, BooleanExpr):
        return "1" if node.value else "0"
    if isinstance(node, OldExpr):
        return _body_expression(node.expression, field_map)
    if isinstance(node, NotExpr):
        return "!(" + _unparenthesized(
            _body_expression(node.expression, field_map)) + ")"
    if isinstance(node, BinaryExpr):
        operator = _OPS.get(node.kind)
        if operator is None:
            raise UnsupportedAcslBoundary(
                f"unsupported V2 expression kind {node.kind!r}")
        left = _body_expression(node.left, field_map)
        right = _body_expression(node.right, field_map)
        return f"({left} {operator} {right})"
    raise UnsupportedAcslBoundary(
        f"unsupported V2 expression node {type(node).__name__}")


def _bounds_invariant(variable) -> BinaryExpr:
    lower, upper = variable.bound
    return BinaryExpr(
        kind="and",
        left=BinaryExpr(kind="lte", left=IntegerExpr(value=lower),
                        right=FieldExpr(name=variable.name)),
        right=BinaryExpr(kind="lte", left=FieldExpr(name=variable.name),
                         right=IntegerExpr(value=upper)),
    )


def _invariant_contract(reviewed) -> str:
    expressions = ([_bounds_invariant(variable)
                    for variable in reviewed.state_variables
                    if isinstance(variable, IntStateVariable)]
                   + [item.expression for item in reviewed.tlc_invariants])
    return " && ".join(_unparenthesized(render_acsl_expression(expression))
                       for expression in expressions) or "\\true"


def _effect_ensures(operation) -> str:
    if not operation.effects:
        return "\\true"
    return " && ".join(
        f"counter->{effect.target} == " +
        _unparenthesized(render_acsl_expression(effect.value, pre_state=True))
        for effect in operation.effects)


def _frame(operation) -> str:
    return (", ".join(f"counter->{name}" for name in operation.frame)
            if operation.frame else "\\nothing")


def _render_operation(operation, variables_by_name: dict, reviewed,
                      module: str) -> list[str]:
    if operation.failure_semantics == "exception":
        raise UnsupportedAcslBoundary(
            f"operation {operation.name!r} uses exception semantics; the "
            "deterministic ACSL subset supports void/unavailable and "
            "boolean/false_and_stutter only")
    name = f"{module}_{_snake(operation.name)}"
    referenced = sorted(set().union(
        *(_referenced_fields(effect.value) for effect in operation.effects))
        if operation.effects else set())
    pre_map = {field: f"pre_{field}" for field in referenced}
    decl_map = {field: f"counter->{field}" for field in variables_by_name}
    invariant = _invariant_contract(reviewed)
    lines = [
        "/*@",
        r"  requires \valid(counter);",
        f"  requires {invariant};",
    ]
    lines.extend(
        f"  requires {_unparenthesized(render_acsl_expression(guard.expression))};"
        for guard in operation.guards)
    lines.append(f"  assigns {_frame(operation)};")
    if operation.return_type == "void":
        lines.append(f"  ensures {_unparenthesized(_effect_ensures(operation))};")
        lines.append(f"  ensures {invariant};")
        lines.append("*/")
        lines.append(f"void {name}({module} *counter) {{")
        lines.extend(f"    {_c_type(variables_by_name[field])} "
                     f"pre_{field} = counter->{field};"
                     for field in referenced)
        lines.extend(
            f"    counter->{effect.target} = " +
            _unparenthesized(_body_expression(effect.value, pre_map)) + ";"
            for effect in operation.effects)
    else:
        guard_old = " && ".join(
            _unparenthesized(render_acsl_expression(guard.expression,
                                                    pre_state=True))
            for guard in operation.guards) or "\\true"
        stutter = " && ".join(
            rf"counter->{field} == \old(counter->{field})"
            for field in variables_by_name) or "\\true"
        lines.extend([
            rf"  ensures \result == ({guard_old});",
            rf"  ensures \result ==> ({_unparenthesized(_effect_ensures(operation))});",
            rf"  ensures !\result ==> ({stutter});",
            f"  ensures {invariant};",
            "*/",
            f"int {name}({module} *counter) {{",
        ])
        lines.extend(f"    {_c_type(variables_by_name[field])} "
                     f"pre_{field} = counter->{field};"
                     for field in referenced)
        if operation.guards:
            guard_now = " && ".join(
                _unparenthesized(_body_expression(guard.expression, decl_map))
                for guard in operation.guards)
            lines.extend([
                f"    if (!({guard_now})) {{",
                "        return 0;",
                "    }",
            ])
        lines.extend(
            f"    counter->{effect.target} = " +
            _unparenthesized(_body_expression(effect.value, pre_map)) + ";"
            for effect in operation.effects)
        lines.append("    return 1;")
    lines.append("}")
    return lines


def render_translation_unit(reviewed: ReviewedDomainSpecV2) -> str:
    """Assemble the complete deterministic C/ACSL translation unit."""
    module = reviewed.module_name
    variables_by_name = {variable.name: variable
                         for variable in reviewed.state_variables}
    lines = [
        f"/* Deterministic contract lowered from the reviewed V2 domain "
        f"'{module}'.",
        " * Human review of the reviewed artifact is required before trust. */",
        "",
        "typedef struct {",
    ]
    lines.extend(f"    {_c_type(variable)} {variable.name};"
                 for variable in reviewed.state_variables)
    lines.extend([f"}} {module};", ""])

    initial = " && ".join(
        f"counter->{variable.name} == {_literal(variable)}"
        for variable in reviewed.state_variables) or "\\true"
    lines.extend([
        "/*@",
        r"  requires \valid(counter);",
        "  assigns " + ", ".join(
            f"counter->{variable.name}"
            for variable in reviewed.state_variables) + ";",
        f"  ensures {initial};",
        f"  ensures {_invariant_contract(reviewed)};",
        "*/",
        f"void {module}_init({module} *counter) {{",
    ])
    lines.extend(
        f"    counter->{variable.name} = {_literal(variable)};"
        for variable in reviewed.state_variables)
    lines.extend(["}", ""])

    for variable in reviewed.state_variables:
        lines.extend([
            "/*@",
            r"  requires \valid_read(counter);",
            r"  assigns \nothing;",
            f"  ensures \\result == counter->{variable.name};",
            "*/",
            f"{_c_type(variable)} {module}_get_{variable.name}"
            f"(const {module} *counter) {{",
            f"    return counter->{variable.name};",
            "}",
            "",
        ])

    for operation in reviewed.operations:
        lines.extend(
            _render_operation(operation, variables_by_name, reviewed, module))
        lines.append("")
    return "\n".join(lines)


def render_reviewed_v2_acsl_file(path: str | Path) -> tuple[ReviewedDomainSpecV2, str]:
    """Load only a promoted artifact and serialize its exact reviewed semantics."""
    reviewed = ReviewedDomainSpecV2.model_validate_json(
        Path(path).read_text(encoding="utf-8"))
    return reviewed, render_translation_unit(reviewed)
