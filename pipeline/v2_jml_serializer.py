# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic reviewed-V2 to Java/JML contract serialization."""
from __future__ import annotations

from pathlib import Path

from .domain_v2 import (
    BinaryExpr, BooleanExpr, BoolStateVariable, DomainSpecV2, FieldExpr,
    IntegerExpr, IntStateVariable, NotExpr, OldExpr, Operation,
)
from .domain_v2_promotion import ReviewedDomainSpecV2
from .extract_tla_ir import UnsupportedJmlSemantics
from .v2_invariants import canonical_invariant_expressions

_OPS = {
    "eq": "==", "neq": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">=",
    "add": "+", "sub": "-", "implies": "==>", "and": "&&", "or": "||",
}


def render_expression(node, *, pre_state: bool = False) -> str:
    """Render the reviewed expression subset; optionally interpret fields in the pre-state."""
    if isinstance(node, FieldExpr):
        return rf"\old({node.name})" if pre_state else node.name
    if isinstance(node, IntegerExpr):
        return str(node.value)
    if isinstance(node, BooleanExpr):
        return "true" if node.value else "false"
    if isinstance(node, OldExpr):
        return rf"\old({render_expression(node.expression)})"
    if isinstance(node, NotExpr):
        return f"!({render_expression(node.expression, pre_state=pre_state)})"
    if isinstance(node, BinaryExpr):
        operator = _OPS.get(node.kind)
        if operator is None:
            raise UnsupportedJmlSemantics(f"unsupported V2 expression kind {node.kind!r}")
        left = render_expression(node.left, pre_state=pre_state)
        right = render_expression(node.right, pre_state=pre_state)
        return f"({left} {operator} {right})"
    raise UnsupportedJmlSemantics(
        f"unsupported V2 expression node {type(node).__name__}")


def render_state_variable(variable) -> list[str]:
    if isinstance(variable, IntStateVariable):
        lower, upper = variable.bound
        return [f"    private /*@ spec_public @*/ int {variable.name};",
                f"    //@ public invariant {lower} <= {variable.name} && "
                f"{variable.name} <= {upper};"]
    if isinstance(variable, BoolStateVariable):
        return [f"    private /*@ spec_public @*/ boolean {variable.name};"]
    raise UnsupportedJmlSemantics(
        f"unsupported V2 state variable {type(variable).__name__}")


def _conjunction(expressions: list[str]) -> str:
    return " && ".join(expressions) if expressions else "true"


def canonical_guard_expressions(operation: Operation) -> list:
    """Canonicalize equivalent integer inequalities and remove exact duplicates."""
    result, seen = [], set()
    for guard in operation.guards:
        expression = guard.expression
        if (isinstance(expression, BinaryExpr) and
                isinstance(expression.right, IntegerExpr) and
                expression.kind in {"lt", "gt"}):
            expression = expression.model_copy(update={
                "kind": "lte" if expression.kind == "lt" else "gte",
                "right": IntegerExpr(value=(expression.right.value - 1
                                             if expression.kind == "lt"
                                             else expression.right.value + 1)),
            })
        key = expression.model_dump_json()
        if key not in seen:
            seen.add(key); result.append(expression)
    return result


def java_method_name(action_name: str) -> str:
    """Map a reviewed TLA+ action identifier to Java lower camel case."""
    if not action_name:
        raise UnsupportedJmlSemantics("V2 operation name cannot be empty")
    return action_name[0].lower() + action_name[1:]


def _getter_name(field_name: str) -> str:
    suffix = "".join(
        part[0].upper() + part[1:] for part in field_name.split("_") if part)
    if not suffix:
        raise UnsupportedJmlSemantics("V2 state field name cannot be empty")
    return "get" + suffix


def render_getter(variable) -> str:
    if isinstance(variable, IntStateVariable):
        java_type = "int"
    elif isinstance(variable, BoolStateVariable):
        java_type = "boolean"
    else:
        raise UnsupportedJmlSemantics(
            f"unsupported V2 getter variable {type(variable).__name__}")
    return "\n".join([
        "    //@ assignable \\nothing;",
        f"    //@ ensures \\result == {variable.name};",
        f"    public /*@ pure @*/ {java_type} {_getter_name(variable.name)}() "
        f"{{ return {variable.name}; }}",
    ])


def _effect_expression(operation: Operation) -> str:
    return _conjunction([
        f"{effect.target} == {render_expression(effect.value, pre_state=True)}"
        for effect in operation.effects
    ])


def render_operation(operation: Operation, state_fields: list[str]) -> str:
    lines: list[str] = []
    method_name = java_method_name(operation.name)
    if operation.return_type == "void" and operation.failure_semantics == "unavailable":
        lines.extend(f"    //@ requires {render_expression(expression)};"
                     for expression in canonical_guard_expressions(operation))
        frame = ", ".join(operation.frame) if operation.frame else r"\nothing"
        lines.append(f"    //@ assignable {frame};")
        lines.append(f"    //@ ensures {_effect_expression(operation)};")
        lines.append(f"    public void {method_name}() {{}}")
        return "\n".join(lines)
    if operation.return_type == "boolean" and operation.failure_semantics == "false_and_stutter":
        guard = _conjunction([
            render_expression(item, pre_state=True)
            for item in canonical_guard_expressions(operation)])
        frame = ", ".join(operation.frame) if operation.frame else r"\nothing"
        lines.extend([
            f"    //@ assignable {frame};",
            f"    //@ ensures \\result <==> ({guard});",
            f"    //@ ensures \\result ==> ({_effect_expression(operation)});",
            "    //@ ensures !\\result ==> (" + _conjunction([
                rf"{field} == \old({field})" for field in state_fields]) + ");",
            f"    public boolean {method_name}() {{ return false; }}",
        ])
        return "\n".join(lines)
    raise UnsupportedJmlSemantics(
        f"unsupported V2 operation semantics for {operation.name}: "
        f"{operation.return_type}/{operation.failure_semantics}")


def render_class(spec: DomainSpecV2) -> str:
    """Assemble a complete deterministic Java/JML contract from typed V2 semantics."""
    state_fields = [item.name for item in spec.state_variables]
    lines = [f"public class {spec.domain_name} {{"]
    for variable in spec.state_variables:
        rendered = render_state_variable(variable)
        lines.append(rendered[0])
    lines.append("")
    lines.extend(
        f"    //@ public invariant {render_expression(expression)};"
        for expression in canonical_invariant_expressions(spec))
    initial = _conjunction([
        f"{item.name} == " + (("true" if item.initial else "false")
                              if isinstance(item, BoolStateVariable) else str(item.initial))
        for item in spec.state_variables])
    # OpenJML forbids references to the not-yet-constructed receiver in a
    # constructor frame.  Fresh-object field initialization is permitted by
    # ``assignable \\nothing`` while mutation of pre-existing heap state is not.
    constructor_frame = r"\nothing"
    lines.extend(["", f"    //@ assignable {constructor_frame};",
                  f"    //@ ensures {initial};", f"    public {spec.domain_name}() {{"])
    for item in spec.state_variables:
        value = (("true" if item.initial else "false")
                 if isinstance(item, BoolStateVariable) else str(item.initial))
        lines.append(f"        this.{item.name} = {value};")
    lines.append("    }")
    for variable in spec.state_variables:
        lines.extend(["", render_getter(variable)])
    for operation in spec.operations:
        lines.extend(["", render_operation(operation, state_fields)])
    lines.extend(["}", ""])
    return "\n".join(lines)


def render_reviewed_v2_file(path: str | Path) -> tuple[ReviewedDomainSpecV2, str]:
    """Load only a promoted artifact and serialize its exact reviewed semantics."""
    reviewed = ReviewedDomainSpecV2.model_validate_json(
        Path(path).read_text(encoding="utf-8"))
    return reviewed, render_class(reviewed)
