# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic reviewed-V2 to bounded C++17 serialization."""
from __future__ import annotations

import re

from .domain_v2 import (
    BinaryExpr, BooleanExpr, BoolStateVariable, FieldExpr, IntStateVariable,
    IntegerExpr, NotExpr, OldExpr, _referenced_fields,
)
from .domain_v2_promotion import ReviewedDomainSpecV2
from .v2_invariants import canonical_invariant_expressions
from .v2_jml_serializer import _OPS


class UnsupportedCppBoundary(ValueError):
    """Reviewed semantics outside the deterministic C++ subset."""


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def _unparenthesized(text: str) -> str:
    return text[1:-1] if text.startswith("(") and text.endswith(")") else text


def _type(variable) -> str:
    return "bool" if isinstance(variable, BoolStateVariable) else "int"


def _expr(node, *, old: bool = False) -> str:
    if isinstance(node, FieldExpr):
        return f"this->{node.name}" if old else node.name
    if isinstance(node, IntegerExpr):
        return str(node.value)
    if isinstance(node, BooleanExpr):
        return "true" if node.value else "false"
    if isinstance(node, OldExpr):
        return _expr(node.expression, old=True)
    if isinstance(node, NotExpr):
        return "!(" + _unparenthesized(_expr(node.expression, old=old)) + ")"
    if isinstance(node, BinaryExpr):
        operator = {**_OPS, "implies": "==>"}.get(node.kind)
        if node.kind == "implies":
            return ("(!(" + _expr(node.left, old=old) + ") || (" +
                    _expr(node.right, old=old) + "))")
        if operator is None:
            raise UnsupportedCppBoundary(f"unsupported V2 expression kind {node.kind!r}")
        operator = {"&&": "&&", "||": "||"}.get(operator, operator)
        return f"({_expr(node.left, old=old)} {operator} {_expr(node.right, old=old)})"
    raise UnsupportedCppBoundary(f"unsupported V2 expression node {type(node).__name__}")


def _invariant(reviewed) -> str:
    terms = [_expr(item) for item in canonical_invariant_expressions(reviewed)]
    return " && ".join(f"({_unparenthesized(term)})" for term in terms) or "true"


def _effect_expr(node, locals_by_name: dict[str, str]) -> str:
    if isinstance(node, FieldExpr):
        if node.name not in locals_by_name:
            raise UnsupportedCppBoundary(f"unknown effect field {node.name!r}")
        return locals_by_name[node.name]
    if isinstance(node, OldExpr):
        return _effect_expr(node.expression, locals_by_name)
    if isinstance(node, (IntegerExpr, BooleanExpr, NotExpr, BinaryExpr)):
        if isinstance(node, NotExpr):
            return "!(" + _unparenthesized(_effect_expr(node.expression, locals_by_name)) + ")"
        if isinstance(node, BinaryExpr):
            operator = {**_OPS, "implies": "==>"}.get(node.kind)
            if node.kind == "implies":
                return ("(!(" + _effect_expr(node.left, locals_by_name) + ") || (" +
                        _effect_expr(node.right, locals_by_name) + "))")
            if operator is None:
                raise UnsupportedCppBoundary(f"unsupported V2 expression kind {node.kind!r}")
            return f"({_effect_expr(node.left, locals_by_name)} {operator} " \
                   f"{_effect_expr(node.right, locals_by_name)})"
        return _expr(node)
    raise UnsupportedCppBoundary(f"unsupported effect node {type(node).__name__}")


def render_cpp(reviewed: ReviewedDomainSpecV2) -> str:
    """Render a standalone C++17 class with assertion-based bounded evidence."""
    if reviewed.execution_model == "async_message_passing":
        raise UnsupportedCppBoundary("async_message_passing lowering is restricted to Rust Tokio")
    if reviewed.concurrency is not None:
        raise UnsupportedCppBoundary("C++ lock lowering requires a dedicated mutex model")
    fields = {item.name: item for item in reviewed.state_variables}
    invariant = _invariant(reviewed)
    lines = ["#include <cassert>", "", f"class {reviewed.domain_name} {{", "private:"]
    lines.extend(f"    {_type(item)} {item.name};" for item in reviewed.state_variables)
    lines.extend(["", "    void check_invariants() const {", f"        assert({invariant});",
                  "    }", "", "public:"])
    initializers = ", ".join(f"{item.name}({'true' if item.initial else 'false'}"
                              f")" if isinstance(item, BoolStateVariable)
                              else f"{item.name}({item.initial})"
                              for item in reviewed.state_variables)
    lines.extend([f"    {reviewed.domain_name}() : {initializers} {{", "        check_invariants();",
                  "    }"])
    for operation in reviewed.operations:
        if operation.failure_semantics == "exception":
            raise UnsupportedCppBoundary("exception operation semantics are unsupported")
        name = _snake(operation.name)
        return_type = "bool" if operation.return_type == "boolean" else "void"
        lines.extend(["", f"    {return_type} {name}() {{"])
        for guard in operation.guards:
            guard_text = _expr(guard.expression)
            if return_type == "bool":
                lines.append(f"        if (!({guard_text})) return false;")
            else:
                lines.append(f"        assert({guard_text});")
        referenced = sorted(set().union(
            *(_referenced_fields(effect.value) for effect in operation.effects))
            if operation.effects else set())
        locals_by_name = {field: f"pre_{field}" for field in referenced}
        lines.extend(f"        const {_type(fields[field])} pre_{field} = {field};"
                     for field in referenced)
        lines.extend(f"        {effect.target} = {_effect_expr(effect.value, locals_by_name)};"
                     for effect in operation.effects)
        lines.append("        check_invariants();")
        if return_type == "bool":
            lines.append("        return true;")
        lines.append("    }")
    lines.extend(["};", ""])
    return "\n".join(lines)


def render_reviewed_v2_cpp_file(path) -> tuple[ReviewedDomainSpecV2, str]:
    reviewed = ReviewedDomainSpecV2.model_validate_json(__import__("pathlib").Path(path).read_text())
    return reviewed, render_cpp(reviewed)
