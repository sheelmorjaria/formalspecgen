# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Generic transition IR and fail-closed TLA+ expression visitor."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .jml_ast import (
    BinaryExpr, BooleanLiteral, ExpressionIR, FieldAccess, IntegerLiteral,
    OldValue, Parameter, ResultValue, UnaryExpr,
)


class UnsupportedBoundaryError(ValueError):
    def __init__(self, clause: str, reason: str, method: str = ""):
        self.clause = clause
        self.reason = reason
        self.method = method
        super().__init__(f"UNSUPPORTED_BOUNDARY: {reason} in {clause}")


class LocationIR(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    receiver: str = "this"
    field: str


class AssignmentIR(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    target: LocationIR
    value: ExpressionIR


class ParameterIR(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    type: Literal["boolean", "int", "long"]


class MethodTransitionIR(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    parameters: list[ParameterIR]
    guards: list[ExpressionIR]
    success_condition: ExpressionIR | None = None
    success_effects: list[AssignmentIR]
    failure_effects: list[AssignmentIR]
    frame: list[LocationIR]
    result_constrained: bool
    atomicity: Literal["unspecified", "method_atomic", "ordered_account_locks"] = "unspecified"

    @model_validator(mode="after")
    def unique_frame(self) -> "MethodTransitionIR":
        values = {(item.receiver, item.field) for item in self.frame}
        if len(values) != len(self.frame):
            raise ValueError("frame locations must be unique")
        return self


class TLARenderer:
    """Render only the reviewed expression subset; never repair or stringify unknown AST."""

    _OPS = {
        "add": "+", "sub": "-", "lt": "<", "lte": "<=", "gt": ">",
        "gte": ">=", "eq": "=", "neq": "/=", "and": "/\\", "or": "\\/",
    }

    def __init__(self, field_variables: dict[str, str] | None = None):
        self.field_variables = field_variables or {"balance": "balances"}

    def render_expression(self, node: ExpressionIR, context: str = "self") -> str:
        if isinstance(node, IntegerLiteral):
            return str(node.value)
        if isinstance(node, BooleanLiteral):
            return "TRUE" if node.value else "FALSE"
        if isinstance(node, FieldAccess):
            variable = self.field_variables.get(node.field)
            if not variable:
                raise UnsupportedBoundaryError("FieldAccess",
                    f"field {node.field!r} has no reviewed TLA+ state-variable mapping")
            receiver = context if node.receiver == "this" else self._identifier(node.receiver)
            return f"{variable}[{receiver}]"
        if isinstance(node, Parameter):
            return self._identifier(node.name)
        if isinstance(node, OldValue):
            return self.render_expression(node.expression, context)
        if isinstance(node, ResultValue):
            raise UnsupportedBoundaryError("ResultValue",
                "\\result must be compiled into success/failure transitions before rendering")
        if isinstance(node, UnaryExpr):
            if node.kind != "not":
                raise UnsupportedBoundaryError("UnaryExpr",
                    f"unary operation {node.kind!r} has no reviewed TLA+ mapping")
            return f"~({self.render_expression(node.operand, context)})"
        if isinstance(node, BinaryExpr):
            if node.kind in {"mul", "div"}:
                raise UnsupportedBoundaryError("BinaryExpr",
                    "nonlinear arithmetic has no reviewed TLA+ IR mapping")
            operator = self._OPS.get(node.kind)
            if not operator:
                raise UnsupportedBoundaryError("BinaryExpr",
                    f"binary operation {node.kind!r} must be lowered before TLA+ rendering")
            left = self.render_expression(node.left, context)
            right = self.render_expression(node.right, context)
            return f"({left} {operator} {right})"
        raise UnsupportedBoundaryError("Expression",
            f"AST node {type(node).__name__!r} is outside the supported TLA+ subset")

    @staticmethod
    def _identifier(value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise UnsupportedBoundaryError("Identifier", f"unsafe identifier {value!r}")
        return value


def flatten_and(node: ExpressionIR) -> list[ExpressionIR]:
    if isinstance(node, BinaryExpr) and node.kind == "and":
        return [*flatten_and(node.left), *flatten_and(node.right)]
    return [node]


def assignment_from_equality(node: ExpressionIR) -> AssignmentIR | None:
    """Recognize post-state field equality; preserve the RHS as a typed expression."""
    if not isinstance(node, BinaryExpr) or node.kind != "eq" or not isinstance(node.left, FieldAccess):
        return None
    return AssignmentIR(target=LocationIR(receiver=node.left.receiver, field=node.left.field),
                        value=node.right)
