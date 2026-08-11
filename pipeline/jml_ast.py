# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Typed AST and deterministic parser for the reviewed JML expression subset."""
from __future__ import annotations

import re
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field


class _Node(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class IntegerLiteral(_Node):
    kind: Literal["integer"] = "integer"
    value: int


class BooleanLiteral(_Node):
    kind: Literal["boolean"] = "boolean"
    value: bool


class Parameter(_Node):
    kind: Literal["parameter"] = "parameter"
    name: str


class ResultValue(_Node):
    kind: Literal["result"] = "result"


class FieldAccess(_Node):
    kind: Literal["field"] = "field"
    receiver: str = "this"
    field: str


class OldValue(_Node):
    kind: Literal["old"] = "old"
    expression: "ExpressionIR"


class UnaryExpr(_Node):
    kind: Literal["not", "neg"]
    operand: "ExpressionIR"


class BinaryExpr(_Node):
    kind: Literal[
        "add", "sub", "mul", "div", "lt", "lte", "gt", "gte", "eq", "neq",
        "and", "or", "implies", "iff",
    ]
    left: "ExpressionIR"
    right: "ExpressionIR"


ExpressionIR = Annotated[Union[
    IntegerLiteral, BooleanLiteral, Parameter, ResultValue, FieldAccess,
    OldValue, UnaryExpr, BinaryExpr,
], Field(discriminator="kind")]

OldValue.model_rebuild()
UnaryExpr.model_rebuild()
BinaryExpr.model_rebuild()


class JmlExpressionSyntaxError(ValueError):
    def __init__(self, source: str, offset: int, reason: str):
        self.source = source
        self.offset = offset
        self.reason = reason
        super().__init__(f"{reason} at offset {offset}: {source!r}")


_TOKEN = re.compile(
    r"\s*(?:(?P<old>\\old)|(?P<result>\\result)|"
    r"(?P<number>\d+)(?P<long>[lL])?|(?P<ident>[A-Za-z_$][\w$]*)|"
    r"(?P<op><==>|==>|&&|\|\||<=|>=|==|!=|[()+\-*/!<>,.]))"
)

_BINARY = {
    "<==>": ("iff", 1), "==>": ("implies", 2), "||": ("or", 3),
    "&&": ("and", 4), "==": ("eq", 5), "!=": ("neq", 5),
    "<": ("lt", 6), "<=": ("lte", 6), ">": ("gt", 6), ">=": ("gte", 6),
    "+": ("add", 7), "-": ("sub", 7), "*": ("mul", 8), "/": ("div", 8),
}


class _Parser:
    def __init__(self, source: str, fields: set[str], parameters: set[str]):
        self.source = source.strip().rstrip(";").strip()
        self.fields = fields
        self.parameters = parameters
        self.tokens: list[tuple[str, str, int]] = []
        position = 0
        while position < len(self.source):
            match = _TOKEN.match(self.source, position)
            if not match:
                raise JmlExpressionSyntaxError(self.source, position, "unsupported token")
            kind = next(name for name, value in match.groupdict().items()
                        if value is not None and name != "long")
            self.tokens.append((kind, match.group(kind), match.start(kind)))
            position = match.end()
        self.index = 0

    def parse(self) -> ExpressionIR:
        if not self.tokens:
            raise JmlExpressionSyntaxError(self.source, 0, "empty expression")
        result = self.expression(1)
        if self.index != len(self.tokens):
            token = self.tokens[self.index]
            raise JmlExpressionSyntaxError(self.source, token[2], f"unexpected token {token[1]!r}")
        return result

    def expression(self, minimum: int) -> ExpressionIR:
        left = self.prefix()
        while self.index < len(self.tokens):
            token = self.tokens[self.index]
            if token[0] != "op" or token[1] not in _BINARY:
                break
            kind, precedence = _BINARY[token[1]]
            if precedence < minimum:
                break
            self.index += 1
            # Implication is right-associative; arithmetic/Boolean operators are left-associative.
            right = self.expression(precedence if kind == "implies" else precedence + 1)
            left = BinaryExpr(kind=kind, left=left, right=right)
        return left

    def prefix(self) -> ExpressionIR:
        if self.index >= len(self.tokens):
            raise JmlExpressionSyntaxError(self.source, len(self.source), "expected expression")
        kind, value, offset = self.tokens[self.index]
        self.index += 1
        if kind == "number":
            return IntegerLiteral(value=int(value))
        if kind == "result":
            return ResultValue()
        if kind == "old":
            self._expect("(")
            expression = self.expression(1)
            self._expect(")")
            return OldValue(expression=expression)
        if kind == "op" and value in {"!", "-"}:
            return UnaryExpr(kind="not" if value == "!" else "neg", operand=self.prefix())
        if kind == "op" and value == "(":
            expression = self.expression(1)
            self._expect(")")
            return expression
        if kind == "ident":
            if value in {"true", "false"}:
                return BooleanLiteral(value=value == "true")
            if self._accept("."):
                field = self._take_ident()
                return FieldAccess(receiver=value, field=field)
            if value in self.fields:
                return FieldAccess(field=value)
            if value in self.parameters:
                return Parameter(name=value)
            raise JmlExpressionSyntaxError(self.source, offset, f"unknown identifier {value!r}")
        raise JmlExpressionSyntaxError(self.source, offset, f"unexpected token {value!r}")

    def _accept(self, value: str) -> bool:
        if self.index < len(self.tokens) and self.tokens[self.index][1] == value:
            self.index += 1
            return True
        return False

    def _expect(self, value: str) -> None:
        if not self._accept(value):
            offset = self.tokens[self.index][2] if self.index < len(self.tokens) else len(self.source)
            raise JmlExpressionSyntaxError(self.source, offset, f"expected {value!r}")

    def _take_ident(self) -> str:
        if self.index >= len(self.tokens) or self.tokens[self.index][0] != "ident":
            offset = self.tokens[self.index][2] if self.index < len(self.tokens) else len(self.source)
            raise JmlExpressionSyntaxError(self.source, offset, "expected field name")
        value = self.tokens[self.index][1]
        self.index += 1
        return value


def parse_jml_expression(source: str, *, fields: set[str] | None = None,
                         parameters: set[str] | None = None) -> ExpressionIR:
    """Parse one expression with Java/JML precedence; reject every unknown token/name."""
    return _Parser(source, fields or set(), parameters or set()).parse()
