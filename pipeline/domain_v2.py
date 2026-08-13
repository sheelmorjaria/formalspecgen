# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Typed V2 candidate-domain schema.

This module is intentionally isolated from the active V1 loader and CLI. Parsing a V2 candidate
does not validate, review, register, render, or promote a domain.
"""
from __future__ import annotations

import re
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _safe_identifier(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise ValueError("value must be a safe identifier")
    return value


class FieldExpr(_StrictModel):
    kind: Literal["field"] = "field"
    name: str

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        return _safe_identifier(value)


class IntegerExpr(_StrictModel):
    kind: Literal["integer"] = "integer"
    value: int


class BooleanExpr(_StrictModel):
    kind: Literal["boolean"] = "boolean"
    value: bool


class OldExpr(_StrictModel):
    kind: Literal["old"] = "old"
    expression: "ExpressionIR"


class NotExpr(_StrictModel):
    kind: Literal["not"] = "not"
    expression: "ExpressionIR"


class BinaryExpr(_StrictModel):
    kind: Literal[
        "eq", "neq", "lt", "lte", "gt", "gte", "add", "sub",
        "implies", "and", "or",
    ]
    left: "ExpressionIR"
    right: "ExpressionIR"


ExpressionIR = Annotated[
    Union[FieldExpr, IntegerExpr, BooleanExpr, OldExpr, NotExpr, BinaryExpr],
    Field(discriminator="kind"),
]
_EXPRESSION_NAMESPACE = {"ExpressionIR": ExpressionIR}
OldExpr.model_rebuild(_types_namespace=_EXPRESSION_NAMESPACE)
NotExpr.model_rebuild(_types_namespace=_EXPRESSION_NAMESPACE)
BinaryExpr.model_rebuild(_types_namespace=_EXPRESSION_NAMESPACE)


class IntStateVariable(_StrictModel):
    kind: Literal["int"] = "int"
    name: str
    bound: tuple[int, int]
    initial: int

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        return _safe_identifier(value)

    @model_validator(mode="after")
    def valid_range(self) -> "IntStateVariable":
        lower, upper = self.bound
        if lower >= upper:
            raise ValueError("integer bounds must satisfy lower < upper")
        if not lower <= self.initial <= upper:
            raise ValueError("initial value must be within bounds")
        return self


class BoolStateVariable(_StrictModel):
    kind: Literal["bool"] = "bool"
    name: str
    initial: bool

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        return _safe_identifier(value)


StateVariable = Annotated[
    Union[IntStateVariable, BoolStateVariable], Field(discriminator="kind")]


class Guard(_StrictModel):
    id: str
    expression: ExpressionIR

    @field_validator("id")
    @classmethod
    def safe_id(cls, value: str) -> str:
        return _safe_identifier(value)


class Effect(_StrictModel):
    id: str
    target: str
    value: ExpressionIR

    @field_validator("id", "target")
    @classmethod
    def safe_names(cls, value: str) -> str:
        return _safe_identifier(value)


class Operation(_StrictModel):
    name: str
    return_type: Literal["void", "boolean"]
    failure_semantics: Literal["unavailable", "false_and_stutter", "exception"]
    guards: list[Guard]
    effects: list[Effect]
    frame: list[str]
    exception_type: str | None = None
    exception_trigger: ExpressionIR | None = None

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        return _safe_identifier(value)

    @field_validator("frame")
    @classmethod
    def safe_frame(cls, value: list[str]) -> list[str]:
        for name in value:
            _safe_identifier(name)
        if len(value) != len(set(value)):
            raise ValueError("frame fields must be unique")
        return value

    @model_validator(mode="after")
    def valid_failure_surface(self) -> "Operation":
        if self.failure_semantics == "false_and_stutter" and self.return_type != "boolean":
            raise ValueError("false_and_stutter requires boolean return type")
        if self.failure_semantics == "exception" and (
                not self.exception_type or self.exception_trigger is None):
            raise ValueError("exception semantics require exception_type and exception_trigger")
        if self.failure_semantics != "exception" and (
                self.exception_type is not None or self.exception_trigger is not None):
            raise ValueError("exception metadata is allowed only for exception semantics")
        return self


class Invariant(_StrictModel):
    id: str
    expression: ExpressionIR

    @field_validator("id")
    @classmethod
    def safe_id(cls, value: str) -> str:
        return _safe_identifier(value)


def _referenced_fields(expression: ExpressionIR) -> set[str]:
    if isinstance(expression, FieldExpr):
        return {expression.name}
    if isinstance(expression, (OldExpr, NotExpr)):
        return _referenced_fields(expression.expression)
    if isinstance(expression, BinaryExpr):
        return _referenced_fields(expression.left) | _referenced_fields(expression.right)
    return set()


class DomainSpecV2(_StrictModel):
    schema_version: Literal[2] = 2
    review_status: Literal["unreviewed", "reviewed"] = "unreviewed"
    domain_name: str
    module_name: str
    actors: int = Field(default=1, ge=1, le=16)
    state_variables: list[StateVariable] = Field(min_length=1)
    operations: list[Operation] = Field(min_length=1)
    tlc_invariants: list[Invariant] = Field(min_length=1)

    @field_validator("domain_name")
    @classmethod
    def safe_domain_name(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", value):
            raise ValueError("domain_name must be a safe PascalCase identifier")
        return value

    @field_validator("module_name")
    @classmethod
    def safe_module_name(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", value):
            raise ValueError("module_name must be a safe lower-case identifier")
        return value

    @model_validator(mode="after")
    def unique_names(self) -> "DomainSpecV2":
        groups = {
            "state variables": [item.name for item in self.state_variables],
            "operations": [item.name for item in self.operations],
            "invariants": [item.id for item in self.tlc_invariants],
        }
        for label, values in groups.items():
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must be unique")
        declared = set(groups["state variables"])
        reserved = {"Init", "Next", "Spec", "TypeOK", "vars", "Actors", "callResult"}
        if declared & reserved:
            raise ValueError("state variable uses a reserved TLA+ identifier")
        operator_names: set[str] = set(reserved)
        for operation in self.operations:
            generated = ({operation.name} if operation.return_type == "void" else
                         {operation.name + "Success"} |
                         ({operation.name + "Failure"}
                          if operation.failure_semantics == "false_and_stutter" else set()))
            if operator_names & generated:
                raise ValueError(f"operation {operation.name} collides with a TLA+ operator")
            operator_names |= generated
            targets = [effect.target for effect in operation.effects]
            if len(targets) != len(set(targets)) or set(targets) != set(operation.frame):
                raise ValueError(
                    f"{operation.name} effects must target every framed field exactly once")
            ids = [guard.id for guard in operation.guards] + [effect.id for effect in operation.effects]
            if len(ids) != len(set(ids)):
                raise ValueError(f"{operation.name} guard/effect IDs must be unique")
            references = set().union(
                *(_referenced_fields(item.expression) for item in operation.guards),
                *(_referenced_fields(item.value) for item in operation.effects),
                *([_referenced_fields(operation.exception_trigger)]
                  if operation.exception_trigger is not None else []),
            )
            if (set(operation.frame) | set(targets) | references) - declared:
                raise ValueError(f"{operation.name} references undeclared state fields")
        for invariant in self.tlc_invariants:
            if invariant.id in operator_names:
                raise ValueError(f"invariant {invariant.id} collides with a TLA+ operator")
            operator_names.add(invariant.id)
            if _referenced_fields(invariant.expression) - declared:
                raise ValueError(f"invariant {invariant.id} references undeclared state fields")
        return self
