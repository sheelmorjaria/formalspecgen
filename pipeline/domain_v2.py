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
    # Values that are legitimate end states (an ERROR_SHUTDOWN or
    # completion phase): the static deadlock gate exempts them, and TLC
    # still checks they are reachable rather than dead.
    terminal_states: list[int] | None = None

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


class LockProtocolMetadata(_StrictModel):
    mode: Literal["lock_protocol"] = "lock_protocol"
    lock_variable: str
    lock_states: list[str] = Field(min_length=2)
    unlocked_value: int | None = None
    actor_lock_values: list[int] | None = None
    linearization_points: dict[str, Literal["effect_commit"]] | None = None

    @field_validator("lock_variable")
    @classmethod
    def safe_lock_variable(cls, value: str) -> str:
        return _safe_identifier(value)

    @field_validator("lock_states")
    @classmethod
    def valid_lock_states(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("lock states must be unique")
        for state in value:
            _safe_identifier(state)
        return value


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


def _expression_type(expression: ExpressionIR, fields: dict[str, str]) -> str:
    """Infer the closed V2 scalar type and reject mixed-sort expressions."""
    if isinstance(expression, FieldExpr):
        return fields[expression.name]
    if isinstance(expression, IntegerExpr):
        return "int"
    if isinstance(expression, BooleanExpr):
        return "bool"
    if isinstance(expression, OldExpr):
        return _expression_type(expression.expression, fields)
    if isinstance(expression, NotExpr):
        operand = _expression_type(expression.expression, fields)
        if operand != "bool":
            raise ValueError("not expression requires a boolean operand")
        return "bool"
    left = _expression_type(expression.left, fields)
    right = _expression_type(expression.right, fields)
    if expression.kind in {"eq", "neq"}:
        if left != right:
            raise ValueError("equality operands must have the same scalar type")
        return "bool"
    if expression.kind in {"lt", "lte", "gt", "gte", "add", "sub"}:
        if left != "int" or right != "int":
            raise ValueError(f"{expression.kind} requires integer operands")
        return "int" if expression.kind in {"add", "sub"} else "bool"
    if left != "bool" or right != "bool":
        raise ValueError(f"{expression.kind} requires boolean operands")
    return "bool"


class DomainSpecV2(_StrictModel):
    schema_version: Literal[2] = 2
    review_status: Literal["unreviewed", "reviewed"] = "unreviewed"
    domain_name: str
    module_name: str
    actors: int = Field(default=1, ge=1, le=16)
    execution_model: Literal["async_message_passing"] | None = None
    concurrency: LockProtocolMetadata | None = None
    # Set by the capacity-bounding lane: the silicon-derived element
    # capacity this machine was clamped to. Downstream lowering may
    # materialize a static pool of exactly this size.
    capacity_bound: int | None = None
    # When a pre-bounded logical pool is smaller than the silicon ceiling,
    # retain both values. ``capacity_bound`` is the allocation actually
    # materialized; this is the profile-derived maximum it was proved under.
    hardware_safe_capacity: int | None = None
    pool_counter: str | None = None
    hardware_profile_sha256: str | None = None
    hardware_proof_sha256: str | None = None
    # Provenance for the capacity derivation: the per-element byte size the
    # profile was divided by. With capacity_bound it lets downstream verdicts
    # state the exact memory footprint (capacity x struct bytes).
    struct_size_bytes: int | None = None
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
        hardware_fields = (self.capacity_bound, self.hardware_safe_capacity,
                           self.pool_counter, self.hardware_profile_sha256,
                           self.hardware_proof_sha256, self.struct_size_bytes)
        extended_hardware_fields = (self.hardware_safe_capacity,
                                    self.pool_counter,
                                    self.hardware_profile_sha256,
                                    self.hardware_proof_sha256)
        if any(value is not None for value in extended_hardware_fields):
            if any(value is None for value in hardware_fields):
                raise ValueError("hardware pool metadata must be complete")
            if self.capacity_bound <= 0 or self.struct_size_bytes <= 0:
                raise ValueError("hardware pool capacity and element size must be positive")
            if self.capacity_bound > self.hardware_safe_capacity:
                raise ValueError("logical pool exceeds hardware-safe capacity")
            if not re.fullmatch(r"[0-9a-f]{64}", self.hardware_profile_sha256):
                raise ValueError("hardware profile hash must be SHA-256")
            if not re.fullmatch(r"[0-9a-f]{64}", self.hardware_proof_sha256):
                raise ValueError("hardware proof hash must be SHA-256")
            pool = next((item for item in self.state_variables
                         if item.name == self.pool_counter), None)
            if not isinstance(pool, IntStateVariable) or \
                    pool.bound[1] != self.capacity_bound:
                raise ValueError("pool_counter must be bounded at capacity_bound")
        if self.execution_model == "async_message_passing":
            if self.actors < 2:
                raise ValueError("async message passing requires at least two actors")
            if self.concurrency is not None:
                raise ValueError("async message passing cannot also claim a lock protocol")
        if self.concurrency is not None:
            if self.concurrency.lock_variable not in declared:
                raise ValueError("lock protocol variable must be declared state")
            if self.actors < 2:
                raise ValueError("lock protocol requires at least two actors")
            lock = next(item for item in self.state_variables
                        if item.name == self.concurrency.lock_variable)
            if not isinstance(lock, IntStateVariable):
                raise ValueError("lock protocol variable must be bounded integer state")
            metadata = self.concurrency
            complete = (metadata.unlocked_value is not None or
                        metadata.actor_lock_values is not None or
                        metadata.linearization_points is not None)
            if complete:
                if (metadata.unlocked_value is None or metadata.actor_lock_values is None or
                        metadata.linearization_points is None):
                    raise ValueError("explicit lock protocol metadata must be complete")
                owners = metadata.actor_lock_values
                if len(metadata.lock_states) != self.actors + 1:
                    raise ValueError("lock states must name unlocked plus every actor owner")
                if len(owners) != self.actors or len(owners) != len(set(owners)):
                    raise ValueError("actor lock values must be unique and total over actors")
                if metadata.unlocked_value in owners:
                    raise ValueError("unlocked value must differ from actor lock values")
                if lock.initial != metadata.unlocked_value:
                    raise ValueError("lock state must initialize to the unlocked value")
                if any(not lock.bound[0] <= item <= lock.bound[1]
                       for item in [metadata.unlocked_value, *owners]):
                    raise ValueError("lock ownership values must be within lock bounds")
                operation_names = {item.name for item in self.operations}
                if set(metadata.linearization_points) != operation_names:
                    raise ValueError("linearization points must cover every operation exactly")
                if any(item.return_type != "void" or
                       item.failure_semantics != "unavailable"
                       for item in self.operations):
                    raise ValueError(
                        "explicit lock protocol currently supports void/unavailable operations")
                if any(metadata.lock_variable in item.frame for item in self.operations):
                    raise ValueError("domain operations cannot directly mutate protocol lock state")
                if any(metadata.lock_variable in set().union(
                        *(_referenced_fields(guard.expression) for guard in item.guards),
                        *(_referenced_fields(effect.value) for effect in item.effects))
                       for item in self.operations):
                    raise ValueError(
                        "domain operations cannot reference protocol lock abstraction state")
        field_types = {item.name: ("bool" if isinstance(item, BoolStateVariable) else "int")
                       for item in self.state_variables}
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
            for guard in operation.guards:
                if _expression_type(guard.expression, field_types) != "bool":
                    raise ValueError(f"{operation.name} guard {guard.id} must be boolean")
            for effect in operation.effects:
                if _expression_type(effect.value, field_types) != field_types[effect.target]:
                    raise ValueError(
                        f"{operation.name} effect {effect.id} type does not match its target")
            if (operation.exception_trigger is not None and
                    _expression_type(operation.exception_trigger, field_types) != "bool"):
                raise ValueError(f"{operation.name} exception trigger must be boolean")
        for invariant in self.tlc_invariants:
            if invariant.id in operator_names:
                raise ValueError(f"invariant {invariant.id} collides with a TLA+ operator")
            operator_names.add(invariant.id)
            if _referenced_fields(invariant.expression) - declared:
                raise ValueError(f"invariant {invariant.id} references undeclared state fields")
            if _expression_type(invariant.expression, field_types) != "bool":
                raise ValueError(f"invariant {invariant.id} must be boolean")
        return self
