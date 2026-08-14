# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Typed fragments used by the staged natural-language architecture compiler."""
from __future__ import annotations

from typing import Literal
import json
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field, field_validator
from .domain_v2 import ExpressionIR, _referenced_fields


class ComponentFragment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    type: Literal["core", "interface", "adapter", "orchestrator"]
    desc: str = Field(min_length=1, max_length=500)
    implements: str | None = Field(default=None, pattern=r"^[A-Za-z_]\w*$")


class ParameterFragment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    type: Literal["int", "boolean", "bool"]


class OperationFragment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    params: list[ParameterFragment] = Field(default_factory=list)
    requires: str = Field(min_length=1)
    ensures: str = Field(min_length=1)
    returns: Literal["void", "boolean", "bool", "int"] = "void"

    @field_validator("params")
    @classmethod
    def unique_parameters(cls, value: list[ParameterFragment]) -> list[ParameterFragment]:
        names = [item.name for item in value]
        if len(names) != len(set(names)):
            raise ValueError("operation parameters must be unique")
        return value


class StateVariableFragment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    type: Literal["int", "boolean", "bool"]
    bound: tuple[int, int] | None = None
    initial: int | bool = 0

    @field_validator("bound")
    @classmethod
    def ordered_bound(cls, value):
        if value is not None and value[0] > value[1]:
            raise ValueError("state bounds must be ordered")
        return value

    @field_validator("initial")
    @classmethod
    def bounded_initial(cls, value, info):
        bound = info.data.get("bound")
        if bound is not None and isinstance(value, int) and not isinstance(value, bool):
            if not bound[0] <= value <= bound[1]:
                raise ValueError("initial state value is outside its bound")
        return value


class UseCaseStepFragment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    component: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    operation: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    arguments: dict[str, str] = Field(default_factory=dict)


class TransitionEffectFragment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    value: ExpressionIR


class TransitionFragment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_name: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    precondition: ExpressionIR
    effects: list[TransitionEffectFragment] = Field(min_length=1)
    frame: list[str] = Field(min_length=1)

    @field_validator("frame")
    @classmethod
    def unique_frame(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("FRAME_CONSISTENCY_ERROR: frame fields must be unique")
        return value


def validate_transition(fragment: TransitionFragment,
                        declared_state: set[str]) -> None:
    targets = [effect.target for effect in fragment.effects]
    if set(targets) != set(fragment.frame) or len(targets) != len(set(targets)):
        raise ValueError("FRAME_CONSISTENCY_ERROR: effects and frame must be identical")
    referenced = set(_referenced_fields(fragment.precondition))
    for effect in fragment.effects:
        referenced.update(_referenced_fields(effect.value))
    unknown = referenced - declared_state
    if unknown:
        raise ValueError("UNDECLARED_STATE_REFERENCE: " + ", ".join(sorted(unknown)))


def validate_step_bindings(step: UseCaseStepFragment, operation: OperationFragment) -> None:
    expected = {item.name for item in operation.params}
    actual = set(step.arguments)
    if expected - actual:
        raise ValueError("MISSING_ARGUMENT_BINDING: " + ", ".join(sorted(expected - actual)))
    if actual - expected:
        raise ValueError("EXTRA_ARGUMENT_BINDING: " + ", ".join(sorted(actual - expected)))


def parse_json_fragment(raw: str, model, repair_chat: Callable[[str], str] | None = None,
                        max_attempts: int = 3):
    """Parse one small fragment, optionally asking the provider to repair diagnostics."""
    candidate = raw
    last_error = None
    for _ in range(max_attempts):
        try:
            value = json.loads(candidate)
            return model.model_validate(value)
        except (json.JSONDecodeError, ValueError) as exc:
            last_error = exc
            if repair_chat is None:
                break
            candidate = repair_chat(
                "Return only corrected JSON. Previous fragment:\n" + candidate[:12000] +
                "\nValidation error:\n" + str(exc))
    raise ValueError(f"FRAGMENT_REPAIR_FAILED: {last_error}") from last_error


def assemble_component_fragments(components: list[ComponentFragment],
                                 operations: dict[str, list[OperationFragment]] | None = None,
                                 steps: list[UseCaseStepFragment] | None = None) -> dict:
    """Resolve staged names and return a plain assembly manifest without proving it."""
    by_name = {item.name: item for item in components}
    if len(by_name) != len(components):
        raise ValueError("DUPLICATE_COMPONENT_NAME")
    operation_map: dict[tuple[str, str], OperationFragment] = {}
    for component_name, fragments in (operations or {}).items():
        if component_name not in by_name:
            raise ValueError(f"UNRESOLVED_COMPONENT_REFERENCE: {component_name}")
        names = [item.name for item in fragments]
        if len(names) != len(set(names)):
            raise ValueError(f"DUPLICATE_OPERATION_NAME: {component_name}")
        for operation in fragments:
            operation_map[(component_name, operation.name)] = operation
    for step in steps or []:
        if step.component not in by_name:
            raise ValueError(f"UNRESOLVED_COMPONENT_REFERENCE: {step.component}")
        operation = operation_map.get((step.component, step.operation))
        if operation is None:
            raise ValueError(f"UNRESOLVED_OPERATION_REFERENCE: {step.component}.{step.operation}")
        validate_step_bindings(step, operation)
    return {"components": [item.model_dump() for item in components],
            "operations": {name: [item.model_dump() for item in values]
                            for name, values in (operations or {}).items()},
            "steps": [item.model_dump() for item in (steps or [])]}
