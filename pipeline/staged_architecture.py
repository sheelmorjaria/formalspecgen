# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Typed fragments used by the staged natural-language architecture compiler."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


def validate_step_bindings(step: UseCaseStepFragment, operation: OperationFragment) -> None:
    expected = {item.name for item in operation.params}
    actual = set(step.arguments)
    if expected - actual:
        raise ValueError("MISSING_ARGUMENT_BINDING: " + ", ".join(sorted(expected - actual)))
    if actual - expected:
        raise ValueError("EXTRA_ARGUMENT_BINDING: " + ", ".join(sorted(actual - expected)))
