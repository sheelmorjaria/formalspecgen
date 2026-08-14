# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Typed fragments used by the staged natural-language architecture compiler."""
from __future__ import annotations

from typing import Literal
import json
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator
from .domain_v2 import ExpressionIR, _referenced_fields
from .architecture import Architecture, Component, Operation, Dependency, UseCase, Step


class ComponentFragment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    type: Literal["core", "interface", "adapter", "orchestrator"]
    desc: str = Field(min_length=1, max_length=500)
    implements: str | None = Field(default=None, pattern=r"^[A-Za-z_]\w*$")


class StagedContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requires: str = Field(min_length=1)
    ensures: str = Field(min_length=1)


class StagedOperation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    params: list[ParameterFragment] = Field(default_factory=list)
    contract: StagedContract

    @field_validator("params")
    @classmethod
    def unique_parameters(cls, value: list[ParameterFragment]) -> list[ParameterFragment]:
        names = [item.name for item in value]
        if len(names) != len(set(names)):
            raise ValueError("operation parameters must be unique")
        return value


class StagedStateVariable(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    type: Literal["int", "boolean", "bool"]
    bound: tuple[int, int] | None = None
    initial: int | bool = 0

    @field_validator("bound")
    @classmethod
    def require_integer_bound(cls, value, info):
        if info.data.get("type") == "int" and value is None:
            raise ValueError("UNBOUNDED_STATE_SPACE: integer state requires bound")
        if value is not None and value[0] > value[1]:
            raise ValueError("state bounds must be ordered")
        return value


class StagedComponent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    type: Literal["core", "interface", "adapter"]
    file: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*\.java$")
    external: bool = False
    implements: str | None = Field(default=None, pattern=r"^[A-Za-z_]\w*$")
    state_variables: list[StagedStateVariable] = Field(default_factory=list)
    transitions: list[TransitionFragment] = Field(default_factory=list)
    operations: list[StagedOperation] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_shape(self) -> "StagedComponent":
        if self.type == "adapter" and not self.implements:
            raise ValueError("ADAPTER_REQUIRES_IMPLEMENTS")
        if self.type == "interface" and not self.operations:
            raise ValueError("EXTERNAL_INTERFACE_REQUIRES_OPERATIONS")
        names = [item.name for item in self.state_variables]
        if len(names) != len(set(names)):
            raise ValueError("DUPLICATE_STATE_VARIABLE")
        operation_names = {item.name for item in self.operations}
        for transition in self.transitions:
            if transition.operation_name not in operation_names:
                raise ValueError("UNDECLARED_OPERATION_TRANSITION: " +
                                 transition.operation_name)
            validate_transition(transition, set(names))
        return self


class StagedUseCaseStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    component: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    operation: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    arguments: dict[str, str] = Field(default_factory=dict)


class StagedUseCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    steps: list[StagedUseCaseStep] = Field(min_length=1)


class UnifiedArchitecture(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, pattern=r"^[A-Za-z_]\w*$")
    components: list[StagedComponent] = Field(min_length=1)
    use_cases: list[StagedUseCase] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_components(self) -> "UnifiedArchitecture":
        names = [item.name for item in self.components]
        if len(names) != len(set(names)):
            raise ValueError("DUPLICATE_COMPONENT_NAME")
        return self


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


# Resolve forward references used by the unified models declared before the legacy fragments.
StagedOperation.model_rebuild()
StagedComponent.model_rebuild()


def parse_json_fragment(raw: str, model, repair_chat: Callable[[str], str] | None = None,
                        max_attempts: int = 3):
    """Parse one small fragment, optionally asking the provider to repair diagnostics."""
    candidate = raw
    last_error = None
    for _ in range(max_attempts):
        try:
            value = json.loads(candidate)
            return (model.model_validate(value) if hasattr(model, "model_validate")
                    else TypeAdapter(model).validate_python(value))
        except (json.JSONDecodeError, ValueError) as exc:
            last_error = exc
            if repair_chat is None:
                break
            candidate = repair_chat(
                "Return only corrected JSON. Previous fragment:\n" + candidate[:12000] +
                "\nValidation error:\n" + str(exc))
    raise ValueError(f"FRAGMENT_REPAIR_FAILED: {last_error}") from last_error


def parse_operation_fragments(raw: str) -> dict[str, list[OperationFragment]]:
    """Normalize flat or component-keyed operation JSON into validated groups."""
    data = json.loads(raw)
    groups = data if isinstance(data, dict) else {"": data}
    if not isinstance(groups, dict):
        raise ValueError("operation fragments must be a list or component-keyed object")
    result = {}
    for component, values in groups.items():
        if not isinstance(values, list):
            raise ValueError(f"INVALID_OPERATION_GROUP: {component}")
        result[str(component)] = [OperationFragment.model_validate(item) for item in values]
    return result


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


def attach_transitions(component_name: str, operation_names: set[str],
                       transitions: list[TransitionFragment]) -> list[TransitionFragment]:
    """Attach only transitions belonging to declared component operations."""
    for transition in transitions:
        if transition.operation_name not in operation_names:
            raise ValueError(
                f"UNDECLARED_OPERATION_TRANSITION: {component_name}."
                f"{transition.operation_name}")
    declared = set()
    for transition in transitions:
        if transition.operation_name in declared:
            raise ValueError(f"DUPLICATE_OPERATION_TRANSITION: {component_name}."
                             f"{transition.operation_name}")
        declared.add(transition.operation_name)
    return transitions


def assemble_architecture(components: list[ComponentFragment],
                          operations: dict[str, list[OperationFragment]],
                          states: dict[str, list[StateVariableFragment]],
                          steps: list[UseCaseStepFragment],
                          transitions: dict[str, list[TransitionFragment]]) -> Architecture:
    """Convert validated staged fragments into the existing architecture artifact model."""
    by_name = {item.name: item for item in components}
    operation_map: dict[tuple[str, str], OperationFragment] = {}
    result_components = []
    for fragment in components:
        kind = "interface" if fragment.type == "interface" else "class"
        layer = "adapters" if fragment.type == "adapter" else (
            "use_cases" if fragment.type == "orchestrator" else "entities")
        fragment_ops = operations.get(fragment.name, [])
        for operation in fragment_ops:
            operation_map[(fragment.name, operation.name)] = operation
        result_components.append(Component(
            id=fragment.name, name=fragment.name, layer=layer, kind=kind,
            responsibilities=[fragment.desc], external=fragment.type in {"interface", "adapter"},
            operations=[Operation(name=op.name,
                                  parameters=[item.model_dump() for item in op.params],
                                  returns=op.returns, requires=[op.requires], ensures=[op.ensures])
                        for op in fragment_ops],
            dependencies=[Dependency(target=fragment.implements, abstraction=True)]
            if fragment.implements else []))
    for step in steps:
        if step.component not in by_name:
            raise ValueError(f"UNRESOLVED_COMPONENT_REFERENCE: {step.component}")
        if (step.component, step.operation) not in operation_map:
            raise ValueError(f"UNRESOLVED_OPERATION_REFERENCE: {step.component}.{step.operation}")
        validate_step_bindings(step, operation_map[(step.component, step.operation)])
    return Architecture(name="StagedArchitecture", description="Staged bounded architecture",
                        components=result_components,
                        use_cases=[UseCase(name="MainFlow", steps=[Step(component=s.component,
                                                                          operation=s.operation)
                                                                      for s in steps])])
