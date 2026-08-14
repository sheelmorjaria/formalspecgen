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
    file: str | None = None
    external: bool = False
    implements: str | None = Field(default=None, pattern=r"^[A-Za-z_]\w*$")
    domain: str | None = Field(default=None, pattern=r"^[a-z_][a-z0-9_]*$")


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
    file: str | None = Field(default=None, pattern=r"^[A-Za-z_]\w*\.[A-Za-z0-9]+$")
    external: bool = False
    implements: str | None = Field(default=None, pattern=r"^[A-Za-z_]\w*$")
    # Reviewed V2 domains are the sole source of truth for core state and transitions.
    # When present, inline state_variables/transitions are forbidden below.
    domain: str | None = Field(default=None, pattern=r"^[a-z_][a-z0-9_]*$")
    state_variables: list[StagedStateVariable] = Field(default_factory=list)
    transitions: list[TransitionFragment] = Field(default_factory=list)
    operations: list[StagedOperation] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_shape(self) -> "StagedComponent":
        if self.type == "adapter" and not self.implements:
            raise ValueError("ADAPTER_REQUIRES_IMPLEMENTS")
        if self.type == "interface" and not self.operations:
            raise ValueError("EXTERNAL_INTERFACE_REQUIRES_OPERATIONS")
        if self.domain and (self.state_variables or self.transitions):
            raise ValueError("DOMAIN_COMPONENT_CANNOT_DEFINE_INLINE_STATE")
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
        normalized = []
        for item in values:
            item = dict(item)
            contract = item.pop("contract", {}) or {}
            if not isinstance(contract, dict):
                raise ValueError("operation contract must be an object")
            for key in ("requires", "ensures"):
                value = item.get(key, contract.get(key, "true"))
                if isinstance(value, list):
                    value = " && ".join(str(part) for part in value)
                item[key] = value
            for param in item.get("params", []):
                if str(param.get("type", "")).lower() not in {"int", "boolean", "bool"}:
                    raise ValueError("UNSUPPORTED_OPERATION_PARAMETER_TYPE")
            normalized.append(OperationFragment.model_validate(item))
        result[str(component)] = normalized
    return result


def parse_fragment_list(raw: str, model, label: str) -> list:
    """Parse a flat fragment list or flatten a component-keyed object."""
    data = json.loads(raw)
    if isinstance(data, dict):
        values = []
        for group in data.values():
            if isinstance(group, list):
                values.extend(group)
            elif isinstance(group, dict):
                if ((label == "transition" and "operation_name" in group) or
                        (label == "state" and "name" in group and "type" in group) or
                        (label == "use-case" and "component" in group)):
                    nested = [group]
                else:
                    nested = None
                key = {"state": "state_variables", "transition": "transitions",
                       "use-case": "steps"}.get(label)
                nested = nested or (group.get(key) if key else None)
                if nested is None:
                    list_values = [value for value in group.values() if isinstance(value, list)]
                    nested = list_values[0] if len(list_values) == 1 else None
                if not isinstance(nested, list):
                    # Models sometimes emit {"transitions": {"Component": [...]}}.
                    # Recursively collect nested lists, then validate every item.
                    def collect(value):
                        if isinstance(value, list):
                            return value
                        if isinstance(value, dict):
                            out = []
                            for child in value.values():
                                out.extend(collect(child))
                            return out
                        return []
                    nested = collect(group)
                if not isinstance(nested, list) or not nested:
                    raise ValueError(f"{label} fragments must be lists")
                values.extend(nested)
            else:
                raise ValueError(f"{label} fragments must be lists")
    elif isinstance(data, list):
        values = data
    else:
        raise ValueError(f"{label} fragments must be a list or keyed object")
    if model is dict:
        return values
    return [model.model_validate(item) for item in values]


def normalize_transition_fragments(items: list[dict]) -> list[dict]:
    """Normalize only unambiguous LLM aliases before strict V2 validation."""
    def fix(node):
        if isinstance(node, list):
            return [fix(item) for item in node]
        if not isinstance(node, dict):
            return node
        value = {key: fix(child) for key, child in node.items()}
        if "type" in value and "kind" not in value:
            value["kind"] = value.pop("type")
        return value

    normalized = []
    for item in items:
        item = fix(dict(item))
        effects = []
        for effect in item.get("effects", []):
            effect = dict(effect)
            if "value" not in effect and "set" in effect:
                effect["value"] = effect.pop("set")
            effects.append(effect)
        item["effects"] = effects
        normalized.append(item)
    return normalized


def normalize_component_type(value: str) -> str:
    """Canonicalize common LLM role synonyms without accepting unknown roles."""
    normalized = str(value).strip().lower()
    groups = {
        "core": {"core", "service", "manager", "engine", "logic", "domain"},
        "orchestrator": {"orchestrator", "controller", "coordinator", "flow"},
        "interface": {"interface", "port", "api", "gateway", "external", "external_service"},
        "adapter": {"adapter", "implementation", "impl", "concrete"},
    }
    for canonical, synonyms in groups.items():
        if normalized in synonyms:
            return canonical
    return normalized


def parse_component_fragments(raw: str) -> list[ComponentFragment]:
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("component fragments must be a JSON list")
    normalized = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("component fragment must be an object")
        item = dict(item)
        item["type"] = normalize_component_type(item.get("type", ""))
        if item.get("implements") == "":
            item["implements"] = None
        if item.get("file") == "":
            item["file"] = None
        normalized.append(ComponentFragment.model_validate(item))
    return normalized


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


def assemble_unified_architecture(components: list[ComponentFragment],
                                  operations: dict[str, list[OperationFragment]],
                                  states: dict[str, list[StateVariableFragment]],
                                  steps: list[UseCaseStepFragment],
                                  transitions: dict[str, list[TransitionFragment]],
                                  name: str = "GeneratedSystem") -> UnifiedArchitecture:
    """Build and validate the exact unified staged JSON shape."""
    staged = []
    for component in components:
        component_type = component.type if component.type != "orchestrator" else "core"
        staged_ops = [StagedOperation(
            name=op.name,
            params=[ParameterFragment.model_validate(item.model_dump()) for item in op.params],
            contract=StagedContract(requires=op.requires, ensures=op.ensures))
            for op in operations.get(component.name, [])]
        staged.append(StagedComponent(
            name=component.name, type=component_type,
            file=component.file or f"{component.name}.java",
            external=component.external or component.type == "interface",
            implements=component.implements,
            domain=component.domain,
            state_variables=[StagedStateVariable.model_validate(item.model_dump())
                             for item in states.get(component.name, [])],
            transitions=transitions.get(component.name, []), operations=staged_ops))
    return UnifiedArchitecture(name=name, components=staged,
                               use_cases=[StagedUseCase(
                                   name="CheckoutFlow",
                                   steps=[StagedUseCaseStep.model_validate(item.model_dump())
                                          for item in steps])])
