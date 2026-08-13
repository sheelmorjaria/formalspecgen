# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Multi-tier compositional verification over reviewed V2 domain artifacts.

A composition spec binds architecture components (SOLID-linted through the shared
``architecture`` module) to *promoted* V2 domains, then composes reviewed operations
into orchestrator use cases.  Every contract fact is derived deterministically from
the reviewed typed expression trees; nothing here trusts LLM-drafted clause text.

Scope: single-threaded, atomic contract composition.  One operation per component
per use case, void/unavailable semantics only.  This establishes neither concurrent
linearizability nor distributed-message asynchrony.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from . import config
from .architecture import lint_architecture, parse_architecture
from .domain_v2 import (
    BinaryExpr, BooleanExpr, FieldExpr, IntegerExpr, NotExpr, OldExpr,
)
from .domain_v2_promotion import ReviewedDomainSpecV2
from .v2_jml_serializer import _OPS


class CompositionError(ValueError):
    """A composition artifact could not be resolved against reviewed V2 domains."""


class UnsupportedCompositionBoundary(ValueError):
    """The requested composition leaves the reviewed deterministic subset."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CompositionStep(_StrictModel):
    component: str
    operation: str


class CompositionUseCase(_StrictModel):
    name: str
    steps: list[CompositionStep] = Field(min_length=1)


class ComponentBinding(_StrictModel):
    component: str
    module_name: str


class CompositionSpec(_StrictModel):
    schema_version: Literal[1] = 1
    system_name: str
    architecture: dict
    bindings: list[ComponentBinding] = Field(min_length=1)
    use_cases: list[CompositionUseCase] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_references(self) -> "CompositionSpec":
        bound = [binding.component for binding in self.bindings]
        if len(bound) != len(set(bound)):
            raise ValueError("a component may be bound at most once")
        names = [use_case.name for use_case in self.use_cases]
        if len(names) != len(set(names)):
            raise ValueError("use case names must be unique")
        return self


def parse_composition(value: dict | str) -> CompositionSpec:
    data = json.loads(value) if isinstance(value, str) else value
    return CompositionSpec.model_validate(data)


def resolve_bindings(spec: CompositionSpec,
                     v2_dir: str | Path | None = None) -> dict[str, ReviewedDomainSpecV2]:
    """Bind every component to its promoted V2 artifact; fail closed on any gap."""
    directory = (Path(v2_dir) if v2_dir is not None
                 else Path(config.ROOT) / "domains" / "v2")
    known = {component.id for component in parse_architecture(spec.architecture).components}
    resolved: dict[str, ReviewedDomainSpecV2] = {}
    for binding in spec.bindings:
        if binding.component not in known:
            raise CompositionError(
                f"binding references undeclared architecture component {binding.component!r}")
        path = directory / f"{binding.module_name}.json"
        if not path.exists():
            raise CompositionError(
                f"reviewed V2 artifact for module {binding.module_name!r} not found at {path}")
        try:
            resolved[binding.component] = ReviewedDomainSpecV2.model_validate_json(
                path.read_text(encoding="utf-8"))
        except ValidationError as exc:
            raise CompositionError(
                f"module {binding.module_name!r} is not a reviewed V2 artifact: "
                f"{exc.errors()[0].get('msg', exc)}") from exc
    used = {step.component for use_case in spec.use_cases for step in use_case.steps}
    missing = used - set(resolved)
    if missing:
        raise CompositionError(
            "components used in use cases without a reviewed binding: " + ", ".join(sorted(missing)))
    return resolved


def lint_composition(spec: CompositionSpec,
                     resolved: dict[str, ReviewedDomainSpecV2] | None = None) -> list[dict]:
    """SOLID/STRIDE lint plus composition-specific binding and step checks."""
    architecture = parse_architecture(spec.architecture)
    findings = list(lint_architecture(architecture))
    known = {component.id for component in architecture.components}
    bound = {binding.component for binding in spec.bindings}

    def finding(code, subject, severity, message, advice, target=None):
        findings.append({"code": code, "subject": subject, "target": target,
                         "severity": severity, "message": message, "advice": advice})

    for binding in spec.bindings:
        if binding.component not in known:
            finding("composition-unknown-component", binding.component, "error",
                    f"Binding targets undeclared component {binding.component!r}.",
                    "Declare the component in the architecture artifact or drop the binding.")
    used = {step.component for use_case in spec.use_cases for step in use_case.steps}
    for component in sorted(used - bound):
        finding("composition-missing-binding", component, "error",
                f"Component {component!r} appears in a use case without a V2 binding.",
                "Bind it to a promoted domains/v2 artifact before composing.")
    if resolved is None:
        for binding in spec.bindings:
            finding("composition-binding-unresolved", binding.component, "error",
                    f"Binding for {binding.component!r} was not resolved to a reviewed artifact.",
                    "Resolve bindings before trusting operation-level composition checks.")
        return findings
    for use_case in spec.use_cases:
        seen: set[str] = set()
        for index, step in enumerate(use_case.steps):
            if step.component in seen:
                finding("composition-repeated-component", use_case.name, "error",
                        f"Step {index + 1} repeats component {step.component!r}.",
                        "Compose at most one reviewed operation per component per use case.")
                continue
            seen.add(step.component)
            reviewed = resolved.get(step.component)
            if reviewed is None:
                continue
            operation = next((item for item in reviewed.operations
                              if item.name == step.operation), None)
            if operation is None:
                finding("composition-unknown-operation", use_case.name, "error",
                        f"Step {index + 1} references {step.component}.{step.operation}, "
                        "which the reviewed V2 artifact does not declare.",
                        "Use an operation from the promoted domain, or promote an updated candidate.",
                        target=step.component)
            elif operation.return_type == "boolean":
                finding("composition-boolean-operation", use_case.name, "error",
                        f"Step {index + 1} uses boolean operation {step.operation!r}.",
                        "Composition supports void/unavailable operations only; "
                        "boolean failure-and-stutter semantics cannot be sequentially composed yet.",
                        target=step.component)
    return findings


def render_qualified(node, receiver: str, *, pre_state: bool = False) -> str:
    """Render a reviewed V2 expression against a component receiver field."""
    if isinstance(node, FieldExpr):
        base = f"{receiver}.{node.name}"
        return rf"\old({base})" if pre_state else base
    if isinstance(node, IntegerExpr):
        return str(node.value)
    if isinstance(node, BooleanExpr):
        return "true" if node.value else "false"
    if isinstance(node, OldExpr):
        return rf"\old({render_qualified(node.expression, receiver)})"
    if isinstance(node, NotExpr):
        return "!(" + render_qualified(node.expression, receiver, pre_state=pre_state) + ")"
    if isinstance(node, BinaryExpr):
        operator = _OPS.get(node.kind)
        if operator is None:
            raise UnsupportedCompositionBoundary(
                f"unsupported V2 expression kind {node.kind!r}")
        left = render_qualified(node.left, receiver, pre_state=pre_state)
        right = render_qualified(node.right, receiver, pre_state=pre_state)
        return f"({left} {operator} {right})"
    raise UnsupportedCompositionBoundary(
        f"unsupported V2 expression node {type(node).__name__}")


def _unparenthesized(text: str) -> str:
    return text[1:-1] if text.startswith("(") and text.endswith(")") else text


def analyze_coupling(use_case: CompositionUseCase,
                     resolved: dict[str, ReviewedDomainSpecV2]) -> dict:
    """Partition every step guard into caller preconditions and ESC obligations.

    With one reviewed operation per component per use case, no earlier step writes a
    later step's fields, so every guard must be established by the orchestrator's
    caller; OpenJML ESC must then discharge each callee precondition from that
    ``requires`` clause plus the reviewed invariants and effects.
    """
    preconditions: list[str] = []
    obligations: list[dict] = []
    seen: set[str] = set()
    for index, step in enumerate(use_case.steps):
        if step.component in seen:
            raise UnsupportedCompositionBoundary(
                f"use case {use_case.name!r} composes component {step.component!r} more "
                "than once; one reviewed operation per component is the supported boundary")
        seen.add(step.component)
        reviewed = resolved.get(step.component)
        if reviewed is None:
            raise UnsupportedCompositionBoundary(
                f"component {step.component!r} has no resolved reviewed domain")
        operation = next((item for item in reviewed.operations
                          if item.name == step.operation), None)
        if operation is None:
            raise UnsupportedCompositionBoundary(
                f"component {step.component!r} has no reviewed operation {step.operation!r}")
        if operation.return_type == "boolean":
            raise UnsupportedCompositionBoundary(
                f"operation {step.operation!r} returns boolean; composition steps support "
                "void/unavailable operations only")
        for guard in operation.guards:
            fact = _unparenthesized(render_qualified(guard.expression, step.component))
            preconditions.append(fact)
            obligations.append({"step": index + 1, "component": step.component,
                                "operation": step.operation, "fact": fact})
    return {"use_case": use_case.name,
            "caller_preconditions": preconditions,
            "coupling_obligations": obligations}
