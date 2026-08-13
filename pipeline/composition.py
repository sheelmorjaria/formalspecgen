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
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from . import config
from .architecture import lint_architecture, parse_architecture
from .domain_v2 import (
    BinaryExpr, BooleanExpr, FieldExpr, IntegerExpr, NotExpr, OldExpr,
)
from .domain_v2_promotion import ReviewedDomainSpecV2
from . import jml_ast
from .v2_jml_serializer import _OPS


class CompositionError(ValueError):
    """A composition artifact could not be resolved against reviewed V2 domains."""


class UnsupportedCompositionBoundary(ValueError):
    """The requested composition leaves the reviewed deterministic subset."""


class UnsatisfiableBindingError(ValueError):
    """A composed caller contract is contradictory and would prove vacuously."""

    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(f"{code}: {detail}; vacuous proof prevented")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CompositionStep(_StrictModel):
    component: str
    operation: str
    arguments: dict[str, str] = Field(default_factory=dict)


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
    # Accept the common architecture spelling while retaining one internal model.
    data = json.loads(json.dumps(data))
    for component in data.get("architecture", {}).get("components", []):
        if "type" in component:
            if "kind" in component and component["kind"] != component["type"]:
                raise CompositionError("component type and kind disagree")
            component["kind"] = component.pop("type")
    spec = CompositionSpec.model_validate(data)
    architecture = parse_architecture(spec.architecture)
    for component in architecture.components:
        if not component.external:
            continue
        if component.kind != "interface":
            raise CompositionError("external components must be interfaces (Ports)")
        if not component.operations:
            raise CompositionError("external interface must declare at least one operation contract")
        for operation in component.operations:
            if not operation.requires or not operation.ensures:
                raise CompositionError(
                    f"external interface must declare a contract for {component.name}.{operation.name}")
    return spec


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
    architecture = parse_architecture(spec.architecture)
    external = {component.id for component in architecture.components if component.external}
    used = {step.component for use_case in spec.use_cases for step in use_case.steps} - external
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
    external = {component.id for component in architecture.components if component.external}
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
    for component in sorted(used - bound - external):
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
            external_component = next((item for item in architecture.components
                                       if item.id == step.component and item.external), None)
            if external_component is not None:
                operation = next((item for item in external_component.operations
                                  if item.name == step.operation), None)
                if operation is None:
                    finding("composition-unknown-port-operation", use_case.name, "error",
                            f"External Port {step.component!r} has no operation {step.operation!r}.",
                            "Use an operation declared on the contracted external interface.")
                    continue
                expected = {str(item.get("name")) for item in operation.parameters}
                if set(step.arguments) != expected:
                    finding("composition-port-argument-mismatch", use_case.name, "error",
                            f"Port step {step.component}.{step.operation} requires exact arguments: "
                            + ", ".join(sorted(expected)),
                            "Bind every Port parameter exactly once to an identifier or literal.")
                elif any(not _safe_argument(value) for value in step.arguments.values()):
                    finding("composition-unsafe-port-argument", use_case.name, "error",
                            "Port argument bindings contain an unsupported expression.",
                            "Use a Java identifier or integer/boolean literal only.")
                continue
            if reviewed is None:
                continue
            if step.arguments:
                finding("composition-internal-arguments", use_case.name, "error",
                        "Reviewed V2 operations do not accept explicit arguments.",
                        "Remove arguments from internal atomic steps.")
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
                     resolved: dict[str, ReviewedDomainSpecV2], architecture=None) -> dict:
    """Partition every step guard into caller preconditions and ESC obligations.

    With one reviewed operation per component per use case, no earlier step writes a
    later step's fields, so every guard must be established by the orchestrator's
    caller; OpenJML ESC must then discharge each callee precondition from that
    ``requires`` clause plus the reviewed invariants and effects.
    """
    preconditions: list[str] = []
    obligations: list[dict] = []
    seen: set[str] = set()
    orchestrator_parameters: dict[str, str] = {}
    external_by_id = ({component.id: component for component in architecture.components
                       if component.external} if architecture is not None else {})
    for index, step in enumerate(use_case.steps):
        if step.component in seen:
            raise UnsupportedCompositionBoundary(
                f"use case {use_case.name!r} composes component {step.component!r} more "
                "than once; one reviewed operation per component is the supported boundary")
        seen.add(step.component)
        external = external_by_id.get(step.component)
        if external is not None:
            operation = next((item for item in external.operations
                              if item.name == step.operation), None)
            if operation is None:
                raise UnsupportedCompositionBoundary(
                    f"external Port {step.component!r} has no operation {step.operation!r}")
            expected = {str(item.get("name")): str(item.get("type", "Object"))
                        for item in operation.parameters}
            if set(step.arguments) != set(expected):
                raise UnsupportedCompositionBoundary(
                    f"external Port {step.component}.{step.operation} requires exact argument bindings")
            for parameter, expression in step.arguments.items():
                if not _safe_argument(expression):
                    raise UnsupportedCompositionBoundary(
                        f"unsupported Port argument expression {expression!r}")
                if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", expression):
                    previous = orchestrator_parameters.setdefault(expression, expected[parameter])
                    if previous != expected[parameter]:
                        raise UnsupportedCompositionBoundary(
                            f"orchestrator parameter {expression!r} has conflicting Port types")
            for clause in operation.requires:
                fact = _substitute_arguments(clause, step.arguments)
                preconditions.append(fact)
                obligations.append({"step": index + 1, "component": step.component,
                                    "operation": step.operation, "fact": fact,
                                    "external_port": True})
            continue
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
    _validate_precondition_satisfiability(preconditions, set(orchestrator_parameters))
    return {"use_case": use_case.name,
            "caller_preconditions": preconditions,
            "coupling_obligations": obligations,
            "orchestrator_parameters": orchestrator_parameters}


def _safe_argument(value: str) -> bool:
    return bool(re.fullmatch(r"(?:[A-Za-z_$][A-Za-z0-9_$]*|-?[0-9]+|true|false)", value))


def _substitute_arguments(clause: str, arguments: dict[str, str]) -> str:
    result = clause
    for name in sorted(arguments, key=len, reverse=True):
        result = re.sub(rf"\b{re.escape(name)}\b", arguments[name], result)
    return result


_UNKNOWN = object()


def _literal_value(node):
    """Evaluate a ground expression; return _UNKNOWN when variables remain."""
    if isinstance(node, (jml_ast.IntegerLiteral, jml_ast.BooleanLiteral)):
        return node.value
    if isinstance(node, (jml_ast.Parameter, jml_ast.FieldAccess,
                         jml_ast.ResultValue, jml_ast.OldValue)):
        return _UNKNOWN
    if isinstance(node, jml_ast.UnaryExpr):
        value = _literal_value(node.operand)
        if value is _UNKNOWN:
            return _UNKNOWN
        return (not bool(value)) if node.kind == "not" else -value
    if isinstance(node, jml_ast.BinaryExpr):
        left, right = _literal_value(node.left), _literal_value(node.right)
        if left is _UNKNOWN or right is _UNKNOWN:
            return _UNKNOWN
        operations = {
            "add": lambda: left + right, "sub": lambda: left - right,
            "mul": lambda: left * right, "div": lambda: left // right,
            "lt": lambda: left < right, "lte": lambda: left <= right,
            "gt": lambda: left > right, "gte": lambda: left >= right,
            "eq": lambda: left == right, "neq": lambda: left != right,
            "and": lambda: bool(left) and bool(right),
            "or": lambda: bool(left) or bool(right),
            "implies": lambda: (not bool(left)) or bool(right),
            "iff": lambda: bool(left) == bool(right),
        }
        try:
            return operations[node.kind]()
        except (ArithmeticError, TypeError):
            return _UNKNOWN
    return _UNKNOWN


def _integer_literal(node):
    if isinstance(node, jml_ast.IntegerLiteral):
        return node.value
    if (isinstance(node, jml_ast.UnaryExpr) and node.kind == "neg" and
            isinstance(node.operand, jml_ast.IntegerLiteral)):
        return -node.operand.value
    return None


def _constraints(node):
    """Yield simple parameter/literal comparisons from conjunctions."""
    if isinstance(node, jml_ast.BinaryExpr) and node.kind == "and":
        yield from _constraints(node.left)
        yield from _constraints(node.right)
        return
    if not isinstance(node, jml_ast.BinaryExpr):
        return
    left_name = node.left.name if isinstance(node.left, jml_ast.Parameter) else None
    right_name = node.right.name if isinstance(node.right, jml_ast.Parameter) else None
    left_int, right_int = _integer_literal(node.left), _integer_literal(node.right)
    if left_name is not None and right_int is not None:
        yield left_name, node.kind, right_int
    elif right_name is not None and left_int is not None:
        reverse = {"lt": "gt", "lte": "gte", "gt": "lt", "gte": "lte",
                   "eq": "eq", "neq": "neq"}
        if node.kind in reverse:
            yield right_name, reverse[node.kind], left_int
    elif isinstance(node.left, jml_ast.Parameter) and isinstance(
            node.right, jml_ast.BooleanLiteral) and node.kind in {"eq", "neq"}:
        yield node.left.name, node.kind, node.right.value


def _validate_precondition_satisfiability(clauses: list[str], parameters: set[str]) -> None:
    """Reject ground-false and simple contradictory caller preconditions."""
    parsed = []
    for clause in clauses:
        try:
            node = jml_ast.parse_jml_expression(clause, parameters=parameters)
        except jml_ast.JmlExpressionSyntaxError:
            continue  # OpenJML remains authoritative outside the reviewed parser subset.
        parsed.append(node)
        value = _literal_value(node)
        if value is not _UNKNOWN and not bool(value):
            raise UnsatisfiableBindingError(
                "UNSATISFIABLE_BINDING", f"literal Port precondition {clause!r} is false")

    ranges: dict[str, dict[str, object]] = {}
    for node in parsed:
        for name, operator, value in _constraints(node):
            state = ranges.setdefault(name, {"lower": None, "upper": None,
                                             "equal": None, "boolean": None})
            if isinstance(value, bool):
                required = value if operator == "eq" else not value
                if state["boolean"] is not None and state["boolean"] != required:
                    raise UnsatisfiableBindingError(
                        "CONTRADICTORY_COMPOSITION", f"conflicting Boolean constraints for {name}")
                state["boolean"] = required
                continue
            if operator == "eq":
                state["equal"] = value if state["equal"] is None else state["equal"]
                if state["equal"] != value:
                    raise UnsatisfiableBindingError(
                        "CONTRADICTORY_COMPOSITION", f"conflicting equalities for {name}")
            elif operator in {"gt", "gte"}:
                bound = (value, operator == "gte")
                old = state["lower"]
                if old is None or bound[0] > old[0] or (bound[0] == old[0] and not bound[1]):
                    state["lower"] = bound
            elif operator in {"lt", "lte"}:
                bound = (value, operator == "lte")
                old = state["upper"]
                if old is None or bound[0] < old[0] or (bound[0] == old[0] and not bound[1]):
                    state["upper"] = bound
    for name, state in ranges.items():
        lower, upper, equal = state["lower"], state["upper"], state["equal"]
        impossible = (lower is not None and upper is not None and
                      (lower[0] > upper[0] or
                       (lower[0] == upper[0] and not (lower[1] and upper[1]))))
        if equal is not None:
            impossible = impossible or (lower is not None and
                (equal < lower[0] or (equal == lower[0] and not lower[1])))
            impossible = impossible or (upper is not None and
                (equal > upper[0] or (equal == upper[0] and not upper[1])))
        if impossible:
            raise UnsatisfiableBindingError(
                "CONTRADICTORY_COMPOSITION", f"integer constraints for {name} have no solution")
