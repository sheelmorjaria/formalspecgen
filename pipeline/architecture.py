# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Typed macro-architecture artifacts and deterministic design/composition linting."""
import json
import re
from dataclasses import dataclass, field, asdict


LAYERS = ("entities", "use_cases", "adapters", "infrastructure")
_RANK = {name: index for index, name in enumerate(LAYERS)}


@dataclass
class Dependency:
    target: str
    abstraction: bool = True


@dataclass
class Operation:
    name: str
    parameters: list[dict] = field(default_factory=list)
    returns: str = "void"
    requires: list[str] = field(default_factory=list)
    ensures: list[str] = field(default_factory=list)
    assignable: list[str] = field(default_factory=list)


@dataclass
class Component:
    id: str
    name: str
    layer: str
    kind: str
    responsibilities: list[str] = field(default_factory=list)
    operations: list[Operation] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    trust_zone: str = "internal"
    privilege: str = "standard"
    external: bool = False


@dataclass
class DataFlow:
    source: str
    target: str
    data: str
    classification: str = "internal"
    entry_operation: str | None = None
    sanitizer_operation: str | None = None
    authenticated: bool = False
    authorized: bool = False
    encrypted: bool = False
    audited: bool = False
    bounded: bool = False


@dataclass
class Step:
    component: str
    operation: str


@dataclass
class UseCase:
    name: str
    requires: list[str] = field(default_factory=list)
    ensures: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)


@dataclass
class Architecture:
    name: str
    description: str
    components: list[Component]
    use_cases: list[UseCase] = field(default_factory=list)
    invariants: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def parse_architecture(value: dict | str) -> Architecture:
    data = json.loads(value) if isinstance(value, str) else value
    components = []
    for item in data.get("components", []):
        components.append(Component(
            id=str(item["id"]), name=str(item.get("name") or item["id"]),
            layer=str(item.get("layer", "use_cases")), kind=str(item.get("kind", "interface")),
            responsibilities=list(item.get("responsibilities") or []),
            operations=[Operation(**operation) for operation in item.get("operations", [])],
            dependencies=[Dependency(**dependency) for dependency in item.get("dependencies", [])],
            trust_zone=str(item.get("trust_zone", "internal")),
            privilege=str(item.get("privilege", "standard")),
            external=bool(item.get("external", False))))
    use_cases = [UseCase(name=item["name"], requires=list(item.get("requires") or []),
                         ensures=list(item.get("ensures") or []),
                         steps=[Step(**step) for step in item.get("steps", [])])
                 for item in data.get("use_cases", [])]
    return Architecture(name=str(data.get("name", "System")),
                        description=str(data.get("description", "")), components=components,
                        use_cases=use_cases, invariants=list(data.get("invariants") or []),
                        assumptions=list(data.get("assumptions") or []),
                        data_flows=[DataFlow(**flow) for flow in data.get("data_flows", [])])


def lint_architecture(architecture: Architecture, source_files: dict[str, str] | None = None) -> list[dict]:
    warnings = []
    by_id = {component.id: component for component in architecture.components}
    for component in architecture.components:
        if component.layer not in _RANK:
            warnings.append(_warning("unknown-layer", component.id, "error",
                f"Unknown architecture layer '{component.layer}'.", f"Use one of: {', '.join(LAYERS)}."))
        if len(component.responsibilities) > 3:
            warnings.append(_warning("single-responsibility", component.id, "warning",
                f"{component.name} owns {len(component.responsibilities)} responsibilities.",
                "Split unrelated policy, persistence, transport, or coordination responsibilities."))
        if len(component.operations) > 7:
            warnings.append(_warning("interface-segregation", component.id, "warning",
                f"{component.name} exposes {len(component.operations)} operations.",
                "Split clients into smaller role-specific interfaces."))
        for dependency in component.dependencies:
            target = by_id.get(dependency.target)
            if target is None:
                warnings.append(_warning("missing-component", component.id, "error",
                    f"Dependency target '{dependency.target}' is not declared.", "Declare the component or remove the edge."))
                continue
            source_rank, target_rank = _RANK.get(component.layer, 99), _RANK.get(target.layer, 99)
            if source_rank <= _RANK["use_cases"] and target_rank > source_rank:
                warnings.append(_warning("dependency-inversion", component.id, "error",
                    f"High-level {component.name} depends outward on {target.name} ({target.layer}).",
                    "Introduce an inward-owned interface and make infrastructure implement it.", dependency.target))
            elif source_rank < target_rank and target.kind != "interface" and not dependency.abstraction:
                warnings.append(_warning("concrete-dependency", component.id, "warning",
                    f"{component.name} depends on concrete {target.name}.",
                    "Depend on an interface whose ownership belongs to the inner layer.", dependency.target))
    for cycle in _cycles(by_id):
        warnings.append(_warning("dependency-cycle", cycle[0], "error",
            "Dependency cycle: " + " -> ".join(cycle), "Break the cycle with an event, port, or dependency inversion."))
    warnings.extend(check_composition(architecture))
    warnings.extend(check_stride(architecture))
    for name, source in (source_files or {}).items():
        matches = re.findall(r"\b(?:if|else\s+if)\s*\([^)]*(?:instanceof|getClass\s*\(|\.type\s*==)", source)
        if len(matches) >= 2:
            warnings.append(_warning("open-closed-type-switch", name, "warning",
                f"{name} contains a repeated runtime type switch.",
                "Move variant behavior behind a polymorphic interface or strategy."))
    return warnings


def check_stride(architecture: Architecture) -> list[dict]:
    """STRIDE guardrails over explicit trust-boundary data flows."""
    by_id = {component.id: component for component in architecture.components}
    operations = {f"{component.id}.{operation.name}": operation
                  for component in architecture.components for operation in component.operations}
    warnings = []
    for flow in architecture.data_flows:
        source, target = by_id.get(flow.source), by_id.get(flow.target)
        if not source or not target:
            warnings.append(_warning("stride-invalid-flow", flow.source, "error",
                f"Data flow '{flow.data}' references an unknown endpoint.",
                "Declare both source and target components before reviewing the trust boundary.", flow.target))
            continue
        crosses_trust = source.external or source.trust_zone != target.trust_zone
        if crosses_trust and not flow.authenticated:
            warnings.append(_warning("stride-spoofing", flow.source, "error",
                f"Unauthenticated flow '{flow.data}' crosses into {target.name}.",
                "Require an authenticated principal before accepting the flow.", flow.target))
        sanitizer = operations.get(flow.sanitizer_operation or "")
        sanitizer_proves_clean = bool(sanitizer and any(
            re.search(r"\b(sanitized|validated|trusted)\b", fact, re.I) for fact in sanitizer.ensures))
        if crosses_trust and not sanitizer_proves_clean:
            warnings.append(_warning("stride-tampering", flow.source, "error",
                f"Untrusted data '{flow.data}' reaches {target.name} without a verified sanitization step.",
                "Route it through an operation whose JML postcondition establishes sanitized/validated state.", flow.target))
        if crosses_trust and not flow.audited:
            warnings.append(_warning("stride-repudiation", flow.source, "warning",
                f"Trust-boundary flow '{flow.data}' has no audit evidence.",
                "Record an immutable actor, action, and correlation identifier.", flow.target))
        if flow.classification.lower() in {"confidential", "secret", "restricted", "pii"} and not flow.encrypted:
            warnings.append(_warning("stride-information-disclosure", flow.source, "error",
                f"{flow.classification} data '{flow.data}' crosses an unencrypted flow.",
                "Require authenticated encryption in transit and define redaction at logging boundaries.", flow.target))
        if source.external and not flow.bounded:
            warnings.append(_warning("stride-denial-of-service", flow.source, "warning",
                f"External flow '{flow.data}' has no declared bound or rate limit.",
                "Add finite size/rate bounds and express accepted bounds as operation preconditions.", flow.target))
        if target.privilege in {"privileged", "admin", "system"} and not flow.authorized:
            warnings.append(_warning("stride-elevation-of-privilege", flow.source, "error",
                f"Flow '{flow.data}' reaches privileged {target.name} without authorization.",
                "Require an authorization decision tied to the requested capability.", flow.target))
    return warnings


def check_composition(architecture: Architecture) -> list[dict]:
    operations = {(component.id, operation.name): operation
                  for component in architecture.components for operation in component.operations}
    warnings = []
    for use_case in architecture.use_cases:
        facts = {_normalize(fact) for fact in use_case.requires}
        for index, step in enumerate(use_case.steps):
            operation = operations.get((step.component, step.operation))
            if operation is None:
                warnings.append(_warning("missing-operation", use_case.name, "error",
                    f"Step {index + 1} references missing operation {step.component}.{step.operation}.",
                    "Declare the operation contract before composing the use case."))
                continue
            missing = [requirement for requirement in operation.requires
                       if _normalize(requirement) not in facts]
            if missing:
                warnings.append(_warning("composition-precondition", use_case.name, "error",
                    f"Step {index + 1} cannot establish {step.component}.{step.operation}: " + ", ".join(missing),
                    "Add a preceding operation whose postcondition establishes the fact, or strengthen the use-case precondition."))
            facts.update(_normalize(fact) for fact in operation.ensures)
        for promised in use_case.ensures:
            if _normalize(promised) not in facts:
                warnings.append(_warning("composition-postcondition", use_case.name, "warning",
                    f"The composed steps do not establish use-case result '{promised}'.",
                    "Add an operation postcondition or revise the use-case guarantee."))
    return warnings


def _normalize(value: str) -> str:
    return re.sub(r"\s+", "", value).lower().rstrip(";")


def _warning(code: str, subject: str, severity: str, message: str, advice: str,
             target: str | None = None) -> dict:
    return {"code": code, "subject": subject, "target": target, "severity": severity,
            "message": message, "advice": advice}


def _cycles(by_id: dict[str, Component]) -> list[list[str]]:
    found, visiting, visited = [], [], set()
    def walk(node: str):
        if node in visiting:
            cycle = visiting[visiting.index(node):] + [node]
            if cycle not in found:
                found.append(cycle)
            return
        if node in visited or node not in by_id:
            return
        visiting.append(node)
        for dependency in by_id[node].dependencies:
            walk(dependency.target)
        visiting.pop(); visited.add(node)
    for node in by_id:
        walk(node)
    return found
