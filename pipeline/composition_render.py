# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic composition rendering and scoped composition verification.

Every emitted Java/JML line is derived from promoted V2 artifacts: component
classes reuse the reviewed serializer, interfaces are pure abstraction surfaces,
and orchestrator contracts come from the coupling analysis over reviewed guards,
effects, and frames.  OpenJML ESC then judges whether the orchestrator satisfies
each callee precondition.  The claim is deliberately scoped to single-threaded
atomic contract composition.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

from .architecture import parse_architecture
from .composition import (
    CompositionError,
    CompositionUseCase,
    UnsupportedCompositionBoundary,
    analyze_coupling,
    lint_composition,
    parse_composition,
    render_qualified,
    resolve_bindings,
)
from .domain_v2 import BoolStateVariable, IntStateVariable
from .domain_v2_promotion import ReviewedDomainSpecV2
from .parse_check import parse_check
from .parse_vcs import parse_vcs
from .verify import classify, has_dropped_vc, verify_files
from .v2_jml_serializer import _getter_name, java_method_name, render_class

_SCOPE = "single_threaded_atomic_contract_composition"
_DISCLAIMER = (
    "OpenJML ESC proved the orchestrator satisfies every reviewed callee "
    "precondition for an atomic, single-threaded contract simulation.  This is "
    "not concurrent linearizability and does not model distributed asynchrony, "
    "message duplication, or eventual consistency.")


def _pascal(value: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", value)
    return "".join(word[:1].upper() + word[1:] for word in words) or "System"


def _operation(reviewed: ReviewedDomainSpecV2, name: str):
    return next(item for item in reviewed.operations if item.name == name)


def render_interface(reviewed: ReviewedDomainSpecV2) -> str:
    """Emit the dependency-inversion abstraction surface for a bound component.

    The interface deliberately carries no JML behavior clauses: its contract is
    the reviewed implementation class, and inventing independent spec text here
    would create an unproven second source of truth.
    """
    lines = [
        f"// Abstraction surface for reviewed module '{reviewed.module_name}'.",
        "// Behavioral contracts live on the reviewed implementation class and",
        "// are bound by composition ESC; this interface intentionally carries",
        "// no independent JML claims.",
        f"public interface {reviewed.domain_name}API {{",
    ]
    for variable in reviewed.state_variables:
        java_type = "int" if isinstance(variable, IntStateVariable) else "boolean"
        lines.append(f"    public /*@ pure @*/ {java_type} "
                     f"{_getter_name(variable.name)}();")
    for operation in reviewed.operations:
        lines.extend(["", f"    {operation.return_type} "
                          f"{java_method_name(operation.name)}();"])
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_orchestrator(use_case: CompositionUseCase,
                        resolved: dict[str, ReviewedDomainSpecV2]) -> str:
    """Deterministically compose reviewed operations into a JML orchestrator."""
    coupling = analyze_coupling(use_case, resolved)
    pascal = _pascal(use_case.name)
    class_name = f"{pascal}Orchestrator"
    method_name = pascal[:1].lower() + pascal[1:]
    lines = [f"public class {class_name} {{"]
    for step in use_case.steps:
        lines.append(f"    private /*@ spec_public @*/ final "
                     f"{resolved[step.component].domain_name} {step.component};")
    parameters = ", ".join(
        f"{resolved[step.component].domain_name} {step.component}Arg"
        for step in use_case.steps)
    lines.append("")
    lines.extend(f"    //@ requires {step.component}Arg != null;"
                 for step in use_case.steps)
    lines.append("    //@ assignable \\nothing;")
    lines.extend(f"    //@ ensures this.{step.component} == {step.component}Arg;"
                 for step in use_case.steps)
    lines.append(f"    public {class_name}({parameters}) {{")
    lines.extend(f"        this.{step.component} = {step.component}Arg;"
                 for step in use_case.steps)
    lines.append("    }")

    frame: list[str] = []
    for step in use_case.steps:
        frame.extend(f"{step.component}.{name}"
                     for name in _operation(resolved[step.component],
                                            step.operation).frame)
    lines.append("")
    lines.extend(f"    //@ requires {fact};"
                 for fact in coupling["caller_preconditions"])
    lines.append("    //@ assignable " +
                 (", ".join(frame) if frame else r"\nothing") + ";")
    for step in use_case.steps:
        operation = _operation(resolved[step.component], step.operation)
        for effect in operation.effects:
            value = render_qualified(effect.value, step.component, pre_state=True)
            lines.append(f"    //@ ensures {step.component}.{effect.target} "
                         f"== {value};")
    lines.append(f"    public void {method_name}() {{")
    lines.extend(f"        {step.component}."
                 f"{java_method_name(step.operation)}();"
                 for step in use_case.steps)
    lines.extend(["    }", "}", ""])
    return "\n".join(lines)


def build_composition_sources(spec, resolved) -> dict[str, str]:
    """Assemble every deterministic Java/JML source for the composition."""
    sources: dict[str, str] = {}
    rendered_domains: set[str] = set()
    for binding in spec.bindings:
        reviewed = resolved[binding.component]
        if reviewed.domain_name in rendered_domains:
            continue
        rendered_domains.add(reviewed.domain_name)
        sources[f"{reviewed.domain_name}.java"] = render_class(reviewed)
        sources[f"{reviewed.domain_name}API.java"] = render_interface(reviewed)
    for use_case in spec.use_cases:
        sources[f"{_pascal(use_case.name)}Orchestrator.java"] = \
            render_orchestrator(use_case, resolved)
    return sources


def _has_operation_obligations(text: str) -> bool:
    """True when an orchestrator declares a non-constructor proof obligation."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//@ requires") and "Arg != null;" not in stripped:
            return True
        if stripped.startswith("//@ ensures") and \
                not stripped.startswith("//@ ensures this."):
            return True
    return False


def verify_composition(value, v2_dir=None, *, run_esc: bool = True) -> dict:
    """Render the composition deterministically and let OpenJML judge it."""
    try:
        spec = parse_composition(value)
        resolved = resolve_bindings(spec, v2_dir)
    except CompositionError as exc:
        return {"status": "RESOLUTION_FAILED", "claim": "NO_PROOF", "message": str(exc)}
    try:
        coupling = [analyze_coupling(use_case, resolved)
                    for use_case in spec.use_cases]
    except UnsupportedCompositionBoundary as exc:
        return {"status": "UNSUPPORTED_BOUNDARY", "claim": "NO_PROOF",
                "message": str(exc)}
    findings = lint_composition(spec, resolved)
    if any(item["severity"] == "error" for item in findings):
        return {"status": "COMPOSITION_LINT_FAILED", "claim": "NO_PROOF",
                "findings": findings}
    sources = build_composition_sources(spec, resolved)
    base = {"files": sources, "coupling": coupling, "scope": _SCOPE,
            "concurrent_linearizability_proved": False, "disclaimer": _DISCLAIMER}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        paths = []
        for name in sorted(sources):
            path = root / name
            path.write_text(sources[name], encoding="utf-8")
            paths.append(path)
        check_exit, check_output = verify_files(paths, mode="check")
        if check_exit != 0:
            return {**base, "status": "CHECK_FAILED", "claim": "NO_PROOF",
                    "exit_code": check_exit,
                    "diagnostics": [item.__dict__ for item in parse_check(check_output)]}
        if not run_esc:
            return {**base, "status": "COMPOSITION_CHECKED", "claim": "STATIC_CHECK"}
        esc_exit, esc_output = verify_files(paths, mode="esc")
    verdict = {**base, "exit_code": esc_exit}
    esc_status = classify(esc_exit)
    if esc_status == "VERIFIED":
        if has_dropped_vc(esc_output):
            return {**verdict, "status": "VACUOUS_COMPOSITION", "claim": "NO_PROOF",
                    "message": ("OpenJML reported an unsupported construct dropped "
                                "from the SMT encoding; the composition proof is "
                                "not trustworthy")}
        if not any(_has_operation_obligations(text)
                   for name, text in sources.items() if "Orchestrator" in name):
            return {**verdict, "status": "VACUOUS_COMPOSITION", "claim": "NO_PROOF",
                    "message": ("no orchestrator carries a caller precondition or "
                                "effect obligation; the composition discharged "
                                "nothing")}
        return {**verdict, "status": "COMPOSITION_VERIFIED",
                "claim": "SCOPED_COMPOSITION_PROOF"}
    diagnostics = parse_vcs(esc_output) if esc_exit == 6 else parse_check(esc_output)
    return {**verdict, "status": f"COMPOSITION_{esc_status}", "claim": "NO_PROOF",
            "diagnostics": [item.__dict__ for item in diagnostics]}


def reverify_composition(value, changed_module: str, v2_dir=None, *,
                         run_esc: bool = True) -> dict:
    """Trace reverse dependencies of a changed reviewed module and re-prove."""
    try:
        spec = parse_composition(value)
        resolved = resolve_bindings(spec, v2_dir)
    except CompositionError as exc:
        return {"status": "RESOLUTION_FAILED", "claim": "NO_PROOF", "message": str(exc)}
    seeds = {component for component, reviewed in resolved.items()
             if reviewed.module_name == changed_module}
    reverse: dict[str, set[str]] = {component: set() for component in resolved}
    architecture = parse_architecture(spec.architecture)
    for component in architecture.components:
        for dependency in component.dependencies:
            if dependency.target in reverse:
                reverse[dependency.target].add(component.id)
    impacted, frontier = set(seeds), list(seeds)
    while frontier:
        current = frontier.pop()
        for dependent in reverse.get(current, ()):
            if dependent not in impacted:
                impacted.add(dependent)
                frontier.append(dependent)
    impacted_use_cases = [use_case.name for use_case in spec.use_cases
                          if any(step.component in impacted
                                 for step in use_case.steps)]
    if not impacted_use_cases:
        return {"status": "NOT_IMPACTED", "changed_module": changed_module,
                "impacted_components": sorted(impacted),
                "impacted_use_cases": [],
                "note": ("no composed use case references the changed module or its "
                         "dependents; previously published composition evidence is "
                         "unaffected")}
    verdict = verify_composition(value, v2_dir, run_esc=run_esc)
    return {"status": "REVERIFIED" if verdict["status"] == "COMPOSITION_VERIFIED"
            else "REVERIFICATION_FAILED",
            "changed_module": changed_module,
            "impacted_components": sorted(impacted),
            "impacted_use_cases": impacted_use_cases,
            "composition_status": verdict["status"],
            **{key: item for key, item in verdict.items() if key != "status"}}
