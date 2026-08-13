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
    UnsatisfiableBindingError,
    UnsupportedCompositionBoundary,
    _unparenthesized,
    analyze_coupling,
    lint_composition,
    parse_composition,
    render_qualified,
    resolve_bindings,
)
from .domain_v2 import (
    BinaryExpr, BoolStateVariable, FieldExpr, IntStateVariable, IntegerExpr,
    NotExpr, OldExpr, BooleanExpr, _referenced_fields,
)
from .domain_v2_promotion import ReviewedDomainSpecV2
from .parse_check import parse_check
from .parse_vcs import parse_vcs
from .verify import classify, has_dropped_vc, verify_files
from .v2_jml_serializer import (
    _effect_expression, _getter_name, _OPS, canonical_guard_expressions,
    java_method_name, render_expression, render_getter, render_state_variable,
)

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
                        resolved: dict[str, ReviewedDomainSpecV2], architecture=None) -> str:
    """Deterministically compose reviewed operations into a JML orchestrator."""
    coupling = analyze_coupling(use_case, resolved, architecture)
    external_by_id = ({component.id: component for component in architecture.components
                       if component.external} if architecture is not None else {})
    pascal = _pascal(use_case.name)
    class_name = f"{pascal}Orchestrator"
    method_name = pascal[:1].lower() + pascal[1:]
    lines = [f"public class {class_name} {{"]
    for step in use_case.steps:
        component_type = (external_by_id[step.component].name
                          if step.component in external_by_id else
                          resolved[step.component].domain_name)
        lines.append(f"    private /*@ spec_public @*/ final "
                     f"{component_type} {step.component};")
    parameters = ", ".join(
        f"{(external_by_id[step.component].name if step.component in external_by_id else resolved[step.component].domain_name)} {step.component}Arg"
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
        if step.component in external_by_id:
            continue
        frame.extend(f"{step.component}.{name}"
                     for name in _operation(resolved[step.component],
                                            step.operation).frame)
    lines.append("")
    lines.extend(f"    //@ requires {fact};"
                 for fact in coupling["caller_preconditions"])
    lines.append("    //@ assignable " +
                 (", ".join(frame) if frame else r"\nothing") + ";")
    for step in use_case.steps:
        if step.component in external_by_id:
            continue
        operation = _operation(resolved[step.component], step.operation)
        for effect in operation.effects:
            value = render_qualified(effect.value, step.component, pre_state=True)
            lines.append(f"    //@ ensures {step.component}.{effect.target} "
                         f"== {value};")
    method_parameters = ", ".join(
        f"{_java_type(type_name)} {name}" for name, type_name
        in coupling["orchestrator_parameters"].items())
    lines.append(f"    public void {method_name}({method_parameters}) {{")
    for step in use_case.steps:
        arguments = ", ".join(step.arguments.values())
        lines.append(f"        {step.component}.{java_method_name(step.operation)}"
                     f"({arguments});")
    lines.extend(["    }", "}", ""])
    return "\n".join(lines)


def _variable_type(variable) -> str:
    return "int" if isinstance(variable, IntStateVariable) else "boolean"


def _body_expression(node, field_map: dict[str, str]) -> str:
    """Render a reviewed expression as a Java body term over the mapped fields.

    ``OldExpr`` collapses to the mapped field: bodies evaluate every effect RHS
    against the pre-state captured at method entry, matching the reviewed
    simultaneous-effect semantics of the V2 traverser.
    """
    if isinstance(node, FieldExpr):
        if node.name not in field_map:
            raise UnsupportedCompositionBoundary(
                f"reviewed expression references undeclared field {node.name!r}")
        return field_map[node.name]
    if isinstance(node, IntegerExpr):
        return str(node.value)
    if isinstance(node, BooleanExpr):
        return "true" if node.value else "false"
    if isinstance(node, OldExpr):
        return _body_expression(node.expression, field_map)
    if isinstance(node, NotExpr):
        return "!(" + _body_expression(node.expression, field_map) + ")"
    if isinstance(node, BinaryExpr):
        operator = _OPS.get(node.kind)
        if operator is None:
            raise UnsupportedCompositionBoundary(
                f"unsupported V2 expression kind {node.kind!r}")
        left = _body_expression(node.left, field_map)
        right = _body_expression(node.right, field_map)
        return f"({left} {operator} {right})"
    raise UnsupportedCompositionBoundary(
        f"unsupported V2 expression node {type(node).__name__}")


def _operation_with_reviewed_body(operation, variables_by_name: dict) -> list[str]:
    """Emit a JML method whose body deterministically executes the reviewed effects."""
    if operation.failure_semantics == "exception":
        raise UnsupportedCompositionBoundary(
            f"operation {operation.name!r} uses exception semantics; deterministic "
            "body synthesis supports void/unavailable and boolean/false_and_stutter only")
    method = java_method_name(operation.name)
    frame = ", ".join(operation.frame) if operation.frame else r"\nothing"
    referenced = sorted(set().union(
        *(_referenced_fields(effect.value) for effect in operation.effects))
        if operation.effects else set())
    pre_map = {name: f"pre_{name}" for name in referenced}
    decl_map = {name: f"this.{name}" for name in variables_by_name}
    lines = []
    if operation.return_type == "void":
        lines.extend(f"    //@ requires {render_expression(guard)};"
                     for guard in canonical_guard_expressions(operation))
        lines.append(f"    //@ assignable {frame};")
        lines.append(f"    //@ ensures {_effect_expression(operation)};")
        lines.append(f"    public void {method}() {{")
    else:
        guards = " && ".join(
            _unparenthesized(_body_expression(expression, decl_map))
            for expression in canonical_guard_expressions(operation)) or "true"
        lines.extend([
            f"    //@ assignable {frame};",
            f"    //@ ensures \\result <==> ({guards});",
            f"    //@ ensures \\result ==> ({_effect_expression(operation)});",
        ])
        lines.append("    public boolean " + method + "() {")
        lines.append(f"        if (!({guards})) {{")
        lines.append("            return false;")
        lines.append("        }")
    for name in referenced:
        lines.append(f"        final {_variable_type(variables_by_name[name])} "
                     f"pre_{name} = this.{name};")
    for effect in operation.effects:
        lines.append(f"        this.{effect.target} = "
                     f"{_body_expression(effect.value, pre_map)};")
    if operation.return_type != "void":
        lines.append("        return true;")
    lines.append("    }")
    return lines


def render_verified_class(reviewed: ReviewedDomainSpecV2) -> str:
    """Render the reviewed class with bodies transcribed from the reviewed effects.

    Unlike the drafting serializer (whose empty bodies await the implement loop),
    composition emits deterministic effect-executing bodies so OpenJML ESC has a
    concrete implementation to prove against the same reviewed contracts.
    """
    variables_by_name = {variable.name: variable
                         for variable in reviewed.state_variables}
    initial = " && ".join(
        f"{variable.name} == " +
        (("true" if variable.initial else "false")
         if isinstance(variable, BoolStateVariable) else str(variable.initial))
        for variable in reviewed.state_variables) or "true"
    lines = [f"public class {reviewed.domain_name} {{"]
    for variable in reviewed.state_variables:
        lines.append(render_state_variable(variable)[0])
    lines.append("")
    for variable in reviewed.state_variables:
        lines.extend(render_state_variable(variable)[1:])
    lines.extend(
        f"    //@ public invariant {render_expression(invariant.expression)};"
        for invariant in reviewed.tlc_invariants)
    lines.extend(["", r"    //@ assignable \nothing;",
                  f"    //@ ensures {initial};",
                  f"    public {reviewed.domain_name}() {{"])
    lines.extend(f"        this.{variable.name} = " +
                 (("true" if variable.initial else "false")
                  if isinstance(variable, BoolStateVariable) else str(variable.initial)) + ";"
                 for variable in reviewed.state_variables)
    lines.append("    }")
    for variable in reviewed.state_variables:
        lines.extend(["", render_getter(variable)])
    for operation in reviewed.operations:
        lines.extend([""])
        lines.extend(_operation_with_reviewed_body(operation, variables_by_name))
    lines.extend(["}", ""])
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
        sources[f"{reviewed.domain_name}.java"] = render_verified_class(reviewed)
        sources[f"{reviewed.domain_name}API.java"] = render_interface(reviewed)
    architecture = parse_architecture(spec.architecture)
    for use_case in spec.use_cases:
        sources[f"{_pascal(use_case.name)}Orchestrator.java"] = \
            render_orchestrator(use_case, resolved, architecture)
    for component in architecture.components:
        if component.external and component.kind == "interface":
            adapter_name = _external_adapter_name(spec.architecture, component.id,
                                                  component.name)
            sources[f"{component.name}.java"] = render_external_port(component)
            sources[f"{adapter_name}.java"] = render_external_adapter(component, adapter_name)
    return sources


def _java_type(value: str) -> str:
    return {"integer": "int", "bool": "boolean", "string": "String"}.get(value, value)


def _operation_parameters(operation) -> str:
    return ", ".join(f"{_java_type(str(item.get('type', 'Object')))} {item['name']}"
                     for item in operation.parameters)


def _external_adapter_name(architecture_value: dict, component_id: str,
                           component_name: str) -> str:
    raw = next(item for item in architecture_value.get("components", [])
               if str(item.get("id")) == component_id)
    name = str(raw.get("adapter") or f"{component_name}Adapter")
    if not re.fullmatch(r"[A-Z][A-Za-z0-9_$]*", name):
        raise UnsupportedCompositionBoundary("external adapter must be a Java type identifier")
    return name


def render_external_port(component) -> str:
    lines = ["// Verified abstraction contract for an external boundary.",
             f"public interface {component.name} {{"]
    for operation in component.operations:
        lines.append("")
        lines.extend(f"    //@ requires {clause};" for clause in operation.requires)
        lines.extend(f"    //@ ensures {clause};" for clause in operation.ensures)
        lines.append("    //@ assignable " +
                     (", ".join(operation.assignable) if operation.assignable else r"\nothing") + ";")
        lines.append(f"    public {_java_type(operation.returns)} {operation.name}"
                     f"({_operation_parameters(operation)});")
    return "\n".join(lines + ["}", ""])


def render_external_adapter(component, adapter_name: str) -> str:
    lines = ["// UNVERIFIED EXTERNAL BOUNDARY: generated integration stub.",
             f"public class {adapter_name} implements {component.name} {{"]
    for operation in component.operations:
        lines.append("")
        lines.extend(f"    //@ requires {clause};" for clause in operation.requires)
        lines.extend(f"    //@ ensures {clause};" for clause in operation.ensures)
        lines.append("    //@ assignable " +
                     (", ".join(operation.assignable) if operation.assignable else r"\nothing") + ";")
        return_type = _java_type(operation.returns)
        lines.append(f"    public {return_type} {operation.name}"
                     f"({_operation_parameters(operation)}) {{")
        lines.append("        // TODO: Implement external API call; this body is not ESC evidence.")
        if return_type == "boolean": lines.append("        return false;")
        elif return_type in {"byte", "short", "int", "long", "float", "double"}:
            lines.append("        return 0;")
        elif return_type != "void": lines.append("        return null;")
        lines.append("    }")
    return "\n".join(lines + ["}", ""])


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
        architecture = parse_architecture(spec.architecture)
        coupling = [analyze_coupling(use_case, resolved, architecture)
                    for use_case in spec.use_cases]
    except UnsatisfiableBindingError as exc:
        return {"status": exc.code, "claim": "NO_PROOF", "message": str(exc)}
    except UnsupportedCompositionBoundary as exc:
        return {"status": "UNSUPPORTED_BOUNDARY", "claim": "NO_PROOF",
                "message": str(exc)}
    findings = lint_composition(spec, resolved)
    if any(item["severity"] == "error" for item in findings):
        return {"status": "COMPOSITION_LINT_FAILED", "claim": "NO_PROOF",
                "findings": findings}
    try:
        sources = build_composition_sources(spec, resolved)
    except UnsupportedCompositionBoundary as exc:
        return {"status": "UNSUPPORTED_BOUNDARY", "claim": "NO_PROOF",
                "message": str(exc)}
    unverified_boundaries = sorted(
        _external_adapter_name(spec.architecture, component.id, component.name)
        for component in architecture.components if component.external)
    boundary_files = {f"{name}.java" for name in unverified_boundaries}
    base = {"files": sources, "coupling": coupling, "scope": _SCOPE,
            "concurrent_linearizability_proved": False,
            "unverified_boundaries": unverified_boundaries,
            "verification_skips": {name: "Unverified external boundary"
                                   for name in unverified_boundaries},
            "external_io_safety_proved": False, "disclaimer": _DISCLAIMER}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        paths = []
        for name in sorted(sources):
            path = root / name
            path.write_text(sources[name], encoding="utf-8")
            if name not in boundary_files:
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
        vacuity_markers = ("Precondition is always false", "precondition is false",
                           "unsatisfiable precondition")
        if has_dropped_vc(esc_output) or any(
                marker.lower() in esc_output.lower() for marker in vacuity_markers):
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
                "claim": ("SYSTEM_COMPOSITION_PROOF" if unverified_boundaries else
                          "SCOPED_COMPOSITION_PROOF")}
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
