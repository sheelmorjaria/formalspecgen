# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Polyglot (rust/c/cpp) system composition rendering and native proof.

The language-neutral core of the Java lane — parse_composition, resolve_bindings,
analyze_coupling, lint_composition — is reused untouched; only rendering and
verification are language-specific here. Every composition renders into ONE
compilation unit per language (the prover input); generated external adapters
are distributed as sibling scaffolding files and excluded from proving, exactly
like the Java lane's boundary files. This never claims multi-crate or
multi-translation-unit orchestration.
"""
from __future__ import annotations

import re
from pathlib import Path

from .architecture import parse_architecture
from .composition import (
    CompositionError,
    CompositionSpec,
    UnsupportedCompositionBoundary,
    UnsatisfiableBindingError,
    analyze_coupling,
    lint_composition,
    parse_composition,
    resolve_bindings,
)

BOUNDARY_MARKER = "// UNVERIFIED EXTERNAL BOUNDARY: generated integration stub."
_SCOPE = ("single_compilation_unit_native_contract_composition: the rendered unit "
          "carries reviewed component contracts plus contracted Port calls; multi-crate "
          "and multi-translation-unit orchestration are out of scope")
_DISCLAIMER = ("Composition proves the generated orchestrator establishes each callee "
               "precondition within one verified compilation unit. External adapters, "
               "network I/O, and concurrent execution remain unproved.")

_TYPES = {"java": {"int": "int", "boolean": "boolean"},
          "rust": {"int": "i32", "boolean": "bool"},
          "c": {"int": "int", "boolean": "bool"},
          "cpp": {"int": "int", "boolean": "bool"}}


class UnsupportedPolyglotComposition(ValueError):
    """A composition shape this renderer cannot express natively."""


def _pascal(name: str) -> str:
    return "".join(part.capitalize() for part in re.split(r"[^A-Za-z0-9]+", name) if part)


def _snake(name: str) -> str:
    spaced = re.sub(r"[^A-Za-z0-9]+", "_", name)
    return re.sub(r"(?<!^)([A-Z])", r"_\1", spaced).lower()


def _type_name(language: str, declared: str) -> str:
    return _TYPES[language].get(str(declared), str(declared))


def _port_params(language: str, operation) -> str:
    return ", ".join(f"{item['name']}: {_type_name(language, item.get('type', 'int'))}"
                     if language == "rust" else
                     f"{_type_name(language, item.get('type', 'int'))} {item['name']}"
                     for item in operation.parameters)


def _adapter_name(architecture_value: dict, component) -> str:
    raw = next(item for item in architecture_value.get("components", [])
               if str(item.get("id")) == component.id)
    name = str(raw.get("adapter") or f"{component.name}Adapter")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise UnsupportedPolyglotComposition(
            "external adapter must be a language-safe identifier")
    return name


def _translate_fact(language: str, fact: str) -> str:
    """Qualify component-qualified facts onto the orchestrator receiver."""
    fact = str(fact).strip().rstrip(";")
    if language == "rust":
        fact = fact.replace("\\result", "result")
        return re.sub(r"\b([a-z][a-z0-9_]*)\.", r"self.\1.", fact)
    if language == "c":
        return re.sub(r"\b([a-z][a-z0-9_]*)\.", r"\1->", fact)
    return re.sub(r"\b([a-z][a-z0-9_]*)\.", r"this->\1->", fact)


# --------------------------------------------------------------------- rust ---

def render_port_rust(component) -> str:
    lines = [f"pub trait {component.name} {{"]
    for operation in component.operations:
        lines.append(f"    #[requires({'; '.join(_translate_fact('rust', c) for c in operation.requires) or 'true'})]")
        lines.append(f"    #[ensures({'; '.join(_translate_fact('rust', c) for c in operation.ensures) or 'true'})]")
        returns = operation.returns
        signature = f"    fn {operation.name}(&self{_port_params_lead('rust', operation)})"
        if returns and str(returns) != "void":
            signature += f" -> {_type_name('rust', returns)}"
        lines.append(signature + ";")
    return "\n".join(lines + ["}", ""])


def _port_params_lead(language: str, operation) -> str:
    params = _port_params(language, operation)
    return (", " + params) if params else ""


def render_external_adapter_rust(component, adapter_name: str) -> str:
    lines = [BOUNDARY_MARKER, f"pub struct {adapter_name};", "",
             f"impl {component.name} for {adapter_name} {{"]
    for operation in component.operations:
        returns = operation.returns
        signature = f"    fn {operation.name}(&self{_port_params_lead('rust', operation)})"
        body = ["        // TODO: Implement external API call; this body is not proof evidence."]
        if returns and str(returns) != "void":
            signature += f" -> {_type_name('rust', returns)}"
            body.append("        unreachable!(\"external boundary\")")
        else:
            body.append("        // external boundary bodies are excluded from verification")
        lines.append(signature + " {")
        lines.extend(body)
        lines.append("    }")
    return "\n".join(lines + ["}", ""])


def render_orchestrator_rust(use_case, resolved, architecture) -> str:
    coupling = analyze_coupling(use_case, resolved, architecture)
    external_by_id = {c.id: c for c in architecture.components if c.external}
    pascal = _pascal(use_case.name)
    struct_name = f"{pascal}Orchestrator"
    method_name = _snake(use_case.name)
    port_generics = [(index, external_by_id[step.component].name)
                     for index, step in enumerate(use_case.steps)
                     if step.component in external_by_id]
    generic_names = ", ".join(f"P{index}" for index, _ in port_generics)
    impl_bounds = ", ".join(f"P{index}: {name}" for index, name in port_generics)
    struct_decl = (f"pub struct {struct_name}" +
                   (f"<{generic_names}>" if generic_names else "") + " {")
    lines = [struct_decl]
    for index, step in enumerate(use_case.steps):
        component_type = (f"P{index}" if step.component in external_by_id else
                          resolved[step.component].domain_name)
        lines.append(f"    {step.component}: {component_type},")
    ctor_params = ", ".join(
        (f"{step.component}: P{index}"
         if step.component in external_by_id else
         f"{step.component}: {resolved[step.component].domain_name}")
        for index, step in enumerate(use_case.steps))
    impl_decl = (f"impl" + (f"<{impl_bounds}>" if impl_bounds else "") +
                 f" {struct_name}" + (f"<{generic_names}>" if generic_names else "") + " {")
    lines.extend(["}", "", impl_decl,
                  "    pub fn new(" + ctor_params + ") -> Self {",
                  "        Self {"])
    lines.extend(f"            {step.component}: {step.component}," for step in use_case.steps)
    lines.extend(["        }", "    }", ""])
    for fact in coupling["caller_preconditions"]:
        lines.append(f"    #[requires({_translate_fact('rust', fact)})]")
    params = ", ".join(f"{name}: {_type_name('rust', type_name)}" for name, type_name
                        in coupling["orchestrator_parameters"].items())
    lines.append(f"    pub fn {method_name}(&self{', ' + params if params else ''}) {{")
    for step in use_case.steps:
        arguments = ", ".join(step.arguments.values())
        operation = (next(op for op in external_by_id[step.component].operations
                          if op.name == step.operation)
                     if step.component in external_by_id else
                     next(op for op in resolved[step.component].operations
                          if op.name == step.operation))
        lines.append(f"        self.{step.component}.{operation.name}({arguments});")
    lines.extend(["    }", "}", ""])
    return "\n".join(lines)


def build_rust_unit(spec: CompositionSpec, resolved, architecture) -> dict[str, str]:
    from .v2_prusti_serializer import render_struct
    unit = ["#![allow(dead_code, unused_variables, unused_imports)]",
            "use prusti_contracts::*;", ""]
    scaffolds: dict[str, str] = {}
    for component in architecture.components:
        if component.external:
            continue
        reviewed = resolved.get(component.id)
        if reviewed is None:
            continue
        unit.append(render_struct(reviewed))
    for component in architecture.components:
        if component.external:
            unit.append(render_port_rust(component))
            adapter = _adapter_name(spec.architecture, component)
            scaffolds[f"{adapter}.rs"] = render_external_adapter_rust(component, adapter)
    for use_case in spec.use_cases:
        unit.append(render_orchestrator_rust(use_case, resolved, architecture))
    unit_name = f"{_pascal(spec.system_name)}.rs"
    return {unit_name: "\n".join(unit), **scaffolds}


# ------------------------------------------------------------------------ c ---

def render_port_c(component) -> str:
    name = component.name
    lines = [f"/* Contracted external Port: {name} (function-pointer interface). */"]
    for operation in component.operations:
        returns = _type_name("c", operation.returns) if str(operation.returns) != "void" else "void"
        params = _port_params("c", operation)
        lines.append("/*@ " +
                     " ".join(f"requires {_translate_fact('c', c)};" for c in operation.requires))
        lines.append("    " +
                     " ".join(f"ensures {_translate_fact('c', c)};" for c in operation.ensures) + " */")
        lines.append(f"static {returns} {name.lower()}_{operation.name}_reference({params});")
        lines.append("")
    lines.append(f"typedef struct {name} {{")
    for operation in component.operations:
        returns = _type_name("c", operation.returns) if str(operation.returns) != "void" else "void"
        params = ", ".join(_type_name("c", item.get("type", "int"))
                           for item in operation.parameters)
        lines.append(f"    {returns} (*{operation.name})({params});")
    lines.append("} " + name + ";")
    lines.append("")
    lines.append(f"/* The composition proof binds Port calls to the contracted reference")
    lines.append("   implementation below; real adapters are unverified boundaries. */")
    for operation in component.operations:
        returns = _type_name("c", operation.returns) if str(operation.returns) != "void" else "void"
        params = _port_params("c", operation)
        lines.append("/*@ " +
                     " ".join(f"requires {_translate_fact('c', c)};" for c in operation.requires) +
                     " */")
        lines.append(f"static {returns} {name.lower()}_{operation.name}_reference({params}) {{")
        if str(operation.returns) != "void":
            if _type_name("c", operation.returns) == "bool":
                lines.append("    return true;")
            else:
                lines.append("    return 0;")
        else:
            lines.append("    (void)0;")
        lines.append("}")
    return "\n".join(lines + [""])


def render_external_adapter_c(component, adapter_name: str) -> str:
    lines = [BOUNDARY_MARKER,
             f"/* {adapter_name}: fill these bodies with the real external calls. */"]
    for operation in component.operations:
        returns = _type_name("c", operation.returns) if str(operation.returns) != "void" else "void"
        params = _port_params("c", operation)
        lines.append(f"static {returns} {adapter_name.lower()}_{operation.name}({params}) {{")
        lines.append("    /* TODO: external call; excluded from proof. */")
        if str(operation.returns) != "void":
            lines.append("    return " + ("false;" if returns == "bool" else "0;"))
        lines.append("}")
    return "\n".join(lines + [""])


def render_orchestrator_c(use_case, resolved, architecture) -> str:
    coupling = analyze_coupling(use_case, resolved, architecture)
    external_by_id = {c.id: c for c in architecture.components if c.external}
    name = _snake(use_case.name)
    port_steps = [step for step in use_case.steps if step.component in external_by_id]
    if not port_steps or len(use_case.steps) != len(port_steps):
        raise UnsupportedPolyglotComposition(
            "the C composition lane currently supports external Port steps only")
    port = external_by_id[port_steps[0].component]
    params = [f"{port.name} *gateway"]
    params.extend(f"{type_name} {param}" for param, type_name
                  in coupling["orchestrator_parameters"].items())
    reference = f"{port.name.lower()}_{port_steps[0].operation}_reference"
    lines = [f"/*@ requires \\valid_read(gateway);"]
    lines.append(f"    requires gateway->{port_steps[0].operation} == {reference};")
    for fact in coupling["caller_preconditions"]:
        lines.append(f"    requires {_translate_fact('c', fact)}; */")
    lines.append(f"void {name}_orchestrate({', '.join(params)}) {{")
    arguments = ", ".join(port_steps[0].arguments.values())
    lines.append(f"    gateway->{port_steps[0].operation}({arguments});")
    lines.extend(["}", ""])
    return "\n".join(lines)


def build_c_unit(spec: CompositionSpec, resolved, architecture) -> dict[str, str]:
    unit = ["#include <stdbool.h>", ""]
    scaffolds: dict[str, str] = {}
    for component in architecture.components:
        if not component.external:
            continue
        unit.append(render_port_c(component))
        adapter = _adapter_name(spec.architecture, component)
        scaffolds[f"{_snake(adapter)}.c"] = render_external_adapter_c(component, adapter)
    for use_case in spec.use_cases:
        unit.append(render_orchestrator_c(use_case, resolved, architecture))
    return {f"{_snake(spec.system_name)}.c": "\n".join(unit), **scaffolds}


# ---------------------------------------------------------------------- cpp ---

def render_port_cpp(component) -> str:
    lines = [f"class {component.name} {{"]
    for operation in component.operations:
        returns = _type_name("cpp", operation.returns) if str(operation.returns) != "void" else "void"
        for clause in operation.requires:
            lines.append(f"    // requires {_translate_fact('cpp', clause)};")
        params = _port_params("cpp", operation)
        lines.append(f"    virtual {returns} {operation.name}({params}) = 0;")
    lines.extend(["public:", "    virtual ~" + component.name + "() {}",
                  "};", ""])
    return "\n".join(lines)


def render_external_adapter_cpp(component, adapter_name: str) -> str:
    lines = [BOUNDARY_MARKER, f"class {adapter_name} : public {component.name} {{"]
    for operation in component.operations:
        returns = _type_name("cpp", operation.returns) if str(operation.returns) != "void" else "void"
        params = _port_params("cpp", operation)
        override = " override" if str(operation.returns) != "void" else ""
        lines.append(f"    {returns} {operation.name}({params}){override} {{")
        lines.append("        // TODO: real external call via the SDK; not proof evidence.")
        if str(operation.returns) != "void":
            lines.append("        return " + ("false;" if returns == "bool" else "0;"))
        lines.append("    }")
    lines.extend(["public:", f"    ~{adapter_name}() override {{}}", "};", ""])
    return "\n".join(lines)


def render_orchestrator_cpp(use_case, resolved, architecture) -> str:
    coupling = analyze_coupling(use_case, resolved, architecture)
    external_by_id = {c.id: c for c in architecture.components if c.external}
    pascal = _pascal(use_case.name)
    port_steps = [step for step in use_case.steps if step.component in external_by_id]
    if not port_steps or len(use_case.steps) != len(port_steps):
        raise UnsupportedPolyglotComposition(
            "the C++ composition lane currently supports external Port steps only")
    port = external_by_id[port_steps[0].component]
    member = port_steps[0].component
    lines = [f"class {pascal}Orchestrator {{", "public:"]
    lines.append(f"    explicit {pascal}Orchestrator({port.name}* {member})")
    lines.append(f"        : {member}_({member}) {{}}")
    params = "".join(f", {type_name} {param}" for param, type_name
                     in coupling["orchestrator_parameters"].items())
    method = _snake(use_case.name)
    lines.append(f"    void {method}({params.lstrip(', ')}) {{")
    for fact in coupling["caller_preconditions"]:
        lines.append(f"        assert({_translate_fact('cpp', fact)});")
    arguments = ", ".join(port_steps[0].arguments.values())
    lines.append(f"        {member}_->{port_steps[0].operation}({arguments});")
    lines.extend(["    }", "private:", f"    {port.name}* {member}_;", "};", ""])
    return "\n".join(lines)


def build_cpp_unit(spec: CompositionSpec, resolved, architecture) -> dict[str, str]:
    unit = ["#include <cassert>", ""]
    scaffolds: dict[str, str] = {}
    for component in architecture.components:
        if not component.external:
            continue
        unit.append(render_port_cpp(component))
        adapter = _adapter_name(spec.architecture, component)
        scaffolds[f"{adapter}.cpp"] = render_external_adapter_cpp(component, adapter)
    for use_case in spec.use_cases:
        unit.append(render_orchestrator_cpp(use_case, resolved, architecture))
    return {f"{_pascal(spec.system_name)}.cpp": "\n".join(unit), **scaffolds}


# ---------------------------------------------------------------- dispatch ---

_BUILDERS = {"rust": build_rust_unit, "c": build_c_unit, "cpp": build_cpp_unit}


def build_polyglot_composition_sources(spec: CompositionSpec, resolved,
                                       language: str) -> dict[str, str]:
    """Render the single compilation unit plus adapter scaffolding files."""
    architecture = parse_architecture(spec.architecture)
    if language not in _BUILDERS:
        raise UnsupportedPolyglotComposition(f"unsupported composition language: {language}")
    return _BUILDERS[language](spec, resolved, architecture)


def _native_verification(language: str, unit_path: Path) -> dict:
    if language == "rust":
        from .verify_rust import verify_rust
        return verify_rust(unit_path.read_text(encoding="utf-8"), mode="esc",
                           backend="prusti")
    if language == "c":
        from .verify_c import verify_c
        return verify_c(unit_path.read_text(encoding="utf-8"), mode="esc")
    from .verify_cpp import verify_cpp
    return verify_cpp(unit_path)


def _has_native_obligations(language: str, text: str) -> bool:
    if language == "rust":
        return "#[requires(" in text or "#[ensures(" in text
    if language == "c":
        return re.search(r"/\*@\s*requires", text) is not None
    return "assert(" in text  # cpp: bounded assertions are the obligations


def verify_polyglot_composition(value, v2_dir=None, *, language: str,
                                run_esc: bool = True) -> dict:
    """Render + prove one polyglot compilation unit with its native prover."""
    if language not in _BUILDERS:
        return {"status": "UNSUPPORTED_BOUNDARY", "claim": "NO_PROOF",
                "message": f"unsupported composition language: {language}"}
    try:
        spec = parse_composition(value)
        resolved = resolve_bindings(spec, v2_dir)
    except CompositionError as exc:
        return {"status": "RESOLUTION_FAILED", "claim": "NO_PROOF", "message": str(exc)}
    architecture = parse_architecture(spec.architecture)
    findings = lint_composition(spec, resolved)
    if any(item["severity"] == "error" for item in findings):
        return {"status": "COMPOSITION_LINT_FAILED", "claim": "NO_PROOF",
                "findings": findings}
    try:
        coupling = [analyze_coupling(use_case, resolved, architecture)
                    for use_case in spec.use_cases]
    except UnsatisfiableBindingError as exc:
        return {"status": exc.code, "claim": "NO_PROOF", "message": str(exc)}
    except UnsupportedCompositionBoundary as exc:
        return {"status": "UNSUPPORTED_BOUNDARY", "claim": "NO_PROOF", "message": str(exc)}
    try:
        sources = build_polyglot_composition_sources(spec, resolved, language)
    except UnsupportedPolyglotComposition as exc:
        return {"status": "UNSUPPORTED_BOUNDARY", "claim": "NO_PROOF", "message": str(exc)}
    unverified_boundaries = sorted(
        _adapter_name(spec.architecture, component)
        for component in architecture.components if component.external)
    boundary_files = {f"{_adapter_name(spec.architecture, c)}.rs" if language == "rust"
                      else f"{_snake(_adapter_name(spec.architecture, c))}.c"
                      if language == "c" else
                      f"{_adapter_name(spec.architecture, c)}.cpp"
                      for c in architecture.components if c.external}
    unit_names = [name for name in sources if name not in boundary_files]
    base = {"files": sources, "coupling": coupling, "scope": _SCOPE,
            "language": language,
            "single_compilation_unit": True,
            "concurrent_linearizability_proved": False,
            "unverified_boundaries": unverified_boundaries,
            "verification_skips": {name: "Unverified external boundary"
                                   for name in unverified_boundaries},
            "external_io_safety_proved": False, "disclaimer": _DISCLAIMER}
    if not run_esc:
        return {**base, "status": "COMPOSITION_CHECKED", "claim": "STATIC_CHECK"}
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name, text in sources.items():
            (root / name).write_text(text, encoding="utf-8")
        unit_path = root / unit_names[0]
        verification = _native_verification(language, unit_path)
    result = {**base, "verification": verification,
              "exit_code": verification.get("exit_code")}
    if verification.get("status") != "VERIFIED":
        status = verification.get("status", "VERIFY_FAILED")
        return {**result, "status": f"COMPOSITION_{status}", "claim": "NO_PROOF"}
    if not any(_has_native_obligations(language, text)
               for name, text in sources.items() if name in unit_names):
        return {**result, "status": "VACUOUS_COMPOSITION", "claim": "NO_PROOF",
                "message": "the unit carries no native proof obligation; "
                           "the composition discharged nothing"}
    if language == "cpp":
        return {**result, "status": "COMPOSITION_VERIFIED",
                "claim": "BOUNDED_SYSTEM_COMPOSITION_PROOF", "bounded_only": True}
    return {**result, "status": "COMPOSITION_VERIFIED",
            "claim": ("SYSTEM_COMPOSITION_PROOF" if unverified_boundaries else
                      "SCOPED_COMPOSITION_PROOF")}
