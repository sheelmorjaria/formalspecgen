# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Layered system-design workflow: architecture + TLA, then JML interface scaffolds."""
import json
import re
import tempfile
from pathlib import Path

from .architecture import parse_architecture, lint_architecture, Architecture
from .limitations import prompt_guardrails
from .llm import _chat_fn, LLMError
from .tla_backend import check_tla
from .verify import verify_files, classify
from .parse_check import parse_check
from .parse_vcs import parse_vcs
from .staged_architecture import (
    ComponentFragment, OperationFragment, StateVariableFragment, TransitionFragment,
    UseCaseStepFragment, parse_json_fragment, assemble_architecture, validate_transition,
)
from .architecture_tla_renderer import render_architecture_tla
from .architecture_tlc_gate import publish_architecture

DESIGN_SYSTEM = """Design a bounded, verifiable system from the requirement.
This is a finite-state architecture exercise. Every mutable quantity must be a scalar bounded
integer or boolean with an explicit finite bound (for example stock: 0..5). Do not model lists,
sets, maps, queues, arbitrary strings, timestamps, money decimals, or unbounded collections.
Represent repeated resources with a small scalar bound and state the abstraction explicitly.
Every use-case step must use operations declared on its component; external calls require an
explicit positive literal or named parameter binding. Never invent operation or component names.
Apply Clean Architecture and SOLID: entities and use cases own policy; outer infrastructure
depends on inward-owned interfaces. Split reader/writer roles when clients differ. Model concurrent
state transitions explicitly. Return exactly these sections:
=== ARCHITECTURE ===
JSON with name, description, invariants, assumptions, components, and use_cases. Each component has
id, name, layer (entities|use_cases|adapters|infrastructure), kind (interface|class), responsibilities,
dependencies [{target,abstraction}], and operations. Each operation has name, parameters
[{name,type}], returns, requires, ensures, assignable. Each use case has name, requires, ensures,
and ordered steps [{component,operation}]. Components also declare trust_zone, privilege, and external.
Add data_flows with source, target, data, classification, entry_operation, sanitizer_operation,
authenticated, authorized, encrypted, audited, and bounded. Contract facts used between steps must
use identical text. Sanitizer operations must ensure a fact containing sanitized, validated, or trusted.
=== TLA ===
A complete bounded TLA+ module with Init, Next, Spec, and safety invariants.
=== CFG ===
The TLC configuration.
=== END ===
Do not emit prose outside the sections."""


def design_system(requirement: str, provider: str = "glm", max_attempts: int = 3,
                  timeout: int | None = None) -> dict:
    chat = _chat_fn(provider)
    previous = feedback = ""
    attempts = []
    last_candidate = {}
    for number in range(1, max_attempts + 1):
        user = f"System requirement:\n{requirement}"
        if previous:
            user += f"\n\nPrevious candidate:\n{previous}\n\nVerifier/linter feedback:\n{feedback}\nRepair the architecture and model."
        try:
            raw, model, _usage = chat(
                [{"role": "system", "content": DESIGN_SYSTEM + prompt_guardrails(requirement)},
                 {"role": "user", "content": user}], None, 0.1)
        except LLMError as exc:
            return {"status": "API_ERROR", "message": str(exc), "attempts": attempts}
        try:
            architecture, tla, cfg = parse_design(raw)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            attempts.append({"attempt": number, "status": "PARSE_ERROR", "message": str(exc)})
            previous, feedback = raw, str(exc)
            continue
        lint = lint_architecture(architecture)
        blocking = [item for item in lint if item["severity"] == "error"]
        tlc = check_tla(tla, cfg, timeout=timeout)
        status = "VERIFIED" if tlc["status"] == "VERIFIED" and not blocking else "DESIGN_FAILED"
        last_candidate = {"architecture": architecture.to_dict(), "lint": lint,
                          "tla": tla, "cfg": cfg, "tlc": tlc, "model": model}
        attempts.append({"attempt": number, "status": status, "tlc_status": tlc["status"],
                         "blocking_lints": len(blocking)})
        if status == "VERIFIED":
            return {"status": status, "architecture": architecture.to_dict(), "lint": lint,
                    "tla": tla, "cfg": cfg, "tlc": tlc, "attempts": attempts, "model": model}
        previous = raw
        feedback = json.dumps({"lint": blocking, "tlc": tlc}, ensure_ascii=False)[:12000]
    return {"status": "STALLED", "attempts": attempts, "message": "design repair limit reached",
            **last_candidate}


def design_system_staged(requirement: str, provider: str = "ollama",
                         timeout: int = 120, max_attempts: int = 3) -> dict:
    """Elicit small typed fragments, assemble them, and gate publication through TLC."""
    chat = _chat_fn(provider)
    def ask(prompt: str, model):
        raw, _used, _usage = chat([{"role": "system", "content":
            "Return only valid JSON for the requested fragment. Use bounded scalar state; "
            "never invent identifiers."}, {"role": "user", "content": prompt}], None, 0.0)
        return parse_json_fragment(raw, model, max_attempts=max_attempts)
    try:
        components = ask("List components for this requirement as objects with name,type(core/interface/adapter/orchestrator),desc. Requirement:\n" + requirement, list[ComponentFragment])
        operations = {}
        states = {}
        transitions = {}
        for component in components:
            operations[component.name] = ask(
                f"List operations for {component.name}. Each needs name, params, requires, ensures, returns. Requirement:\n{requirement}",
                list[OperationFragment])
            if component.type in {"core", "orchestrator"}:
                states[component.name] = ask(
                    f"List bounded integer/boolean state variables for {component.name}; every integer needs bound and initial. Requirement:\n{requirement}",
                    list[StateVariableFragment])
            transitions[component.name] = ask(
                f"List transitions for {component.name}; each needs operation_name, typed precondition, effects, frame. Use only declared state fields.",
                list[TransitionFragment])
            declared = {item.name for item in states.get(component.name, [])}
            for transition in transitions[component.name]:
                validate_transition(transition, declared)
        steps = ask("List ordered use-case steps with component, operation, and exact arguments for this requirement:\n" + requirement,
                    list[UseCaseStepFragment])
        architecture = assemble_architecture(components, operations, states, steps, transitions)
        all_states = [state for values in states.values() for state in values]
        all_transitions = [(transition.operation_name, transition)
                           for values in transitions.values() for transition in values]
        tla, cfg = render_architecture_tla(all_states, all_transitions, "StagedArchitecture")
        tlc = check_tla(tla, cfg, timeout=timeout)
        if tlc.get("status") != "VERIFIED":
            return {"status": "DESIGN_FAILED", "message": tlc.get("status"), "tlc": tlc}
        return {"status": "VERIFIED", "architecture": architecture.to_dict(),
                "tlc": tlc, "tla": tla, "cfg": cfg,
                "claim": "BOUNDED_ARCHITECTURE_EVIDENCE"}
    except Exception as exc:
        return {"status": "STAGED_GENERATION_FAILED", "message": str(exc)}


def parse_design(raw: str) -> tuple[Architecture, str, str]:
    arch = re.search(r"=== ARCHITECTURE ===\s*(.*?)\s*=== TLA ===", raw, re.S)
    tla = re.search(r"=== TLA ===\s*(.*?)\s*=== CFG ===", raw, re.S)
    cfg = re.search(r"=== CFG ===\s*(.*?)\s*=== END ===", raw, re.S)
    if not arch or not tla or not cfg:
        raise ValueError("missing architecture/TLA/CFG section markers")
    json_text = arch.group(1).strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", json_text, re.S)
    if fenced:
        json_text = fenced.group(1).strip()
    architecture = parse_architecture(json.loads(json_text))
    if not architecture.components:
        raise ValueError("architecture contains no components")
    return architecture, tla.group(1).strip(), cfg.group(1).strip()


def scaffold_interfaces(value: dict | str) -> dict:
    architecture = parse_architecture(value)
    files = {}
    results = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for component in architecture.components:
            if component.kind != "interface":
                continue
            source = _interface_source(component)
            filename = f"{component.name}.java"
            files[filename] = source
        for use_case in architecture.use_cases:
            filename = f"{_java_name(use_case.name)}Orchestrator.java"
            files[filename] = _orchestrator_source(architecture, use_case)
        for filename, source in files.items():
            (root / filename).write_text(source, encoding="utf-8")
        paths = [root / filename for filename in files]
        exit_code, output = verify_files(paths, mode="check")
        results.append({"file": "<architecture scaffold>", "status": classify(exit_code),
                        "exit_code": exit_code,
                        "diagnostics": [item.__dict__ for item in parse_check(output)]})
        esc_exit = None
        esc_output = ""
        if exit_code == 0 and any(name.endswith("Orchestrator.java") for name in files):
            esc_exit, esc_output = verify_files(paths, mode="esc")
    status = "VALIDATED" if results and results[0]["status"] == "VERIFIED" else "CHECK_FAILED"
    return {"status": status, "files": files, "checks": results,
            "composition_verification": {
                "status": classify(esc_exit) if esc_exit is not None else "SKIPPED",
                "exit_code": esc_exit,
                "diagnostics": [item.__dict__ for item in
                                (parse_vcs(esc_output) if esc_exit == 6 else parse_check(esc_output))]
                               if esc_exit not in (None, 0) else []},
            "composition": [item for item in lint_architecture(architecture)
                            if item["code"].startswith("composition-") or item["code"] == "missing-operation"]}


def _interface_source(component) -> str:
    lines = [f"public interface {component.name} {{"]
    for operation in component.operations:
        lines.append("")
        lines.extend(f"    //@ requires {clause.rstrip(';')};" for clause in operation.requires)
        lines.extend(f"    //@ assignable {clause.rstrip(';')};" for clause in operation.assignable)
        lines.extend(f"    //@ ensures {clause.rstrip(';')};" for clause in operation.ensures)
        parameters = ", ".join(f"{item.get('type', 'int')} {item['name']}" for item in operation.parameters)
        lines.append(f"    {operation.returns} {operation.name}({parameters});")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _orchestrator_source(architecture: Architecture, use_case) -> str:
    by_id = {component.id: component for component in architecture.components}
    used_ids = list(dict.fromkeys(step.component for step in use_case.steps))
    used = [by_id[item] for item in used_ids if item in by_id]
    class_name = f"{_java_name(use_case.name)}Orchestrator"
    lines = [f"public final class {class_name} {{"]
    for component in used:
        lines.append(f"    private /*@ spec_public @*/ final {component.name} {component.id};")
    parameters = ", ".join(f"{component.name} {component.id}Arg" for component in used)
    lines.append("")
    lines.extend(f"    //@ requires {component.id}Arg != null;" for component in used)
    if used:
        lines.append("    //@ assignable \\nothing;")
    lines.extend(f"    //@ ensures this.{component.id} == {component.id}Arg;" for component in used)
    lines.append(f"    public {class_name}({parameters}) {{")
    lines.extend(f"        this.{component.id} = {component.id}Arg;" for component in used)
    lines.append("    }")
    operation_map = {(component.id, operation.name): operation
                     for component in architecture.components for operation in component.operations}
    method_parameters = {}
    for step in use_case.steps:
        operation = operation_map.get((step.component, step.operation))
        if operation:
            for parameter in operation.parameters:
                method_parameters.setdefault(parameter["name"], parameter.get("type", "int"))
    lines.append("")
    lines.extend(f"    //@ requires {clause.rstrip(';')};" for clause in use_case.requires)
    lines.extend(f"    //@ ensures {clause.rstrip(';')};" for clause in use_case.ensures)
    method_params = ", ".join(f"{kind} {name}" for name, kind in method_parameters.items())
    last_operation = (operation_map.get((use_case.steps[-1].component, use_case.steps[-1].operation))
                      if use_case.steps else None)
    return_type = last_operation.returns if last_operation else "void"
    lines.append(f"    public {return_type} {_lower_java_name(use_case.name)}({method_params}) {{")
    for index, step in enumerate(use_case.steps):
        operation = operation_map.get((step.component, step.operation))
        if operation:
            args = ", ".join(parameter["name"] for parameter in operation.parameters)
            prefix = "return " if index == len(use_case.steps) - 1 and operation.returns != "void" else ""
            lines.append(f"        {prefix}{step.component}.{operation.name}({args});")
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _java_name(value: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", value)
    return "".join(word[:1].upper() + word[1:] for word in words) or "UseCase"


def _lower_java_name(value: str) -> str:
    name = _java_name(value)
    return name[:1].lower() + name[1:]
