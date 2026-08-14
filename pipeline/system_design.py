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
    UseCaseStepFragment, parse_json_fragment, parse_component_fragments,
    parse_operation_fragments,
    parse_fragment_list,
    normalize_transition_fragments,
    assemble_architecture, assemble_unified_architecture, validate_transition,
)
from .architecture_tla_renderer import render_architecture_tla, render_unified_architecture
from .architecture_tlc_gate import publish_architecture
from .domain_generator import _dsl_expression

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


def _component_filename(name: str, language: str) -> str:
    import re
    snake = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", snake).lower()
    suffix = {"java": ".java", "rust": ".rs", "c": ".c", "cpp": ".cpp"}.get(language)
    if suffix is None:
        raise ValueError(f"UNSUPPORTED_LANGUAGE: {language}")
    return f"{name if language in {'java', 'cpp'} else snake}{suffix}"


def _inject_missing_adapters(components):
    """Ensure every external port has a deterministic unverified adapter."""
    existing = {item.implements for item in components if item.type == "adapter"}
    for interface in list(components):
        if interface.type == "interface" and interface.name not in existing:
            components.append(ComponentFragment(name=f"Stripe{interface.name}", type="adapter",
                                                desc=f"External adapter for {interface.name}",
                                                implements=interface.name, external=True))
    return components


def design_system_staged(requirement: str, provider: str = "ollama",
                         timeout: int = 120, max_attempts: int = 3,
                         target_lang: str = "java", repair_feedback: str = "") -> dict:
    """Elicit small typed fragments, assemble them, and gate publication through TLC."""
    chat = _chat_fn(provider)
    history = [{"role": "system", "content":
                "You are a formal methods architecture assistant. Return only strict JSON; "
                "use bounded scalar state and preserve identifiers from prior stages. "
                "For core components, reference an existing reviewed V2 domain with a safe "
                "lowercase domain field whenever one is named by the requirement; never emit "
                "state_variables or transitions for a component that has domain. The reviewed "
                "domain is the sole source of truth for its state and transition ASTs."},
               {"role": "user", "content": "System requirement:\n" + requirement +
                ("\n\nPrevious TLC failure; repair the model:\n" + repair_feedback
                 if repair_feedback else "")}]
    transition_schema = {"type": "object", "required": ["transitions"], "properties": {
        "transitions": {"type": "array", "minItems": 1, "items": {"type": "object",
            "required": ["operation_name", "precondition", "effects", "frame"],
            "properties": {
                "operation_name": {"type": "string"},
                "precondition": {"type": "string"},
                "effects": {"type": "array", "minItems": 1, "items": {"type": "object",
                    "required": ["target", "value"], "properties": {
                        "target": {"type": "string"}, "value": {"type": "string"}},
                    "additionalProperties": False}},
                "frame": {"type": "array", "minItems": 1, "items": {"type": "string"}},
            }, "additionalProperties": False}},
    }, "additionalProperties": False}

    def ask_json(prompt: str, parser, system: str = "Return only valid JSON for the requested fragment.", schema=None):
        """Call Ollama defensively, retrying empty or malformed fragment responses."""
        nudge = ""
        last_error = None
        for attempt in range(max_attempts):
            history.append({"role": "user", "content": system + "\n" + prompt + nudge})
            caller = _chat_fn(provider, json_schema=schema) if schema else chat
            raw, _used, _usage = caller(
                history, None, 0.0)
            history.append({"role": "assistant", "content": raw or ""})
            if not raw or not raw.strip():
                last_error = "empty response"
                nudge = "\n\nIMPORTANT: Do not return an empty response. Return ONLY valid JSON."
                continue
            try:
                return parser(raw)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                last_error = str(exc)
                nudge = ("\n\nIMPORTANT: Repair the previous response and return ONLY valid JSON. "
                         f"Validation error: {exc}")
        raise ValueError(f"FRAGMENT_REPAIR_FAILED: {last_error}")

    def ask_model(prompt: str, model, parser=None, schema=None):
        parser = parser or (lambda raw: parse_json_fragment(raw, model))
        return ask_json(prompt, parser,
                        "Return only valid JSON for the requested typed fragment.", schema)
    try:
        components = ask_json(
            "List components for this requirement with name, type, desc, and no file field; include implements only when applicable. The compiler assigns filenames. Requirement:\n" + requirement,
            parse_component_fragments, "Return only a JSON list of component objects.")
        # Bind explicit reviewed-domain references deterministically. This keeps the model's
        # component list lightweight while preventing it from silently dropping a named domain.
        for component in components:
            match = re.search(r"['\"]([a-z_][a-z0-9_]*)['\"]\s+domain", requirement,
                              flags=re.IGNORECASE)
            if match and component.name.lower().startswith(match.group(1)):
                component.domain = match.group(1).lower()
                component.type = "core"
        components = _inject_missing_adapters(components)
        for component in components:
            component.file = _component_filename(component.name, target_lang)
        operations = {}
        states = {}
        transitions = {}
        for component in components:
            operation_prompt = (f"List operations for {component.name}. Return only JSON. Each needs name, params, requires, ensures, returns. "
                                f"requires and ensures MUST be single infix strings, never lists. Parameter types MUST be int or boolean only; never array, list, String, or object. "
                                f"Use an empty params list when there are no parameters. You may return a flat list or an object keyed by component name. Requirement:\n{requirement}")
            grouped = ask_json(operation_prompt, parse_operation_fragments,
                               "Return only valid JSON operation fragments.")
            operations[component.name] = grouped.get(component.name, grouped.get("", []))
            if component.type in {"core", "orchestrator"} and not component.domain:
                states[component.name] = ask_model(
                    f"List bounded integer/boolean state variables for {component.name}; every integer needs bound and initial. Requirement:\n{requirement}",
                    list[StateVariableFragment],
                    lambda raw: parse_fragment_list(raw, StateVariableFragment, "state"))
            if component.type != "core" or component.domain:
                transitions[component.name] = []
                continue
            declared = {item.name for item in states.get(component.name, [])}
            def parse_transitions(raw):
                items = normalize_transition_fragments(parse_fragment_list(raw, dict, "transition"))
                for item in items:
                    if isinstance(item.get("precondition"), str):
                        item["precondition"] = _dsl_expression(item["precondition"], declared)
                    for effect in item.get("effects", []):
                        if isinstance(effect.get("value"), str):
                            effect["value"] = _dsl_expression(effect["value"], declared)
                return [TransitionFragment.model_validate(item) for item in items]
            transitions[component.name] = ask_model(
                f"For {component.name}, return ONLY a JSON object with a transitions key whose value is a JSON list. Do not use the component name as a key. Each transition is parameterless and needs operation_name, precondition as an infix string (for example stock > 0), at least one effect, and a non-empty frame of field-name strings. Effects and frame MUST NOT be empty; omit getter/view operations that do not change state. Use ONLY the exact state fields declared for this component and fixed integer literals. Never invent variables such as quantity or amount, and never emit stock + quantity. Do not emit nested AST objects, timestamps, lists, or invented fields.",
                list[TransitionFragment],
                parse_transitions, transition_schema)
            for transition in transitions[component.name]:
                validate_transition(transition, declared)
        steps = ask_model("List ordered use-case steps with component, operation, and exact arguments for this requirement:\n" + requirement,
                    list[UseCaseStepFragment],
                    lambda raw: parse_fragment_list(raw, UseCaseStepFragment, "use-case"))
        unified = assemble_unified_architecture(components, operations, states, steps, transitions)
        tla, cfg = render_unified_architecture(unified)
        tlc = check_tla(tla, cfg, timeout=timeout)
        if tlc.get("status") != "VERIFIED":
            return {"status": "DESIGN_FAILED", "message": tlc.get("status"), "tlc": tlc}
        return {"status": "VERIFIED", "architecture": unified.model_dump(),
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
