"""Code -> Math -> Natural Language documentation from unreviewed V2 extraction.

`document-code` runs the bottom-up extractor over one source file, rebuilds the
strict V2 candidate payload (state variables, guarded transitions, bounds,
invariants), and renders it as structured English Markdown. Structure and
sentences are deterministic; an optional provider pass contributes an overview
paragraph and semantic invariant prose. When the provider is unavailable the
deterministic rendering stands on its own. Documentation is never verification:
the verdict claim is UNREVIEWED_EXTRACTION_DOCUMENTATION and validation stays
NOT_RUN pending human review.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .codebase_analysis import (
    _infer_java_transitions,
    _polyglot_declarations,
    _register_candidate,
    build_v2_candidate_payload,
    extract_components_ts,
    infer_field_bounds,
)
from .domain_v2 import DomainSpecV2
from .llm import _chat_fn, _first_json_object, strip_fence

_COMPARISON_WORDS = {
    "lt": "is less than", "lte": "is at most", "gt": "is greater than",
    "gte": "is at least", "eq": "is equal to", "neq": "is not equal to",
}
_INFIX_SYMBOLS = {"lt": "<", "lte": "<=", "gt": ">", "gte": ">=", "eq": "==", "neq": "!=",
                  "add": "+", "sub": "-", "mul": "*", "div": "/"}
_FOOTER = ("*This documentation was auto-generated from a formal V2 extraction model. "
           "Review Status: UNREVIEWED.*")


def _term(node: Any) -> str:
    """Render a value/term subexpression in readable infix form."""
    kind = node.get("kind")
    if kind == "field":
        return str(node.get("name"))
    if kind == "integer":
        return str(node.get("value"))
    if kind == "boolean":
        return "true" if node.get("value") else "false"
    if kind in _INFIX_SYMBOLS:
        return f"{_term(node['left'])} {_INFIX_SYMBOLS[kind]} {_term(node['right'])}"
    if kind == "not":
        return f"not ({_term(node['expression'])})"
    raise ValueError(f"unsupported expression kind: {kind!r}")


def render_predicate(node: Any) -> str:
    """Render a boolean expression tree as an English predicate."""
    kind = node.get("kind")
    if kind in _COMPARISON_WORDS:
        return f"{_term(node['left'])} {_COMPARISON_WORDS[kind]} {_term(node['right'])}"
    if kind in ("and", "or"):
        return f"{render_predicate(node['left'])} {kind} {render_predicate(node['right'])}"
    if kind == "implies":
        return f"if {render_predicate(node['left'])} then {render_predicate(node['right'])}"
    if kind == "not":
        return f"not ({render_predicate(node['expression'])})"
    return _term(node)


def render_infix(node: Any) -> str:
    """Render a boolean expression tree with symbolic comparisons and English connectives."""
    kind = node.get("kind")
    if kind in ("and", "or"):
        return f"{render_infix(node['left'])} {kind} {render_infix(node['right'])}"
    if kind == "implies":
        return f"{render_infix(node['left'])} implies {render_infix(node['right'])}"
    return _term(node)


def _effect_sentence(effect: dict) -> str:
    target, value = effect.get("target"), effect.get("value", {})
    kind = value.get("kind")
    if (kind in ("add", "sub") and isinstance(value.get("left"), dict)
            and value["left"].get("kind") == "field" and value["left"].get("name") == target
            and isinstance(value.get("right"), dict)
            and value["right"].get("kind") == "integer"):
        verb = "increases" if kind == "add" else "decreases"
        return f"{verb} the {target} by {value['right'].get('value')}"
    return f"sets {target} to {render_infix(value)}"


def _operation_sentences(operation: dict) -> str:
    guards = [render_predicate(guard.get("expression", {}))
              for guard in operation.get("guards", []) if guard.get("expression")]
    effects = [_effect_sentence(effect) for effect in operation.get("effects", [])]
    name = operation.get("name", "operation")
    if guards:
        sentence = f"The '{name}' operation can only be called if {' and '.join(guards)}."
    else:
        sentence = f"The '{name}' operation can be called at any time."
    if effects:
        sentence += f" When called, it {', '.join(effects)}."
    else:
        sentence += " When called, it leaves the documented state unchanged."
    return sentence


def render_nl_document(payload: dict, *, source_path: Path, source_sha256: str,
                       language: str, extractor: str,
                       narrative: dict | None = None) -> str:
    """Render the deterministic Markdown document for one extracted V2 payload."""
    narrative = narrative or {}
    variables = payload.get("state_variables", [])
    operations = payload.get("operations", [])
    invariants = payload.get("tlc_invariants", [])
    names = ", ".join(var["name"] for var in variables)
    overview = narrative.get("overview") or (
        f"The {payload.get('module_name', 'system')} module tracks "
        f"{len(variables)} state variable(s): {names}.")
    prose = narrative.get("invariant_prose") if isinstance(
        narrative.get("invariant_prose"), dict) else {}

    lines = [f"# {payload.get('domain_name', 'Extracted System')}", "", overview, "",
             "## State Variables", ""]
    for var in variables:
        if var.get("kind") == "bool":
            initial = "true" if var.get("initial") else "false"
            lines.append(f"The system tracks a boolean '{var['name']}' value, "
                         f"initially {initial}.")
        else:
            low, high = var.get("bound", (0, 0))
            lines.append(f"The system tracks a '{var['name']}' value, starting at "
                         f"{var.get('initial', 0)}, which must always remain "
                         f"between {low} and {high}.")
    lines += ["", "## Operations", ""]
    if operations:
        lines.extend(_operation_sentences(operation) for operation in operations)
    else:
        lines.append("No operations were inferred (transition inference currently "
                     "supports Java guarded scalar assignments only).")
    lines += ["", "## Safety Invariants", ""]
    for invariant in invariants:
        lines.append(f"Safety Rule: {render_infix(invariant.get('expression', {}))} "
                     "must always hold.")
        if invariant.get("id") in prose:
            lines.append(f"{prose[invariant['id']]}")
    if not invariants:
        lines.append("No invariants were recorded for this extraction.")
    lines += ["", "---", _FOOTER, "",
              f"- Source: `{source_path}` (sha256 `{source_sha256}`)",
              f"- Extractor: {extractor} ({language})",
              "- Documentation is not verification: no TLC run, no OpenJML ESC run, "
              "and no human review has occurred.",
              ""]
    return "\n".join(lines)


def generate_narrative(payload: dict, provider: str, model: str | None) -> dict | None:
    """Ask the provider for overview/invariant prose; None on any failure."""
    messages = [
        {"role": "system",
         "content": "You are a precise technical writer for formal specifications. "
                    "Reply with a single JSON object and nothing else."},
        {"role": "user",
         "content": "Write natural-language documentation prose for this formal V2 "
                    "domain model. Reply with exactly "
                    '{"overview": "...", "invariant_prose": {"<invariant-id>": "..."}} '
                    "where overview is one paragraph and each invariant_prose entry "
                    "explains one safety invariant semantically.\n\n"
                    + json.dumps(payload, indent=2)},
    ]
    try:
        raw, _, _ = _chat_fn(provider)(messages, model, 0.2)
        data = _first_json_object(strip_fence(raw))
    except Exception:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("overview"), str):
        return None
    if not isinstance(data.get("invariant_prose"), dict):
        data["invariant_prose"] = {}
    return data


def _infer_initials(text: str, class_name: str, fields: list[tuple[str, str]]) -> dict[str, int | bool]:
    """Infer initial values from field declarations and the constructor only.

    Method-body assignments are transitions, not initial state.
    """
    initials: dict[str, int | bool] = {}
    constructor = re.search(rf"public\s+{re.escape(class_name)}\s*\([^)]*\)\s*\{{(.*?)\}}",
                            text, re.DOTALL)
    constructor_body = constructor.group(1) if constructor else ""
    for name, field_type in fields:
        match = re.search(
            rf"\b(?:private|protected|public)\s+\w+\s+{re.escape(name)}\s*=\s*"
            rf"(true|false|-?\d+)\s*;", text)
        if match is None and constructor_body:
            match = re.search(
                rf"\b(?:this\.)?{re.escape(name)}\s*=\s*(true|false|-?\d+)\s*;",
                constructor_body)
        if match:
            value = match.group(1)
            initials[name] = value == "true" if field_type == "boolean" else int(value)
    return initials


def _schema_check(payload: dict) -> tuple[bool, str]:
    try:
        DomainSpecV2.model_validate(payload)
    except Exception as exc:  # validation failures are evidence, not crashes
        return False, str(exc)[:200]
    return True, "DomainSpecV2 validation passed"


def _fail(code: str, message: str, target: str) -> dict:
    return {"status": "FAIL", "claim": "NO_PROOF", "code": code,
            "message": message, "target": target}


def document_code(source: str | Path, out_file: str | Path, *,
                  project_root: str | Path = ".", provider: str = "ollama",
                  model: str | None = None, no_llm: bool = False) -> dict[str, Any]:
    """Document one source file as natural-language requirements (Code -> Math -> NL)."""
    source_path, destination = Path(source), Path(out_file)
    if not source_path.is_file():
        return _fail("input_unavailable", str(source_path), str(source_path))
    try:
        text = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return _fail("input_unavailable", str(exc), str(source_path))
    declarations = extract_components_ts(source_path)
    extractor = "tree-sitter"
    if declarations is None:
        declarations = _polyglot_declarations(source_path, text)
        extractor = "deterministic-fallback"
    declaration = next((item for item in declarations
                        if not item.get("interface") and item.get("fields")), None)
    if declaration is None:
        return _fail("UNPARSEABLE_SOURCE",
                     "no concrete class or struct with scalar fields was found",
                     str(source_path))
    fields = declaration["fields"]
    language = "java" if source_path.suffix.lower() == ".java" else source_path.suffix[1:]
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    bounds = infer_field_bounds(text, fields)
    unbounded = sorted(name for name, bound in bounds.items() if bound is None)
    if unbounded:
        return _fail("UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW",
                     f"cannot safely document unbounded state: {', '.join(unbounded)}",
                     str(source_path))
    initials = _infer_initials(text, declaration["name"], fields)
    transitions = _infer_java_transitions(text, fields) if language == "java" else []
    payload = build_v2_candidate_payload(declaration["name"], fields, transitions,
                                         bounds=bounds, initials=initials)
    narrative, narrative_source = None, "disabled"
    if not no_llm:
        narrative = generate_narrative(payload, provider, model)
        narrative_source = "provider" if narrative else "deterministic_fallback"
    document = render_nl_document(payload, source_path=source_path, source_sha256=digest,
                                  language=language, extractor=extractor,
                                  narrative=narrative)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(document, encoding="utf-8")
    candidate = _register_candidate(Path(project_root), declaration["name"], fields,
                                    transitions, bounds=bounds, initials=initials)
    schema_valid, schema_reason = _schema_check(payload)
    return {"status": "DOCUMENTED", "claim": "UNREVIEWED_EXTRACTION_DOCUMENTATION",
            "document": str(destination), "candidate": str(candidate),
            "source": str(source_path), "source_sha256": digest,
            "narrative_source": narrative_source,
            "schema_valid": schema_valid, "schema_reason": schema_reason,
            "operation_inference": ("guarded_scalar_assignments" if language == "java"
                                    else "java_only"),
            "validation": {"status": "NOT_RUN", "reason": "human review required"},
            "documented_behavior_proved": False}
