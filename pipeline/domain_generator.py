# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Interactive NL -> validated domain specification -> deterministic YAML.

The model asks questions and proposes JSON.  Pydantic owns acceptance and PyYAML owns
serialization; model text is never treated as YAML or executable plugin code.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable

import yaml
from pydantic import ValidationError

from .elicit import _extract_json, normalize_questions
from .llm import LLMError
from .scaffold_domain import DomainSpec
from .domain_v2 import DomainSpecV2


DOMAIN_QUESTIONS_SYSTEM = """You are eliciting a bounded domain model for deterministic TLA+ plugin scaffolding.
Do not write YAML, code, TLA+, or a domain specification yet. Ask only questions needed
to determine: state variables and small integer bounds, atomic operations, guards,
effects, permitted frames, and named safety invariants.

CRITICAL FORMAL-METHODS RULE — STATE OBSERVABILITY:
If physical movement, network transit, asynchronous work, or another duration-bearing process
appears in the idea, do not allow it to collapse into one atomic before/after operation. Ask:
1. whether an in-progress/transit state must be observable;
2. which bounded state variable represents idle and in-progress modes;
3. which distinct operations enter and leave that state.
Explain that a safety property about the in-progress interval is vacuous if no reachable state
records that interval. Require separate start/begin and arrive/stop/complete transitions when
the user wants a non-vacuous invariant during transit.

Return JSON only:
{"questions":[{"id":"q1","category":"state|bounds|operation|guard|effect|frame|invariant|abstraction|other","question":"...","required":true}]}

Use at most 8 concise questions. Do not ask for facts already present in the idea.
"""

DOMAIN_SPEC_SYSTEM = """Propose a bounded domain-plugin declaration from the idea and authoritative human answers.
Return JSON only, with exactly this schema:
{"domain_name":"PascalCase","module_name":"snake_case","state_variables":[{"name":"snake_case","type":"int|dict","bound":[0,4]}],"operations":[{"name":"identifier","guards":["snake_case"],"effect":"snake_case","frame":["declared_state_name"],"ast_pattern":"documented JML post-state pattern"}],"tlc_invariants":["PascalCaseName"]}

Rules: use small finite bounds (upper bound at most 100); every operation has a nonempty
frame containing only declared state variables; identifiers are unique; do not invent
answers that conflict with the human; do not emit YAML, Markdown, TLA+, or Python.

The name, guards, effect, frame, and invariant fields contain IDENTIFIERS, never expressions.
For example use guards ["east_west_is_red"] and effect "set_north_south_green"; never put
"ew_light = 0", "ns_light = 2", comparison operators, assignments, spaces, or formulas in
those fields. Only ast_pattern may contain a JML expression such as "ns_light == 2".
The ast_pattern is documentation for a human-reviewed AST adapter, never executable text.

STATE OBSERVABILITY IS MANDATORY: duration-bearing behavior must have an explicitly bounded
in-progress state plus separate operations that enter and exit it. For elevators, trains,
network transit, robotic motion, and asynchronous jobs, never serialize the entire process as
one atomic source-to-destination operation when an invariant refers to the process while active.
Start operations must frame and set the in-progress state; arrival/stop/complete operations must
frame and clear it. Include guards that make the relevant safety condition non-vacuous.
"""

DOMAIN_SPEC_REPAIR_SYSTEM = """Repair one rejected bounded domain-plugin JSON declaration.
Return JSON only and preserve the domain meaning and authoritative human answers.
Every name, guard, effect, frame, and invariant must be a safe semantic identifier, not an
expression. Convert predicate text to descriptive IDs: "ew_light = 0" becomes
"east_west_is_red"; convert assignments to effect IDs: "ns_light = 2" becomes
"set_north_south_green". Put any documented JML expression only in ast_pattern.
Do not remove operations or invariants merely to satisfy validation. Do not emit Markdown.
If validation reports an unobservable duration state, add separate start/begin and
arrive/stop/complete operations; do not delete the moving/transit state or its invariant.
The `tlc_invariants` array contains PascalCase OPERATOR NAMES only, for example
`["TypeOK", "DoorsClosedWhileMoving", "FloorWithinBounds"]`. Never put formulas,
negation, comparison operators, spaces, or explanatory prose in `tlc_invariants`.
Guards must encode concrete semantic predicates (`door_is_closed`, `moving_is_stopped`,
`below_top_floor`), never bare field names (`door_state`). Effects must identify a concrete
transition (`set_moving_up`, `open_door`), never generic setters (`set_moving_state`).
Never emit `+/-`, primed pseudo-assignments, or conditional prose in `ast_pattern`; split
direction-dependent completion into exact operations such as `arriveUp` and `arriveDown`.
Every observable binary door state requires both open and close operations.
"""

DOMAIN_SPEC_V2_SYSTEM = """Propose an unreviewed bounded V2 domain candidate from the domain idea
and authoritative human answers. Return JSON only. Use the supplied JSON Schema exactly.
Expressions are typed trees, never strings: fields use {"kind":"field","name":"state_name"};
constants use integer or boolean nodes; operators use binary nodes such as eq, lt, add, and implies.
Every state variable has an initial value. Every effect target appears in its operation frame, and
every framed field is assigned exactly once using a value evaluated from the pre-state. Use
false_and_stutter only for Boolean operations; use unavailable for strict-guarded void actions.
Duration-bearing behavior has separate start and finish operations plus an observable in-progress
state. Invariants are typed expressions. review_status MUST be unreviewed. Do not emit YAML,
Markdown, TLA+, Python, reviewed status, or unsupported schema fields.
TypeOK is generated by the renderer and MUST NOT appear in tlc_invariants. All identifiers must be
safe language identifiers and every expression field must name a declared state variable.
"""

DOMAIN_SPEC_V2_REPAIR_SYSTEM = """Repair a rejected V2 domain candidate using the supplied JSON
Schema, validation diagnostics, and authoritative requirements. Return JSON only. Preserve the
domain meaning. Never replace typed expression objects with strings, never remove a safety
invariant to make validation pass, and never set review_status to reviewed. Ensure effect targets
and frames match exactly and all referenced fields are declared.
"""

_DOMAIN_CATEGORIES = {"state", "bounds", "operation", "guard", "effect", "frame",
                      "invariant", "abstraction", "other"}


def elicit_domain_questions(idea: str, chat_fn: Callable, model: str | None = None):
    if not idea.strip():
        raise ValueError("domain idea is required")
    content, used, usage = chat_fn(
        [{"role": "system", "content": DOMAIN_QUESTIONS_SYSTEM},
         {"role": "user", "content": "Domain idea:\n" + idea.strip()}], model, 0.0)
    questions = normalize_questions(_extract_json(content), _DOMAIN_CATEGORIES)
    return questions, used, usage


def compile_domain_spec(idea: str, questions: list[dict[str, Any]],
                        answers: list[dict[str, Any]], chat_fn: Callable,
                        model: str | None = None) -> tuple[DomainSpec, str, str, dict]:
    normalized = normalize_questions(questions, _DOMAIN_CATEGORIES)
    answer_map = {str(item.get("id", "")): str(item.get("answer", "")).strip()
                  for item in answers if isinstance(item, dict)}
    missing = [item["question"] for item in normalized
               if item["required"] and not answer_map.get(item["id"])]
    if missing:
        raise ValueError("required domain clarification unanswered: " + "; ".join(missing))
    _reject_conflicting_elevator_bounds(idea, normalized, answer_map)
    context = ["Domain idea:", idea.strip(), "", "Human clarifications (authoritative):"]
    for item in normalized:
        if answer_map.get(item["id"]):
            context.extend([f"- Q: {item['question']}", f"  A: {answer_map[item['id']]}"])
    content, used, usage = chat_fn(
        [{"role": "system", "content": DOMAIN_SPEC_SYSTEM},
         {"role": "user", "content": "\n".join(context)}], model, 0.0)
    value = _extract_json(content)
    repair_attempts = 0
    while True:
        try:
            spec = DomainSpec.model_validate(value)
            break
        except ValidationError as validation_error:
            if repair_attempts >= 2:
                compact = "; ".join(
                    f"{'.'.join(map(str, item['loc']))}: {item['msg']}"
                    for item in validation_error.errors(include_url=False)[:8])
                raise LLMError("INVALID_DOMAIN_SPEC",
                               f"schema-aware repair was rejected: {compact}") from validation_error
            diagnostics = [{"path": ".".join(map(str, item["loc"])),
                            "message": item["msg"], "rejected_value": item.get("input")}
                           for item in validation_error.errors(include_url=False)]
            repair_context = {
                "rejected_spec": value,
                "validation_errors": diagnostics,
                "authoritative_requirement": "\n".join(context),
                "repair_attempt": repair_attempts + 1,
            }
            repaired_content, repaired_model, repaired_usage = chat_fn(
                [{"role": "system", "content": DOMAIN_SPEC_REPAIR_SYSTEM},
                 {"role": "user", "content": json.dumps(
                     repair_context, ensure_ascii=False, default=str)}], model, 0.0)
            value = _extract_json(repaired_content)
            used, usage = repaired_model, repaired_usage
            repair_attempts += 1
    if repair_attempts:
        usage = {**usage, "domain_spec_repair_attempts": repair_attempts}
    yaml_text = yaml.safe_dump(spec.model_dump(mode="json"), sort_keys=False,
                               allow_unicode=True, default_flow_style=False)
    return spec, yaml_text, used, usage


def compile_domain_spec_v2(idea: str, questions: list[dict[str, Any]],
                           answers: list[dict[str, Any]], chat_fn: Callable,
                           model: str | None = None) -> tuple[DomainSpecV2, str, str, dict]:
    """Compile authoritative clarifications into an unreviewed typed V2 candidate."""
    normalized = normalize_questions(questions, _DOMAIN_CATEGORIES)
    answer_map = {str(item.get("id", "")): str(item.get("answer", "")).strip()
                  for item in answers if isinstance(item, dict)}
    missing = [item["question"] for item in normalized
               if item["required"] and not answer_map.get(item["id"])]
    if missing:
        raise ValueError("required domain clarification unanswered: " + "; ".join(missing))
    _reject_conflicting_elevator_bounds(idea, normalized, answer_map)
    context = ["Domain idea:", idea.strip(), "", "Human clarifications (authoritative):"]
    for item in normalized:
        if answer_map.get(item["id"]):
            context.extend([f"- Q: {item['question']}", f"  A: {answer_map[item['id']]}"])
    schema = DomainSpecV2.model_json_schema()
    request = "\n".join(context) + "\n\nRequired JSON Schema:\n" + json.dumps(schema)
    content, used, usage = chat_fn(
        [{"role": "system", "content": DOMAIN_SPEC_V2_SYSTEM},
         {"role": "user", "content": request}], model, 0.0)
    value = _extract_json(content)
    repair_attempts = 0
    while True:
        try:
            spec = DomainSpecV2.model_validate(value)
            if spec.review_status != "unreviewed":
                raise ValueError("generated V2 candidates cannot assign reviewed status")
            break
        except (ValidationError, ValueError) as validation_error:
            if repair_attempts >= 2:
                if isinstance(validation_error, ValidationError):
                    compact = "; ".join(
                        f"{'.'.join(map(str, item['loc']))}: {item['msg']}"
                        for item in validation_error.errors(include_url=False)[:8])
                else:
                    compact = str(validation_error)
                raise LLMError("INVALID_DOMAIN_SPEC_V2",
                               f"schema-aware repair was rejected: {compact}") from validation_error
            diagnostics = (validation_error.errors(include_url=False)
                           if isinstance(validation_error, ValidationError)
                           else [{"path": "review_status", "message": str(validation_error)}])
            repair_context = {"rejected_spec": value, "validation_errors": diagnostics,
                              "authoritative_requirement": "\n".join(context),
                              "json_schema": schema, "repair_attempt": repair_attempts + 1}
            repaired, used, usage = chat_fn(
                [{"role": "system", "content": DOMAIN_SPEC_V2_REPAIR_SYSTEM},
                 {"role": "user", "content": json.dumps(
                     repair_context, ensure_ascii=False, default=str)}], model, 0.0)
            value = _extract_json(repaired)
            repair_attempts += 1
    if repair_attempts:
        usage = {**usage, "domain_spec_repair_attempts": repair_attempts}
    yaml_text = yaml.safe_dump(spec.model_dump(mode="json"), sort_keys=False,
                               allow_unicode=True, default_flow_style=False)
    return spec, yaml_text, used, usage


def _reject_conflicting_elevator_bounds(idea: str, questions: list[dict[str, Any]],
                                        answer_map: dict[str, str]) -> None:
    if "elevator" not in idea.lower():
        return
    ranges: set[tuple[int, int]] = set()
    for question in questions:
        text = (question["question"] + " " + answer_map.get(question["id"], "")).lower()
        if "floor" not in text:
            continue
        for lower, upper in re.findall(r"\b(\d+)\s*(?:\.\.|-|to)\s*(\d+)\b", text):
            ranges.add((int(lower), int(upper)))
        for lower, upper in re.findall(
                r"(\d+)\s*<=\s*current_floor\s*&&\s*current_floor\s*<=\s*(\d+)", text):
            ranges.add((int(lower), int(upper)))
    if len(ranges) > 1:
        rendered = ", ".join(f"{lower}..{upper}" for lower, upper in sorted(ranges))
        raise ValueError(
            "conflicting elevator floor bounds in authoritative clarifications: " + rendered +
            ". Correct the saved domain answers so exactly one inclusive range remains.")
