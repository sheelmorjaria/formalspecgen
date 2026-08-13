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
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .elicit import _extract_json, normalize_questions, request_questions
from .llm import LLMError
from .jml_ast import (BinaryExpr as JmlBinaryExpr, BooleanLiteral, FieldAccess,
                      IntegerLiteral, UnaryExpr, parse_jml_expression)
from .scaffold_domain import DomainSpec
from .domain_v2 import DomainSpecV2, Invariant, Operation, StateVariable


class _InvariantPlanV2(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    clause_names: list[str] = Field(min_length=1)


class _OperationPlanV2(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    frame: list[str] = Field(min_length=1)
    guard_expressions: list[str]
    effect_values: dict[str, str]


class _InvariantClauseDsl(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    expression: str


class _GuardDsl(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    expression: str


class _EffectDsl(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    target: str
    value: str


class _OperationDsl(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    return_type: str
    failure_semantics: str
    guards: list[_GuardDsl]
    effects: list[_EffectDsl]
    frame: list[str]
    exception_type: str | None = None
    exception_trigger: str | None = None


class _DomainHeaderV2(BaseModel):
    """Small structured-output stage; final DomainSpecV2 remains the trust boundary."""
    model_config = ConfigDict(extra="forbid")
    schema_version: int
    review_status: str
    domain_name: str
    module_name: str
    actors: int
    state_variables: list[StateVariable] = Field(min_length=1)
    invariant_plans: list[_InvariantPlanV2] = Field(min_length=1)
    operation_plans: list[_OperationPlanV2] = Field(min_length=1)


def _merge_usage(total: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    merged = dict(total)
    for key, value in current.items():
        if isinstance(value, int) and isinstance(merged.get(key, 0), int):
            merged[key] = merged.get(key, 0) + value
        else:
            merged[key] = value
    return merged


def _dsl_expression(source: str, fields: set[str]) -> dict[str, Any]:
    """Parse compact model output and lower the accepted subset into strict V2 nodes."""
    def lower(node: Any) -> dict[str, Any]:
        if isinstance(node, FieldAccess) and node.receiver == "this":
            return {"kind": "field", "name": node.field}
        if isinstance(node, IntegerLiteral):
            return {"kind": "integer", "value": node.value}
        if isinstance(node, BooleanLiteral):
            return {"kind": "boolean", "value": node.value}
        if isinstance(node, UnaryExpr) and node.kind == "not":
            return {"kind": "not", "expression": lower(node.operand)}
        if isinstance(node, JmlBinaryExpr) and node.kind in {
                "eq", "neq", "lt", "lte", "gt", "gte", "add", "sub",
                "implies", "and", "or"}:
            return {"kind": node.kind, "left": lower(node.left), "right": lower(node.right)}
        raise ValueError(f"unsupported V2 expression construct: {node.kind}")
    return lower(parse_jml_expression(source, fields=fields))


def _operation_from_dsl(operation_dsl: _OperationDsl, fields: set[str]) -> Operation:
    value = operation_dsl.model_dump(mode="json")
    if (value["failure_semantics"] in {"none", "skip"} and
            value["return_type"] == "void" and value["exception_type"] is None and
            value["exception_trigger"] is None):
        value["failure_semantics"] = "unavailable"
    value["guards"] = [
        {"id": (guard.id if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", guard.id)
                else f"guard_{index + 1}"),
         "expression": _dsl_expression(guard.expression, fields)}
        for index, guard in enumerate(operation_dsl.guards)]
    value["effects"] = [
        {"id": (effect.id if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", effect.id)
                else f"effect_{index + 1}"), "target": effect.target,
         "value": _dsl_expression(effect.value, fields)}
        for index, effect in enumerate(operation_dsl.effects)]
    if operation_dsl.exception_trigger is not None:
        value["exception_trigger"] = _dsl_expression(
            operation_dsl.exception_trigger, fields)
    return Operation.model_validate(value)


def _compile_domain_spec_v2_staged(request: str, context: list[str], chat_fn: Callable,
                                   model: str | None,
                                   progress: Callable[[str], None] | None = None
                                   ) -> tuple[Any, str, dict[str, Any]]:
    """Generate bounded fragments with exact schemas, then assemble without inventing values."""
    report = progress or (lambda _message: None)
    structured_for = getattr(chat_fn, "structured_for")
    header_chat = structured_for(_DomainHeaderV2.model_json_schema(), "v2_domain_header")
    report("[1/?] Generating V2 manifest via Ollama…")
    header_request = request + (
        "\n\nSTAGED OUTPUT: Return metadata, state_variables, the exact ordered "
        "invariant_plans (each top-level invariant id plus ordered atomic clause_names), and "
        "the exact ordered operation_plans. Each operation plan contains its name, exact write "
        "frame, every guard_expressions item as compact infix JML, and effect_values mapping "
        "each framed target to compact infix JML. Use syntax like `pc0 == 0` and `pc0 + 1`; "
        "never use constructors like eq(...), field(...), or integer(...). Use one clause name "
        "per indivisible semantic safety statement; do not emit invariant expressions or "
        "operation bodies. A scalar owner field already represents exactly one owner: do not "
        "invent a cross-field invariant for 'single owner by construction'.")
    header = None
    usage: dict[str, Any] = {}
    for attempt in range(3):
        header_raw, used, current_usage = header_chat(
            [{"role": "system", "content": DOMAIN_SPEC_V2_SYSTEM},
             {"role": "user", "content": header_request}], model, 0.0)
        usage = _merge_usage(usage, current_usage)
        try:
            candidate_header = _DomainHeaderV2.model_validate(_extract_json(header_raw))
            fields = set(variable.name for variable in candidate_header.state_variables)
            for plan in candidate_header.operation_plans:
                for expression in plan.guard_expressions:
                    _dsl_expression(expression, fields)
                for expression in plan.effect_values.values():
                    _dsl_expression(expression, fields)
            header = candidate_header
            break
        except (ValidationError, ValueError, LLMError) as exc:
            if attempt >= 2:
                raise ValueError(f"staged V2 manifest failed local repair: {exc}") from exc
            report(f"[1/?] Repairing V2 manifest: {exc}")
            header_request += (
                "\n\nREPAIR DIAGNOSTIC: " + str(exc) +
                "\nReturn the complete manifest again. All guard/effect strings must use "
                "compact infix JML syntax only.")
    assert header is not None
    if (header.schema_version != 2 or header.review_status != "unreviewed" or
            len([plan.name for plan in header.operation_plans]) !=
            len(set(plan.name for plan in header.operation_plans)) or
            len([plan.id for plan in header.invariant_plans]) !=
            len(set(plan.id for plan in header.invariant_plans)) or
            any(len(plan.clause_names) != len(set(plan.clause_names))
                for plan in header.invariant_plans)):
        raise ValueError(
            "staged V2 header has invalid version, review status, or fragment names")
    clause_count = sum(len(plan.clause_names) for plan in header.invariant_plans)
    total_stages = 2 + clause_count + len(header.operation_plans)
    report(f"[1/{total_stages}] Manifest complete: {len(header.invariant_plans)} invariant(s) "
           f"across {clause_count} atomic clause(s), "
           f"{len(header.operation_plans)} operation(s).")
    invariants: list[dict[str, Any]] = []
    invariant_chat = structured_for(
        _InvariantClauseDsl.model_json_schema(), "v2_domain_invariant_clause")
    header_context = header.model_dump(
        mode="json", exclude={"operation_plans", "invariant_plans"})
    total_usage = usage
    completed_clauses = 0
    for invariant_index, plan in enumerate(header.invariant_plans):
        expressions: list[dict[str, Any]] = []
        for clause_index, clause_name in enumerate(plan.clause_names):
            stage = 2 + completed_clauses
            report(f"[{stage}/{total_stages}] Generating invariant clause "
                   f"{plan.id}.{clause_name}…")
            invariant_request = {
                "authoritative_requirement": "\n".join(context),
                "validated_header": header_context,
                "top_level_invariant_id": plan.id,
                "required_clause_name": clause_name,
                "instruction": (
                    "Return exactly one compact invariant clause. Its id must equal "
                    "required_clause_name. expression is a parenthesized JML-style string using "
                    "only declared fields, integer/boolean literals, !, ==, !=, <, <=, >, >=, "
                    "+, -, &&, ||, and ==>. Do not combine sibling clauses."),
            }
            raw, used, fragment_usage = invariant_chat(
                [{"role": "system", "content": DOMAIN_SPEC_V2_REPAIR_SYSTEM},
                 {"role": "user", "content": json.dumps(
                     invariant_request, ensure_ascii=False)}], model, 0.0)
            clause = _InvariantClauseDsl.model_validate(_extract_json(raw))
            expressions.append(_dsl_expression(clause.expression, set(
                variable.name for variable in header.state_variables)))
            total_usage = _merge_usage(total_usage, fragment_usage)
            report(f"[{stage}/{total_stages}] Invariant clause "
                   f"{plan.id}.{clause_name} complete.")
            completed_clauses += 1
        expression = expressions[0]
        for sibling in expressions[1:]:
            expression = {"kind": "and", "left": expression, "right": sibling}
        invariants.append({"id": plan.id, "expression": expression})
    operations: list[dict[str, Any]] = []
    operation_chat = structured_for(_OperationDsl.model_json_schema(), "v2_domain_operation")
    declared_fields = set(variable.name for variable in header.state_variables)
    for index, operation_plan in enumerate(header.operation_plans):
        operation_name = operation_plan.name
        if (len(operation_plan.frame) != len(set(operation_plan.frame)) or
                not set(operation_plan.frame).issubset(declared_fields) or
                set(operation_plan.effect_values) != set(operation_plan.frame)):
            raise ValueError(f"staged operation plan {operation_name!r} has invalid frame")
        stage = 2 + clause_count + index
        report(f"[{stage}/{total_stages}] Generating operation {operation_name}…")
        operation_request = {
            "authoritative_requirement": "\n".join(context),
            "validated_header": header_context,
            "required_operation_name": operation_name,
            "required_exact_frame": operation_plan.frame,
            "required_exact_guards": operation_plan.guard_expressions,
            "required_exact_effect_values": operation_plan.effect_values,
            "instruction": (
                "Return exactly one compact V2 operation. Guard expression and effect value "
                "fields are parenthesized JML-style strings using only declared fields, "
                "integer/boolean literals, !, ==, !=, <, <=, >, >=, +, -, &&, ||, and ==>. "
                "Preserve every authoritative guard, effect, and frame. frame must equal the "
                "unique effect-target set. Do not return any other operation."),
        }
        operation = None
        fragment_usage: dict[str, Any] = {}
        for attempt in range(3):
            raw, used, current_usage = operation_chat(
                [{"role": "system", "content": DOMAIN_SPEC_V2_REPAIR_SYSTEM},
                 {"role": "user", "content": json.dumps(
                     operation_request, ensure_ascii=False)}], model, 0.0)
            fragment_usage = _merge_usage(fragment_usage, current_usage)
            try:
                operation_dsl = _OperationDsl.model_validate(_extract_json(raw))
                if operation_dsl.name != operation_name:
                    raise ValueError(
                        f"returned name {operation_dsl.name!r}, expected {operation_name!r}")
                operation = _operation_from_dsl(operation_dsl, declared_fields)
                if set(operation.frame) != set(operation_plan.frame):
                    raise ValueError(
                        f"frame {operation.frame!r} does not match required exact frame "
                        f"{operation_plan.frame!r}")
                planned_guards = [
                    _dsl_expression(expression, declared_fields)
                    for expression in operation_plan.guard_expressions]
                actual_guards = [guard.expression.model_dump(mode="json")
                                 for guard in operation.guards]
                if actual_guards != planned_guards:
                    raise ValueError("guards do not match required exact guard plan")
                planned_effects = {
                    target: _dsl_expression(expression, declared_fields)
                    for target, expression in operation_plan.effect_values.items()}
                actual_effects = {
                    effect.target: effect.value.model_dump(mode="json")
                    for effect in operation.effects}
                if actual_effects != planned_effects:
                    raise ValueError("effects do not match required exact effect plan")
                break
            except (ValidationError, ValueError, LLMError) as exc:
                if attempt >= 2:
                    raise ValueError(
                        f"staged operation {operation_name!r} failed local repair: {exc}") from exc
                report(f"[{stage}/{total_stages}] Repairing operation {operation_name}: {exc}")
                operation_request["rejected_fragment"] = raw
                operation_request["repair_diagnostic"] = str(exc)
                operation_request["instruction"] += (
                    " Repair only this operation and obey required_exact_frame exactly.")
        assert operation is not None
        operations.append(operation.model_dump(mode="json"))
        total_usage = _merge_usage(total_usage, fragment_usage)
        report(f"[{stage}/{total_stages}] Operation {operation_name} complete.")
    value = header.model_dump(mode="json", exclude={"operation_plans", "invariant_plans"})
    value["tlc_invariants"] = invariants
    value["operations"] = operations
    total_usage = {
        **total_usage,
        "domain_spec_staged_invariants": len(invariants),
        "domain_spec_staged_operations": len(operations),
    }
    report(f"[{total_stages}/{total_stages}] Fragments assembled; validating complete V2 model…")
    return value, used, total_usage


DOMAIN_QUESTIONS_SYSTEM = """You are eliciting a bounded domain model for deterministic TLA+ plugin scaffolding.
Do not write YAML, code, TLA+, or a domain specification yet. Ask only questions needed
to determine: state variables and small integer bounds, atomic operations, guards,
effects, permitted frames, and named safety invariants.

INITIALIZATION AND TRANSITION COVERAGE:
Ask for the initial value of every state variable. For every modeled state variable, including
environment-controlled physical state, determine which operation changes it. If an invariant
relates two variables (for example door state and lock state), elicit operations that can change
both sides of that relationship. Do not leave a variable permanently frozen unless the user
explicitly declares it immutable. Ask whether terminal deadlocks are intended; otherwise ensure
the operation set has an enabled transition from the initial state and every intended state.
When eliciting numeric bounds, explicitly require each bound to contain its stated initial value.
If an invariant claims conservation, check the stated effects algebraically and ask which missing
environment variable (for example user-held cash) completes the conserved quantity when necessary.

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
module_name is lower-case snake_case. Each effect target is the declared field-name STRING, not a
typed field-expression object; only effect values and guard/invariant expressions are typed trees.
Every mutable state variable described by the user, including environment state, must be targeted
by at least one operation. The initial state must enable an operation unless the user explicitly
requires an initially terminal system. Never omit environment operations merely because they do
not modify the controller's primary field.
Every integer initial value must lie within its declared bound. Do not shrink a bound below an
authoritative initial value. A conservation invariant must include every source and sink named by
the operation effects; do not claim account_balance + atm_cash is constant when both terms change
in the same direction unless another modeled term changes oppositely.
"""

DOMAIN_SPEC_V2_REPAIR_SYSTEM = """Repair a rejected V2 domain candidate using the supplied JSON
Schema, validation diagnostics, and authoritative requirements. Return JSON only. Preserve the
domain meaning. Never replace typed expression objects with strings, never remove a safety
invariant to make validation pass, and never set review_status to reviewed. Ensure effect targets
and frames match exactly and all referenced fields are declared. module_name must be a lower-case
snake_case identifier. An effect target must be a declared field-name JSON string, not a typed
field-expression object. The authoritative domain requirements at the end of the request override
the rejected candidate and every learned example. Never recycle an unrelated example domain.
Return the candidate object directly. Do not wrap it in a `candidate`, `domain`, `spec`, or
`result` property.

REQUIRED TOP-LEVEL SHAPE: emit every one of these keys exactly once: schema_version,
review_status, domain_name, module_name, actors, state_variables, operations, tlc_invariants.
`actors` is an integer count, not an array. Use `state_variables`, never `variables` or
`initial_state`; use `operations`, never `transitions`; and every tlc_invariants item uses `id`,
never `name`. A repair must return the complete candidate, including fields that were already
valid. Never return only the repaired fragment.

FRAME/EFFECT BIJECTION IS MANDATORY: for each operation, the frame array must equal the set of
effect target strings exactly, and every target occurs once. When authoritative answers say an
operation changes multiple fields, emit one effect for every such field and include exactly those
fields in frame. Never repair a mismatch by silently dropping an authoritative state update.
"""

DOMAIN_SPEC_V2_WIRE_FORMAT = r"""Use exactly these top-level keys:
schema_version, review_status, domain_name, module_name, actors, state_variables, operations,
tlc_invariants. Do not use aliases such as name, state, variables, transitions, or invariants.

Exact JSON shape (replace all angle-bracket placeholders):
{
  "schema_version": 2,
  "review_status": "unreviewed",
  "domain_name": "<PascalCase identifier>",
  "module_name": "<snake_case identifier>",
  "actors": 1,
  "state_variables": [{"kind":"int","name":"<field>","bound":[0,1],"initial":0}],
  "operations": [{
    "name":"<operation>",
    "return_type":"void",
    "failure_semantics":"unavailable",
    "guards":[{"id":"<guard_id>","expression":<EXPRESSION>}],
    "effects":[{"id":"<effect_id>","target":"<field string>","value":<EXPRESSION>}],
    "frame":["<field string>"],
    "exception_type":null,
    "exception_trigger":null
  }],
  "tlc_invariants":[{"id":"<InvariantName>","expression":<EXPRESSION>}]
}
Boolean state variables instead use {"kind":"bool","name":"<field>","initial":false} and
MUST NOT have bound. return_type is exactly "void" or "boolean". failure_semantics is exactly
"unavailable", "false_and_stutter", or "exception"; Boolean guarded APIs normally use
"false_and_stutter", while strict-guarded void actions use "unavailable".
For an operation that changes two fields, use this exact structural pattern (with domain-specific
names and expressions):
"effects":[
  {"id":"update_first","target":"first_field","value":<EXPRESSION>},
  {"id":"update_second","target":"second_field","value":<EXPRESSION>}
],
"frame":["first_field","second_field"]
The frame and effect-target set must be identical. Never combine two assignments into one effect.
EXPRESSION is a typed object: field={"kind":"field","name":"<field>"};
integer={"kind":"integer","value":0}; boolean={"kind":"boolean","value":false};
not={"kind":"not","expression":<EXPRESSION>};
binary={"kind":"eq","left":<EXPRESSION>,"right":<EXPRESSION>}, where kind is one of
eq, neq, lt, lte, gt, gte, add, sub, implies, and, or.
Return one JSON object only. Never copy angle brackets or descriptive placeholders."""

_DOMAIN_CATEGORIES = {"state", "bounds", "operation", "guard", "effect", "frame",
                      "invariant", "abstraction", "other"}


def elicit_domain_questions(idea: str, chat_fn: Callable, model: str | None = None):
    if not idea.strip():
        raise ValueError("domain idea is required")
    return request_questions(
        [{"role": "system", "content": DOMAIN_QUESTIONS_SYSTEM},
         {"role": "user", "content": "Domain idea:\n" + idea.strip()}],
        chat_fn, model, _DOMAIN_CATEGORIES)


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
    _reject_initial_values_outside_answered_bounds(normalized, answer_map)
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
                           model: str | None = None,
                           progress: Callable[[str], None] | None = None
                           ) -> tuple[DomainSpecV2, str, str, dict]:
    """Compile authoritative clarifications into an unreviewed typed V2 candidate."""
    normalized = normalize_questions(questions, _DOMAIN_CATEGORIES)
    answer_map = {str(item.get("id", "")): str(item.get("answer", "")).strip()
                  for item in answers if isinstance(item, dict)}
    missing = [item["question"] for item in normalized
               if item["required"] and not answer_map.get(item["id"])]
    if missing:
        raise ValueError("required domain clarification unanswered: " + "; ".join(missing))
    _reject_conflicting_elevator_bounds(idea, normalized, answer_map)
    _reject_initial_values_outside_answered_bounds(normalized, answer_map)
    context = ["Domain idea:", idea.strip(), "", "Human clarifications (authoritative):"]
    for item in normalized:
        if answer_map.get(item["id"]):
            context.extend([f"- Q: {item['question']}", f"  A: {answer_map[item['id']]}"])
    identity_tokens = sorted(_identity_tokens(idea))
    identity_rule = (
        "\n\nDOMAIN IDENTITY REQUIREMENT:\n"
        "The domain_name, module_name, state-variable names, or operation names MUST preserve "
        "at least one of these meaningful tokens from the authoritative idea: "
        + ", ".join(identity_tokens)
    )
    request = (
        "Required JSON Schema (compact exact wire format):\n" + DOMAIN_SPEC_V2_WIRE_FORMAT +
        "\n\nAUTHORITATIVE DOMAIN REQUIREMENTS (these override every example):\n" +
        "\n".join(context) + identity_rule +
        "\nDiscard any unrelated example-domain vocabulary. Return this domain only."
    )
    value: Any = None
    parse_error: LLMError | None = None
    normalizations: list[dict[str, str]] = []
    if hasattr(chat_fn, "structured_for"):
        try:
            value, used, usage = _compile_domain_spec_v2_staged(
                request, context, chat_fn, model, progress)
        except (ValidationError, ValueError, LLMError) as exc:
            raise LLMError("INVALID_DOMAIN_SPEC_V2_STAGE",
                           f"staged candidate generation failed closed: {exc}") from exc
    else:
        content, used, usage = chat_fn(
            [{"role": "system", "content": DOMAIN_SPEC_V2_SYSTEM},
             {"role": "user", "content": request}], model, 0.0)
        try:
            value, syntax_changes = _normalize_v2_syntax(_extract_json(content))
            normalizations.extend(syntax_changes)
        except LLMError as exc:
            parse_error = exc
    repair_attempts = 0
    while True:
        try:
            if parse_error is not None:
                raise parse_error
            spec = DomainSpecV2.model_validate(value)
            if spec.review_status != "unreviewed":
                raise ValueError("generated V2 candidates cannot assign reviewed status")
            spec, bound_changes = _complete_literal_bound_guards(spec)
            normalizations.extend(bound_changes)
            _validate_generated_domain_identity(idea, spec)
            break
        except (ValidationError, ValueError, LLMError) as validation_error:
            if repair_attempts >= 2:
                if isinstance(validation_error, ValidationError):
                    compact = "; ".join(
                        f"{'.'.join(map(str, item['loc']))}: {item['msg']}"
                        for item in validation_error.errors(include_url=False)[:8])
                    obligations = _frame_effect_repair_obligations(value)
                    if obligations:
                        compact += "; frame/effect details: " + json.dumps(
                            obligations, ensure_ascii=False, separators=(",", ":"))
                else:
                    compact = str(validation_error)
                raise LLMError("INVALID_DOMAIN_SPEC_V2",
                               f"schema-aware repair was rejected: {compact}") from validation_error
            diagnostics = (validation_error.errors(include_url=False)
                           if isinstance(validation_error, ValidationError)
                           else [{"path": ("response_json" if isinstance(validation_error, LLMError)
                                           else "domain_identity"),
                                  "message": str(validation_error)}])
            repair_context = {
                "required_wire_format": DOMAIN_SPEC_V2_WIRE_FORMAT,
                "rejected_spec": value,
                "validation_errors": diagnostics,
                "repair_attempt": repair_attempts + 1,
                "authoritative_requirement": "\n".join(context),
                "required_identity_tokens": identity_tokens,
                "identity_instruction": (
                    "Discard unrelated example-domain content, including its domain, module, "
                    "state, and operation identifiers. Rebuild the candidate from the "
                    "authoritative requirement and preserve its identity tokens."),
                "frame_effect_obligations": _frame_effect_repair_obligations(value),
            }
            rejected_value = value
            repaired, used, usage = chat_fn(
                [{"role": "system", "content": DOMAIN_SPEC_V2_REPAIR_SYSTEM},
                 {"role": "user", "content": json.dumps(
                     repair_context, ensure_ascii=False, default=str)}], model, 0.0)
            parse_error = None
            try:
                value, syntax_changes = _normalize_v2_syntax(_extract_json(repaired))
                normalizations.extend(syntax_changes)
                if isinstance(rejected_value, dict) and isinstance(value, dict):
                    required_keys = {
                        "schema_version", "review_status", "domain_name", "module_name",
                        "actors", "state_variables", "operations", "tlc_invariants",
                    }
                    if value and not required_keys.issubset(value):
                        supplied = set(value)
                        value = {**rejected_value, **value}
                        normalizations.append({
                            "path": "$", "from": "partial repair fragment",
                            "to": "overlay keys: " + ", ".join(sorted(supplied)),
                        })
            except LLMError as exc:
                value = None
                parse_error = exc
            repair_attempts += 1
    if repair_attempts:
        usage = {**usage, "domain_spec_repair_attempts": repair_attempts}
    if normalizations:
        usage = {**usage, "domain_spec_normalizations": normalizations}
    yaml_text = yaml.safe_dump(spec.model_dump(mode="json"), sort_keys=False,
                               allow_unicode=True, default_flow_style=False)
    return spec, yaml_text, used, usage


def _normalize_v2_syntax(value: Any) -> tuple[Any, list[dict[str, str]]]:
    """Repair representation-only LLM drift without inventing domain semantics."""
    if not isinstance(value, dict):
        return value, []
    import copy
    normalized = copy.deepcopy(value)
    changes: list[dict[str, str]] = []
    if (set(normalized) == {"candidate"} and
            isinstance(normalized.get("candidate"), dict)):
        normalized = normalized["candidate"]
        changes.append({"path": "$", "from": "candidate wrapper", "to": "candidate object"})
    aliases = {
        "name": "domain_name",
        "state": "state_variables",
        "variables": "state_variables",
        "transitions": "operations",
        "invariants": "tlc_invariants",
        "safety_invariants": "tlc_invariants",
    }
    for alias, canonical in aliases.items():
        if alias in normalized and canonical not in normalized:
            normalized[canonical] = normalized.pop(alias)
            changes.append({"path": alias, "from": alias, "to": canonical})
    domain_name = normalized.get("domain_name")
    if isinstance(domain_name, str) and not re.fullmatch(r"[A-Z][A-Za-z0-9]*", domain_name):
        words = re.findall(r"[A-Za-z0-9]+", re.sub(
            r"(?<=[a-z0-9])(?=[A-Z])", " ", domain_name))
        pascal = "".join(word[:1].upper() + word[1:] for word in words)
        if pascal and re.fullmatch(r"[A-Z][A-Za-z0-9]*", pascal):
            normalized["domain_name"] = pascal
            changes.append({"path": "domain_name", "from": domain_name, "to": pascal})
    state_variables = normalized.get("state_variables")
    if isinstance(state_variables, list):
        for index, variable in enumerate(state_variables):
            if not isinstance(variable, dict) or "kind" in variable:
                continue
            variable_type = variable.get("type")
            if variable_type in {"int", "bool"}:
                variable["kind"] = variable.pop("type")
                changes.append({
                    "path": f"state_variables.{index}.type",
                    "from": "type", "to": "kind",
                })
    actors = normalized.get("actors")
    if isinstance(actors, str) and actors.isdigit() and int(actors) >= 1:
        normalized["actors"] = int(actors)
        changes.append({"path": "actors", "from": "numeric string",
                        "to": actors})
    elif (isinstance(actors, dict) and set(actors) == {"count"} and
          isinstance(actors.get("count"), int) and actors["count"] >= 1):
        normalized["actors"] = actors["count"]
        changes.append({"path": "actors", "from": "actor count object",
                        "to": str(actors["count"])})
    elif (isinstance(actors, list) and actors and
            all(isinstance(actor, str) and actor for actor in actors) and
            len(actors) == len(set(actors))):
        normalized["actors"] = len(actors)
        changes.append({"path": "actors", "from": "actor identifier list",
                        "to": str(len(actors))})
    invariants = normalized.get("tlc_invariants")
    if isinstance(invariants, list):
        for index, invariant in enumerate(invariants):
            if (isinstance(invariant, dict) and "id" not in invariant and
                    isinstance(invariant.get("name"), str)):
                invariant["id"] = invariant.pop("name")
                changes.append({
                    "path": f"tlc_invariants.{index}.name", "from": "name", "to": "id",
                })
    initial_state = normalized.get("initial_state")
    if isinstance(initial_state, dict) and isinstance(state_variables, list):
        declared_initials = {
            variable.get("name"): variable.get("initial")
            for variable in state_variables
            if isinstance(variable, dict) and isinstance(variable.get("name"), str) and
            "initial" in variable
        }
        if (initial_state and set(initial_state).issubset(declared_initials) and
                all(declared_initials[name] == initial
                    for name, initial in initial_state.items())):
            normalized.pop("initial_state")
            changes.append({"path": "initial_state", "from": "duplicate initial map subset",
                            "to": "state_variables.*.initial"})
    if ("module_name" not in normalized and
            isinstance(normalized.get("domain_name"), str)):
        domain_name = normalized["domain_name"]
        module_name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", domain_name)
        module_name = re.sub(r"[^A-Za-z0-9_]+", "_", module_name).strip("_").lower()
        if module_name:
            normalized["module_name"] = module_name
            changes.append({"path": "module_name", "from": "omitted", "to": module_name})
    module_name = normalized.get("module_name")
    if isinstance(module_name, str):
        snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", module_name)
        snake = re.sub(r"[^A-Za-z0-9_]+", "_", snake).strip("_").lower()
        if snake and snake != module_name:
            normalized["module_name"] = snake
            changes.append({"path": "module_name", "from": module_name, "to": snake})
    operations = normalized.get("operations")
    if isinstance(operations, list):
        for operation_index, operation in enumerate(operations):
            if not isinstance(operation, dict) or not isinstance(operation.get("effects"), list):
                continue
            for effect_index, effect in enumerate(operation["effects"]):
                if not isinstance(effect, dict):
                    continue
                target = effect.get("target")
                if (isinstance(target, dict) and set(target) == {"kind", "name"} and
                        target.get("kind") == "field" and isinstance(target.get("name"), str)):
                    effect["target"] = target["name"]
                    changes.append({
                        "path": f"operations.{operation_index}.effects.{effect_index}.target",
                        "from": "typed field node", "to": target["name"],
                    })
    return normalized, changes


def _frame_effect_repair_obligations(value: Any) -> list[dict[str, Any]]:
    """Describe malformed frame/effect surfaces without changing their semantics."""
    if not isinstance(value, dict) or not isinstance(value.get("operations"), list):
        return []
    obligations = []
    for operation in value["operations"]:
        if not isinstance(operation, dict):
            continue
        frame = operation.get("frame")
        effects = operation.get("effects")
        if not isinstance(frame, list) or not isinstance(effects, list):
            continue
        targets = [effect.get("target") for effect in effects if isinstance(effect, dict)]
        if len(targets) != len(set(map(str, targets))) or set(map(str, targets)) != set(map(str, frame)):
            obligations.append({
                "operation": operation.get("name", "<unnamed>"),
                "current_frame": frame,
                "current_effect_targets": targets,
                "required_rule": (
                    "frame must equal the unique effect-target set; preserve every "
                    "authoritative multi-field update"),
            })
    return obligations


def _complete_literal_bound_guards(
        spec: DomainSpecV2) -> tuple[DomainSpecV2, list[dict[str, str]]]:
    """Add only guards mechanically required by bounded literal +/- effects."""
    value = spec.model_dump(mode="json")
    integer_bounds = {
        item.name: item.bound for item in spec.state_variables if item.kind == "int"}
    changes: list[dict[str, str]] = []
    for operation in value["operations"]:
        guard_trees = [guard["expression"] for guard in operation["guards"]]
        canonical_guard_trees = {_canonical_integer_guard_tree(tree) for tree in guard_trees}
        used_ids = {guard["id"] for guard in operation["guards"]} | {
            effect["id"] for effect in operation["effects"]}
        for effect in operation["effects"]:
            target, expression = effect["target"], effect["value"]
            if target not in integer_bounds or expression.get("kind") not in {"add", "sub"}:
                continue
            left, right = expression.get("left", {}), expression.get("right", {})
            if (left != {"kind": "field", "name": target} or
                    right.get("kind") != "integer" or right.get("value", 0) <= 0):
                continue
            amount = right["value"]
            lower, upper = integer_bounds[target]
            kind = "lte" if expression["kind"] == "add" else "gte"
            threshold = upper - amount if kind == "lte" else lower + amount
            required = {"kind": kind, "left": {"kind": "field", "name": target},
                        "right": {"kind": "integer", "value": threshold}}
            if _canonical_integer_guard_tree(required) in canonical_guard_trees:
                continue
            base_id = f"{target}_{'within_upper_bound' if kind == 'lte' else 'within_lower_bound'}"
            guard_id = base_id
            suffix = 2
            while guard_id in used_ids:
                guard_id = f"{base_id}_{suffix}"; suffix += 1
            operation["guards"].append({"id": guard_id, "expression": required})
            guard_trees.append(required)
            canonical_guard_trees.add(_canonical_integer_guard_tree(required))
            used_ids.add(guard_id)
            changes.append({
                "path": f"operations.{operation['name']}.guards.{guard_id}",
                "from": "omitted bound-preservation guard",
                "to": f"{target} {kind} {threshold}",
            })
    return DomainSpecV2.model_validate(value), changes


def _canonical_integer_guard_tree(tree: dict[str, Any]) -> str:
    """Return a stable key where integer < and > use inclusive equivalents."""
    value = json.loads(json.dumps(tree))
    if (isinstance(value, dict) and value.get("kind") in {"lt", "gt"} and
            isinstance(value.get("right"), dict) and
            value["right"].get("kind") == "integer"):
        if value["kind"] == "lt":
            value["kind"] = "lte"; value["right"]["value"] -= 1
        else:
            value["kind"] = "gte"; value["right"]["value"] += 1
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


_IDENTITY_STOP_WORDS = {
    "a", "an", "and", "as", "be", "but", "by", "can", "controller", "for", "from",
    "has", "have", "if", "in", "is", "it", "must", "of", "only", "or", "state",
    "system", "that", "the", "to", "with",
}


def _identity_tokens(text: str) -> set[str]:
    expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    return {token for token in re.findall(r"[a-z0-9]+", expanded.casefold())
            if len(token) >= 3 and token not in _IDENTITY_STOP_WORDS}


def _validate_generated_domain_identity(idea: str, spec: DomainSpecV2) -> None:
    """Reject structurally valid candidates unrelated to the authoritative idea."""
    idea_tokens = _identity_tokens(idea)
    identifiers = [spec.domain_name, spec.module_name]
    identifiers.extend(variable.name for variable in spec.state_variables)
    identifiers.extend(operation.name for operation in spec.operations)
    candidate_tokens = _identity_tokens(" ".join(identifiers))
    if idea_tokens and not idea_tokens.intersection(candidate_tokens):
        expected = ", ".join(sorted(idea_tokens)[:8])
        actual = ", ".join(sorted(candidate_tokens)[:8]) or "none"
        raise ValueError(
            "generated domain is not anchored to the authoritative idea; "
            f"expected vocabulary related to [{expected}], received [{actual}]")


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


def _reject_initial_values_outside_answered_bounds(
        questions: list[dict[str, Any]], answer_map: dict[str, str]) -> None:
    """Reject explicit initial/bound contradictions before asking the LLM to serialize them."""
    initial: dict[str, int] = {}
    bounds: dict[str, tuple[int, int]] = {}
    for question in questions:
        prompt = question["question"].casefold()
        answer = answer_map.get(question["id"], "")
        combined = f"{prompt} {answer.casefold()}"
        if "initial" in prompt:
            for name, value in re.findall(
                    r"\b([a-z_][a-z0-9_]*)\s*=\s*(-?\d+)\b", answer.casefold()):
                initial[name] = int(value)
        if question.get("category") == "bounds" or "bound" in combined:
            for name, upper in re.findall(
                    r"upper\s+bound\s+(?:for|of)\s+([a-z_][a-z0-9_]*)\s+"
                    r"(?:is|=)\s*(-?\d+)", combined):
                bounds[name] = (0, int(upper))
            for name, lower, upper in re.findall(
                    r"\b([a-z_][a-z0-9_]*)\s+(?:is\s+)?bounded\s+(?:to|in)\s+"
                    r"\[?(-?\d+)\s*(?:\.\.|,|to)\s*(-?\d+)\]?", combined):
                bounds[name] = (int(lower), int(upper))
    conflicts = [(name, value, bounds[name]) for name, value in initial.items()
                 if name in bounds and not bounds[name][0] <= value <= bounds[name][1]]
    if conflicts:
        details = "; ".join(
            f"{name} initial {value} is outside {lower}..{upper}"
            for name, value, (lower, upper) in conflicts)
        raise ValueError(
            "contradictory authoritative initial values and bounds: " + details +
            ". Reconcile the answers before generation: either choose initial values within "
            "the finite bounds or raise the bounds to contain every initial value.")
