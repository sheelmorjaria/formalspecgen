# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed semantic extraction from validated banking JML into typed TLA IR."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .tla_ir import (
    BankingConcurrencyMetadata, BankingOperationIR, BankingTlaModel,
)
from .jml_ast import BinaryExpr, ResultValue, UnaryExpr, parse_jml_expression
from .transition_ir import (
    LocationIR, MethodTransitionIR, ParameterIR, TLARenderer,
    UnsupportedBoundaryError, assignment_from_equality, flatten_and,
)


class UnsupportedJmlSemantics(ValueError):
    pass


@dataclass(frozen=True)
class ConsistencyFinding:
    code: str
    operation: str
    message: str


_METHOD = re.compile(
    r"(?P<contracts>(?:\s*//@[^\n]*\n)+)\s*public\s+(?:static\s+)?"
    r"(?P<return>boolean|void|int|long)\s+(?P<name>deposit|withdraw|transfer)\s*"
    r"\((?P<params>[^)]*)\)\s*\{", re.I,
)


def normalize_jml_clause(value: str) -> str:
    value = value.strip().rstrip(";")
    value = re.sub(r"\\old\s*\(\s*([^()]+?)\s*\)", r"\\old(\1)", value)
    return re.sub(r"\s+", "", value).lower()


def _clauses(contracts: str, keyword: str) -> list[str]:
    return [item.strip() for item in re.findall(
        rf"(?m)^\s*//@\s*{keyword}\s+(.+?)\s*;\s*$", contracts, re.I)]


def _contains(clauses: list[str], pattern: str) -> bool:
    return any(re.search(pattern, normalize_jml_clause(item)) for item in clauses)


def _parameters(source: str) -> list[ParameterIR]:
    if not source.strip():
        return []
    result = []
    for item in source.split(","):
        match = re.fullmatch(r"\s*(boolean|int|long|[A-Z]\w*)\s+(\w+)\s*", item)
        if not match:
            raise UnsupportedJmlSemantics(f"Unsupported Java parameter declaration: {item.strip()}")
        # Object references may identify state receivers but are not scalar TLA parameters.
        if match.group(1) in {"boolean", "int", "long"}:
            result.append(ParameterIR(name=match.group(2), type=match.group(1)))
    return result


def extract_method_transition_ir(name: str, return_type: str, params_source: str,
                                 contracts: str, fields: set[str],
                                 field_variables: dict[str, str] | None = None) -> MethodTransitionIR:
    """Compile supported clauses into transition structure before domain lowering."""
    scalar_params = _parameters(params_source)
    all_param_names = set(re.findall(r"\b(\w+)\s*(?:,|$)", params_source))

    def parse(clause: str):
        try:
            return parse_jml_expression(clause, fields=fields, parameters=all_param_names)
        except ValueError as exc:
            raise UnsupportedJmlSemantics(f"Unsupported JML expression in {name}: {exc}") from exc

    guards = [parse(item) for item in _clauses(contracts, "requires")]
    success_condition = None
    success_effects = []
    failure_effects = []
    result_constrained = False
    for clause in _clauses(contracts, "ensures"):
        expression = parse(clause)
        if isinstance(expression, BinaryExpr) and expression.kind == "iff" and isinstance(
                expression.left, ResultValue):
            result_constrained = True
            success_condition = expression.right
            continue
        if isinstance(expression, BinaryExpr) and expression.kind == "implies":
            destination = None
            if isinstance(expression.left, ResultValue):
                result_constrained, destination = True, success_effects
            elif (isinstance(expression.left, UnaryExpr) and expression.left.kind == "not" and
                  isinstance(expression.left.operand, ResultValue)):
                result_constrained, destination = True, failure_effects
            if destination is not None:
                for effect in flatten_and(expression.right):
                    assignment = assignment_from_equality(effect)
                    if assignment is None:
                        raise UnsupportedJmlSemantics(
                            f"Unsupported result-guarded postcondition in {name}: {clause}")
                    destination.append(assignment)
                continue
        if return_type.lower() == "void":
            assignments = []
            for effect in flatten_and(expression):
                assignment = assignment_from_equality(effect)
                if assignment is None:
                    raise UnsupportedJmlSemantics(
                        f"Unsupported unconditional postcondition in {name}: {clause}")
                assignments.append(assignment)
            success_effects.extend(assignments)
            continue
        raise UnsupportedJmlSemantics(
            f"Ensures clause in {name} has no reviewed transition lowering: {clause}")

    frame = []
    for clause in _clauses(contracts, "assignable"):
        for location in clause.split(","):
            value = location.strip()
            if value == r"\nothing":
                continue
            match = re.fullmatch(r"(?:(\w+)\.)?(\w+)", value)
            if not match:
                raise UnsupportedJmlSemantics(f"Unsupported assignable location in {name}: {value}")
            frame.append(LocationIR(receiver=match.group(1) or "this", field=match.group(2)))

    transition = MethodTransitionIR(name=name, parameters=scalar_params, guards=guards,
        success_condition=success_condition, success_effects=success_effects,
        failure_effects=failure_effects, frame=frame, result_constrained=result_constrained)

    # Exercise the fail-closed visitor now, before a domain template can be selected.
    renderer = TLARenderer(field_variables)
    try:
        for expression in [*transition.guards,
                           *([transition.success_condition] if transition.success_condition else []),
                           *(item.value for item in transition.success_effects),
                           *(item.value for item in transition.failure_effects)]:
            renderer.render_expression(expression)
    except UnsupportedBoundaryError as exc:
        raise UnsupportedJmlSemantics(f"Unsupported JML semantics in {name}: {exc.reason}") from exc
    return transition


def _extract_operation(name: str, return_type: str, contracts: str) -> BankingOperationIR:
    requires = _clauses(contracts, "requires")
    ensures = _clauses(contracts, "ensures")
    assignable = _clauses(contracts, "assignable")
    signals = _clauses(contracts, r"signals\s*\([^)]*\)")
    normalized_ensures = [normalize_jml_clause(item) for item in ensures]
    result_constrained = return_type.lower() == "boolean" and any(
        "\\result" in item for item in normalized_ensures)
    positive = _contains(requires, r"(?:^|&&|\()amount>0(?:$|&&|\))") or _contains(
        signals, r"amount<=0")

    if name == "deposit":
        effect = any(re.search(
            r"\\result==>balance==\\old\(balance\)\+amount", item)
            for item in normalized_ensures)
        failure = any(re.search(
            r"!\\result==>balance==\\old\(balance\)", item)
            for item in normalized_ensures)
        capacity = any("maxbalance" in item or re.search(
            r"amount<=\d+l?-\\old\(balance\)", item) for item in
            [*map(normalize_jml_clause, requires), *normalized_ensures])
        if not effect:
            raise UnsupportedJmlSemantics("No reviewed deposit effect mapping")
        guards = ["positive_amount"] if positive else []
        if capacity:
            guards.append("destination_has_capacity")
        frames = ["receiver_balance"] if any(
            normalize_jml_clause(item) == "balance" for item in assignable) else []
        return BankingOperationIR(operation=name, guard_ids=guards,
            effect_id="atomic_deposit", frame_ids=frames,
            result_constrained=result_constrained, failure_preserves_frame=failure)

    if name == "withdraw":
        effect = any(re.search(
            r"\\result==>balance==\\old\(balance\)-amount", item)
            for item in normalized_ensures)
        failure = any(re.search(
            r"!\\result==>balance==\\old\(balance\)", item)
            for item in normalized_ensures)
        funds = any(re.search(r"amount<=\\old\(balance\)|amount<=balance", item)
                    for item in [*map(normalize_jml_clause, requires), *normalized_ensures])
        if not effect:
            raise UnsupportedJmlSemantics("No reviewed withdraw effect mapping")
        guards = ["positive_amount"] if positive else []
        if funds:
            guards.append("source_has_funds")
        frames = ["receiver_balance"] if any(
            normalize_jml_clause(item) == "balance" for item in assignable) else []
        return BankingOperationIR(operation=name, guard_ids=guards,
            effect_id="atomic_withdraw", frame_ids=frames,
            result_constrained=result_constrained, failure_preserves_frame=failure)

    # Transfer supports the reviewed from/to and source/destination contract shapes.
    joined = "&&".join(normalized_ensures)
    names = (("from", "to") if "from.balance" in joined else ("source", "destination"))
    source, destination = names
    debit = f"{source}.balance==\\old({source}.balance)-amount" in joined
    credit = f"{destination}.balance==\\old({destination}.balance)+amount" in joined
    failure = (f"{source}.balance==\\old({source}.balance)" in joined and
               f"{destination}.balance==\\old({destination}.balance)" in joined and
               "!\\result==>" in joined)
    normalized_all = [*map(normalize_jml_clause, requires), *normalized_ensures]
    funds = any(f"amount<=\\old({source}.balance)" in item or
                f"amount<={source}.balance" in item for item in normalized_all)
    capacity = any(f"\\old({destination}.balance)" in item and
                   ("max" in item or re.search(r"\d+l?", item)) for item in normalized_all)
    distinct = any(f"{source}!={destination}" in normalize_jml_clause(item) for item in requires)
    frames_text = {normalize_jml_clause(value) for item in assignable
                   for value in item.split(",")}
    frames = []
    if f"{source}.balance" in frames_text:
        frames.append("source_balance")
    if f"{destination}.balance" in frames_text:
        frames.append("destination_balance")
    if not (debit and credit):
        raise UnsupportedJmlSemantics("No reviewed atomic transfer debit/credit mapping")
    guards = ["positive_amount"] if positive else []
    if funds:
        guards.append("source_has_funds")
    if capacity:
        guards.append("destination_has_capacity")
    if distinct:
        guards.append("distinct_accounts")
    return BankingOperationIR(operation=name, guard_ids=guards,
        effect_id="atomic_transfer", frame_ids=frames,
        result_constrained=result_constrained, failure_preserves_frame=failure)


def extract_concurrency_metadata(clarifications: str,
                                 abstraction: str | None = None) -> BankingConcurrencyMetadata:
    text = re.sub(r"\s+", " ", clarifications).lower()
    has_atomicity = "linearizable" in text or "linearised" in text or "linearized" in text
    ordered = bool(re.search(r"(?:ascending|increasing).*?(?:immutable\s+)?account[- ]?id", text))
    immutable = bool(re.search(r"account (?:identity|id).*immutable|immutable account[- ]?id", text))
    selected = abstraction or ("lock_protocol" if ordered else "atomic_operations")
    if not has_atomicity:
        raise UnsupportedJmlSemantics("Concurrency metadata has no explicit linearization strategy")
    if selected == "lock_protocol" and not (ordered and immutable):
        raise UnsupportedJmlSemantics(
            "Lock-protocol abstraction requires ascending immutable account-ID ordering")
    return BankingConcurrencyMetadata(
        abstraction=selected,
        linearization="ordered_account_locks" if selected == "lock_protocol" else "method_atomic",
        lock_order="ascending_immutable_account_id" if selected == "lock_protocol" else "not_modeled",
        account_ids_immutable=immutable,
    )


def check_consistency(operations: list[BankingOperationIR],
                      metadata: BankingConcurrencyMetadata) -> list[dict]:
    findings: list[ConsistencyFinding] = []
    expected_frames = {
        "deposit": {"receiver_balance"}, "withdraw": {"receiver_balance"},
        "transfer": {"source_balance", "destination_balance"},
    }
    required_guards = {
        "deposit": {"positive_amount", "destination_has_capacity"},
        "withdraw": {"positive_amount", "source_has_funds"},
        "transfer": {"positive_amount", "source_has_funds",
                     "destination_has_capacity", "distinct_accounts"},
    }
    for operation in operations:
        def add(code: str, message: str) -> None:
            findings.append(ConsistencyFinding(code, operation.operation, message))
        if not operation.result_constrained:
            add("unconstrained_result", "Boolean result does not distinguish success and failure")
        if not operation.failure_preserves_frame:
            add("failure_changes_state", "Failed operation does not explicitly preserve its frame")
        actual_frames = set(operation.frame_ids)
        if actual_frames != expected_frames[operation.operation]:
            add("frame_mismatch", f"Expected frame {sorted(expected_frames[operation.operation])}, got {sorted(actual_frames)}")
        missing = required_guards[operation.operation] - set(operation.guard_ids)
        if missing:
            add("missing_guard", "Missing reviewed guards: " + ", ".join(sorted(missing)))
    if metadata.abstraction == "lock_protocol" and (
            metadata.lock_order != "ascending_immutable_account_id" or
            not metadata.account_ids_immutable):
        findings.append(ConsistencyFinding("unsafe_lock_order", "transfer",
            "Lock protocol lacks ascending immutable account-ID ordering"))
    return [asdict(item) for item in findings]


def extract_banking_model(java_code: str, clarifications: str,
                          abstraction: str | None = None) -> tuple[BankingTlaModel, list[dict]]:
    matches = list(_METHOD.finditer(java_code))
    by_name = {match.group("name").lower(): match for match in matches}
    missing = [name for name in ("deposit", "withdraw", "transfer") if name not in by_name]
    if missing:
        raise UnsupportedJmlSemantics("Missing reviewed banking methods: " + ", ".join(missing))
    fields = set(re.findall(
        r"\b(?:private|protected|public)\s+(?:/\*@.*?@\*/\s+)?(?:boolean|int|long)\s+(\w+)\s*;",
        java_code))
    # Parsing and transition compilation is mandatory even though the final domain mapping
    # remains deliberately whitelisted below.
    transitions = [extract_method_transition_ir(
        name, by_name[name].group("return"), by_name[name].group("params"),
        by_name[name].group("contracts"), fields)
        for name in ("deposit", "withdraw", "transfer")]
    operations = [_extract_operation(name, by_name[name].group("return"),
                  by_name[name].group("contracts"))
                  for name in ("deposit", "withdraw", "transfer")]
    metadata = extract_concurrency_metadata(clarifications, abstraction)
    findings = check_consistency(operations, metadata)
    model = BankingTlaModel(abstraction=metadata.abstraction,
        operations=[item.operation for item in operations], operation_ir=operations,
        transitions=transitions, concurrency=metadata)
    return model, findings
