# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Typed assurance profiles and fail-closed evidence-to-claim policy."""
from __future__ import annotations

import hashlib
import json
import re
from enum import Enum

from pydantic import BaseModel, ConfigDict


class AssuranceLevel(str, Enum):
    CRITICAL = "critical"
    STANDARD = "standard"
    LIGHTWEIGHT = "lightweight"


class GatePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    required: bool
    skip_reason: str = ""


_ORDER = ("javac", "spec_lint", "openjml_check", "tla", "openjml_esc", "refinement",
          "boundary_fallback", "rac_junit")


def parse_assurance_level(value: str | AssuranceLevel | None) -> AssuranceLevel:
    if isinstance(value, AssuranceLevel):
        return value
    normalized = str(value or AssuranceLevel.CRITICAL.value).strip().lower()
    try:
        return AssuranceLevel(normalized)
    except ValueError as exc:
        raise ValueError(
            f"unknown assurance level {value!r}; expected critical, standard, or lightweight") from exc


def gate_plan(value: str | AssuranceLevel | None) -> list[GatePolicy]:
    level = parse_assurance_level(value)
    required = {
        AssuranceLevel.CRITICAL: set(_ORDER[:-1]),
        AssuranceLevel.STANDARD: {"javac", "spec_lint", "openjml_check", "rac_junit"},
        AssuranceLevel.LIGHTWEIGHT: {"javac", "spec_lint"},
    }[level]
    return [GatePolicy(
        name=name, required=name in required,
        skip_reason="" if name in required else f"Assurance level is {level.value}")
        for name in _ORDER]


def assurance_verdict(value: str | AssuranceLevel | None,
                      gate_statuses: dict[str, str],
                      fail_reasons: dict[str, str] | None = None) -> dict:
    """Classify completed evidence without promoting samples into proof claims."""
    level = parse_assurance_level(value)
    plan = gate_plan(level)
    reasons = fail_reasons or {}
    records = []
    failed = []
    for gate in plan:
        status = gate_statuses.get(gate.name, "NOT_RUN") if gate.required else "SKIPPED"
        reason = gate.skip_reason if not gate.required else reasons.get(gate.name, "")
        records.append({"gate": gate.name, "required": gate.required,
                        "status": status, "reason": reason})
        accepted = {"PASS", "VERIFIED", "TESTS_PASSED"}
        if gate.name == "boundary_fallback":
            accepted.add("NOT_APPLICABLE")
        if gate.required and status not in accepted:
            failed.append(gate.name)

    if failed:
        status, claim = "ASSURANCE_INCOMPLETE", "NO_PROOF"
    elif level is AssuranceLevel.CRITICAL:
        status, claim = "VERIFIED", "DEDUCTIVE_PROOF"
    elif level is AssuranceLevel.STANDARD:
        status, claim = "STATIC_CHECKED_RUNTIME_TESTED", "RUNTIME_SAMPLE"
    else:
        status, claim = "COMPILED_LINTED", "STATIC_CHECK"
    return {
        "final_status": status,
        "assurance_level": level.value,
        "gates": records,
        "failed_required_gates": failed,
        "final_claim_type": claim,
        # ESC and TLC judge different artifacts. Passing both does not establish
        # a simulation/refinement relation between the implementation and model.
        "source_refinement_proved": (
            level is AssuranceLevel.CRITICAL and not failed and
            gate_statuses.get("refinement") == "VERIFIED"),
        "deductive_proof_provided": level is AssuranceLevel.CRITICAL and not failed,
        "warnings": ([
            "OpenJML ESC and TLC passed independently; source/model refinement is not proven."
        ] if (level is AssuranceLevel.CRITICAL and
              gate_statuses.get("tla") in {"PASS", "VERIFIED"} and
              gate_statuses.get("openjml_esc") in {"PASS", "VERIFIED"} and
              gate_statuses.get("refinement") != "VERIFIED") else []),
    }


def refinement_gate(contract_code: str, implementation_code: str,
                    architecture_evidence: dict, *, esc_verified: bool) -> dict:
    """Check a reviewed sequential JML-contract-to-TLA action simulation.

    This gate composes an ESC result with a deterministic contract/model
    correspondence proof. It deliberately does not establish concurrent
    linearizability or refinement for an unreviewed domain.
    """
    from .domains.traffic_light_controller import (
        ABSTRACTION_MAPPING, ACTION_REFINEMENTS, INITIAL_STATE,
    )
    from .domains.traffic_light_controller_extract import (
        extract_traffic_light_controller_model,
    )
    from .jml_ast import BinaryExpr, FieldAccess, IntegerLiteral

    def fail(code: str, message: str, obligations: list[dict] | None = None) -> dict:
        return {"status": "FAIL", "code": code, "message": message,
                "source_refinement_proved": False,
                "obligations": obligations or []}

    if not esc_verified:
        return fail("esc_not_verified", "Implementation has no deductive ESC proof")
    if architecture_evidence.get("status") != "VERIFIED":
        return fail("tla_not_verified", "Architecture model has no successful TLC result")
    domain = architecture_evidence.get("domain")
    if domain not in {"traffic_light_controller", "elevator_controller"}:
        return fail("unsupported_refinement_domain",
                    "No reviewed refinement checker exists for this domain")
    if architecture_evidence.get("provenance", {}).get("execution_assumption") != "single_threaded":
        return fail("unsupported_execution_model",
                    "Reviewed refinement requires the single-threaded atomic abstraction")
    if domain == "elevator_controller":
        return _elevator_refinement_gate(
            contract_code, implementation_code, architecture_evidence, fail)

    try:
        contract_model, contract_findings = extract_traffic_light_controller_model(
            contract_code, "single-threaded", "atomic_operations")
        implementation_model, implementation_findings = extract_traffic_light_controller_model(
            implementation_code, "single-threaded", "atomic_operations")
    except ValueError as exc:
        return fail("unsupported_jml_semantics", str(exc))
    if contract_findings or implementation_findings:
        return fail("contract_model_inconsistent",
                    "JML guards, effects, or frames do not match reviewed actions",
                    [*contract_findings, *implementation_findings])
    if contract_model.model_dump() != implementation_model.model_dump():
        return fail("trusted_contract_changed",
                    "Implementation does not preserve the extracted trusted transition contract")
    if architecture_evidence.get("ir") != contract_model.model_dump():
        return fail("architecture_ir_mismatch",
                    "TLC did not check the exact IR extracted from the trusted contract")

    if (len(set(ABSTRACTION_MAPPING.values())) != len(ABSTRACTION_MAPPING) or
            set(INITIAL_STATE) != set(ABSTRACTION_MAPPING)):
        return fail("invalid_abstraction_mapping",
                    "Abstraction map must be total and injective over modeled Java state")

    transitions = {item.name: item for item in contract_model.transitions}
    if set(transitions) != set(ACTION_REFINEMENTS):
        return fail("operation_coverage_mismatch",
                    "Java methods and reviewed TLA+ actions are not one-to-one")
    action_names = [item["action"] for item in ACTION_REFINEMENTS.values()]
    if len(action_names) != len(set(action_names)):
        return fail("duplicate_tla_action", "Two Java methods map to the same TLA+ action")

    obligations = [{"kind": "initialization", "status": "PROVED",
                    "mapping": ABSTRACTION_MAPPING, "state": INITIAL_STATE}]
    tla_source = architecture_evidence.get("tla", "")
    for method, semantics in ACTION_REFINEMENTS.items():
        transition = transitions[method]
        guard_location, guard_value = semantics["guard"]
        update_location, update_value = semantics["update"]
        guard_field = guard_location.split(".", 1)[1]
        update_field = update_location.split(".", 1)[1]
        guard = transition.guards[0] if len(transition.guards) == 1 else None
        guard_ok = bool(
            isinstance(guard, BinaryExpr) and guard.kind == "eq" and
            ((isinstance(guard.left, FieldAccess) and guard.left.field == guard_field and
              isinstance(guard.right, IntegerLiteral) and guard.right.value == guard_value) or
             (isinstance(guard.right, FieldAccess) and guard.right.field == guard_field and
              isinstance(guard.left, IntegerLiteral) and guard.left.value == guard_value)))
        effects = transition.success_effects
        effect_ok = bool(
            len(effects) == 1 and effects[0].target.receiver == "this" and
            effects[0].target.field == update_field and
            isinstance(effects[0].value, IntegerLiteral) and
            effects[0].value.value == update_value)
        frame_ok = [(item.receiver, item.field) for item in transition.frame] == [
            ("this", update_field)]
        tla_guard = ABSTRACTION_MAPPING[guard_location]
        tla_update = ABSTRACTION_MAPPING[update_location]
        unchanged = next(value for key, value in ABSTRACTION_MAPPING.items()
                         if key != update_location)
        expected_action = (
            f"{semantics['action']} == /\\ {tla_guard} = {guard_value} "
            f"/\\ {tla_update}' = {update_value} /\\ UNCHANGED {unchanged}")
        action_ok = len(re.findall(
            rf"(?m)^{re.escape(expected_action)}$", tla_source)) == 1
        proved = guard_ok and effect_ok and frame_ok and action_ok
        obligations.append({"kind": "method_action", "method": method,
                            "action": semantics["action"], "pre_state_aligned": guard_ok,
                            "post_state_aligned": effect_ok,
                            "frame_aligned": frame_ok, "serialized_action_aligned": action_ok,
                            "status": "PROVED" if proved else "FAILED"})
    failed = [item for item in obligations if item["status"] != "PROVED"]
    if failed:
        return fail("refinement_obligation_failed",
                    "At least one method/action simulation obligation failed", obligations)

    certificate_body = {
        "domain": "traffic_light_controller",
        "scope": "single_threaded_atomic_contract_refinement",
        "abstraction_mapping": ABSTRACTION_MAPPING,
        "obligations": obligations,
        "architecture_ir_sha256": architecture_evidence.get("provenance", {}).get("ir_sha256"),
    }
    certificate_hash = hashlib.sha256(json.dumps(
        certificate_body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"status": "VERIFIED", "claim": "SOURCE_MODEL_REFINEMENT",
            "scope": certificate_body["scope"], "source_refinement_proved": True,
            "concurrent_linearizability_proved": False,
            "abstraction_mapping": ABSTRACTION_MAPPING,
            "obligations": obligations, "certificate_sha256": certificate_hash}


def _elevator_refinement_gate(contract_code: str, implementation_code: str,
                              architecture_evidence: dict, fail) -> dict:
    """Prove the reviewed elevator JML transition surface matches checked actions."""
    from .domains.elevator_controller import ABSTRACTION_MAPPING, ACTION_REFINEMENTS, INITIAL_STATE
    from .domains.elevator_controller_extract import extract_elevator_controller_model
    try:
        contract_model, contract_findings = extract_elevator_controller_model(
            contract_code, "single-threaded", "atomic_operations")
        implementation_model, implementation_findings = extract_elevator_controller_model(
            implementation_code, "single-threaded", "atomic_operations")
    except ValueError as exc:
        return fail("unsupported_jml_semantics", str(exc))
    findings = [*contract_findings, *implementation_findings]
    if findings:
        return fail("contract_model_inconsistent",
                    "Elevator guards, effects, or frames do not match reviewed actions", findings)
    if contract_model.model_dump() != implementation_model.model_dump():
        return fail("trusted_contract_changed",
                    "Implementation does not preserve the extracted trusted transition contract")
    if architecture_evidence.get("ir") != contract_model.model_dump():
        return fail("architecture_ir_mismatch",
                    "TLC did not check the exact IR extracted from the trusted contract")
    if (len(set(ABSTRACTION_MAPPING.values())) != len(ABSTRACTION_MAPPING) or
            set(INITIAL_STATE) != set(ABSTRACTION_MAPPING)):
        return fail("invalid_abstraction_mapping",
                    "Elevator abstraction map must be total and injective")
    transitions = {item.name: item for item in contract_model.transitions}
    if set(transitions) != set(ACTION_REFINEMENTS):
        return fail("operation_coverage_mismatch",
                    "Elevator methods and reviewed TLA+ actions are not one-to-one")
    action_names = [item["action"] for item in ACTION_REFINEMENTS.values()]
    if len(action_names) != len(set(action_names)):
        return fail("duplicate_tla_action", "Two elevator methods map to one TLA+ action")
    expected_lines = {
        "startMoveUp": "StartMoveUp == /\\ movingState = 0 /\\ doorState = 0 /\\ currentFloor < 4 /\\ movingState' = 1 /\\ UNCHANGED <<currentFloor, doorState>>",
        "startMoveDown": "StartMoveDown == /\\ movingState = 0 /\\ doorState = 0 /\\ currentFloor > 0 /\\ movingState' = 2 /\\ UNCHANGED <<currentFloor, doorState>>",
        "arriveUp": "ArriveUp == /\\ movingState = 1 /\\ currentFloor' = currentFloor + 1 /\\ movingState' = 0 /\\ UNCHANGED doorState",
        "arriveDown": "ArriveDown == /\\ movingState = 2 /\\ currentFloor' = currentFloor - 1 /\\ movingState' = 0 /\\ UNCHANGED doorState",
        "openDoors": "OpenDoors == /\\ movingState = 0 /\\ doorState = 0 /\\ doorState' = 1 /\\ UNCHANGED <<currentFloor, movingState>>",
        "closeDoors": "CloseDoors == /\\ doorState = 1 /\\ doorState' = 0 /\\ UNCHANGED <<currentFloor, movingState>>",
    }
    tla = architecture_evidence.get("tla", "")
    obligations = [{"kind": "initialization", "status": "PROVED",
                    "mapping": ABSTRACTION_MAPPING, "state": INITIAL_STATE}]
    for method, semantics in ACTION_REFINEMENTS.items():
        transition = transitions[method]
        serialized = len(re.findall(
            rf"(?m)^{re.escape(expected_lines[method])}$", tla)) == 1
        # The reviewed extractor has already matched every typed guard, effect and
        # frame. Record those separate simulation obligations for auditability.
        obligation = {"kind": "method_action", "method": method,
                      "action": semantics["action"], "pre_state_aligned": True,
                      "post_state_aligned": True,
                      "frame_aligned": bool(transition.frame),
                      "serialized_action_aligned": serialized}
        obligation["status"] = "PROVED" if all((
            obligation["pre_state_aligned"], obligation["post_state_aligned"],
            obligation["frame_aligned"], serialized)) else "FAILED"
        obligations.append(obligation)
    if any(item["status"] != "PROVED" for item in obligations):
        return fail("refinement_obligation_failed",
                    "At least one elevator method/action simulation obligation failed", obligations)
    body = {"domain": "elevator_controller",
            "scope": "single_threaded_atomic_contract_refinement",
            "abstraction_mapping": ABSTRACTION_MAPPING, "obligations": obligations,
            "architecture_ir_sha256": architecture_evidence.get("provenance", {}).get("ir_sha256")}
    certificate = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"status": "VERIFIED", "claim": "SOURCE_MODEL_REFINEMENT",
            "scope": body["scope"], "source_refinement_proved": True,
            "concurrent_linearizability_proved": False,
            "abstraction_mapping": ABSTRACTION_MAPPING,
            "obligations": obligations, "certificate_sha256": certificate}
