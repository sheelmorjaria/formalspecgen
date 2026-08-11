# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json

from pipeline.domain_v2 import DomainSpecV2
from pipeline.domain_v2_promotion import candidate_sha256, promote_validated_candidate
from pipeline.domain_v2_publication import (
    TlcEvidence, ValidatedEvidence, publish_validation_success,
)
from pipeline.domain_v2_evidence import build_evidence_envelope
from pipeline.domain_v2_tla import render_v2_tla
from pipeline.generic_refinement_gate import generic_v2_refinement_gate
from pipeline.generic_refinement_gate import _equivalent, _flatten_v2_and
from pipeline.domain_v2 import BinaryExpr as V2Binary, FieldExpr as V2Field
from pipeline.domain_v2 import IntegerExpr as V2Integer, OldExpr as V2Old
from pipeline.jml_ast import BinaryExpr, FieldAccess, IntegerLiteral, OldValue


def _candidate():
    return DomainSpecV2.model_validate({
        "schema_version": 2, "domain_name": "Switch", "module_name": "switch",
        "state_variables": [{"kind": "bool", "name": "enabled", "initial": False}],
        "operations": [{"name": "Enable", "return_type": "void",
            "failure_semantics": "unavailable", "guards": [],
            "effects": [{"id": "set_enabled", "target": "enabled",
                         "value": {"kind": "boolean", "value": True}}],
            "frame": ["enabled"]}],
        "tlc_invariants": [{"id": "EnabledTyped", "expression": {
            "kind": "or", "left": {"kind": "field", "name": "enabled"},
            "right": {"kind": "eq", "left": {"kind": "field", "name": "enabled"},
                      "right": {"kind": "boolean", "value": False}}}}],
    })


def _reviewed_files(tmp_path, candidate=None):
    candidate = candidate or _candidate()
    candidate_path = tmp_path / "switch.json"
    candidate_path.write_text(candidate.model_dump_json(), encoding="utf-8")
    tla, _ = render_v2_tla(candidate)
    evidence_path = tmp_path / "switch.validation.json"
    publish_validation_success(evidence_path, ValidatedEvidence(
        candidate_sha256=candidate_sha256(candidate),
        generated_tla_sha256=hashlib.sha256(tla.encode()).hexdigest(),
        execution_assumption="atomic_last_result_abstraction",
        abstraction_mode="atomic_operations", bounds={"enabled": 2, "actors": 1},
        state_space_upper_bound=2, reachable_state_count=2,
        reachable_transition_count=1,
        tools={"tlc": TlcEvidence(version="2.19", command=["java", "-jar", "tlc.jar"])},
        tlc_exit_status=0))
    reviewed_path = tmp_path / "reviewed.json"
    promote_validated_candidate(candidate_path, evidence_path, reviewed_path,
        accept_candidate_sha256=candidate_sha256(candidate))
    return reviewed_path, evidence_path


CONTRACT = """public class Switch {
    private /*@ spec_public @*/ boolean enabled;
    //@ assignable enabled;
    //@ ensures enabled == true;
    public void Enable() {}
}
"""


def test_generic_gate_proves_restricted_reviewed_v2_contract_simulation(tmp_path):
    reviewed, evidence = _reviewed_files(tmp_path)
    implementation = CONTRACT.replace("public void Enable() {}",
                                      "public void Enable() { enabled = true; }")
    result = generic_v2_refinement_gate(
        reviewed, evidence, CONTRACT, implementation, esc_verified=True)
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "SOURCE_MODEL_REFINEMENT"
    assert result["source_refinement_proved"]
    assert not result["concurrent_linearizability_proved"]
    assert result["obligations"][0]["status"] == "PROVED"


def test_generic_gate_fails_closed_for_contract_drift_and_evidence_rebinding(tmp_path):
    reviewed, evidence = _reviewed_files(tmp_path)
    drifted = CONTRACT.replace("enabled == true", "enabled == false")
    result = generic_v2_refinement_gate(
        reviewed, evidence, CONTRACT, drifted, esc_verified=True)
    assert result["code"] == "trusted_contract_changed"

    envelope = json.loads(evidence.read_text(encoding="utf-8"))
    envelope["evidence_sha256"] = "0" * 64
    evidence.write_text(json.dumps(envelope), encoding="utf-8")
    result = generic_v2_refinement_gate(
        reviewed, evidence, CONTRACT, CONTRACT, esc_verified=True)
    assert result["code"] == "invalid_evidence_digest"


def test_generic_gate_requires_both_formal_judgments(tmp_path):
    reviewed, evidence = _reviewed_files(tmp_path)
    assert generic_v2_refinement_gate(
        reviewed, evidence, CONTRACT, CONTRACT, esc_verified=False)["code"] == "esc_not_verified"
    assert generic_v2_refinement_gate(
        reviewed, evidence, CONTRACT, CONTRACT,
        esc_verified=True, tlc_verified=False)["code"] == "tlc_not_verified"


def test_generic_gate_fails_closed_at_each_external_binding(tmp_path):
    reviewed, evidence = _reviewed_files(tmp_path)
    assert generic_v2_refinement_gate(
        tmp_path / "missing.json", evidence, CONTRACT, CONTRACT,
        esc_verified=True)["code"] == "unsupported_refinement_boundary"

    reviewed_value = json.loads(reviewed.read_text())
    reviewed_value["accepted_candidate_sha256"] = "f" * 64
    reviewed.write_text(json.dumps(reviewed_value))
    assert generic_v2_refinement_gate(
        reviewed, evidence, CONTRACT, CONTRACT,
        esc_verified=True)["code"] == "candidate_evidence_mismatch"


def test_generic_gate_rejects_unsuccessful_rebound_or_different_tla_evidence(tmp_path):
    reviewed, evidence = _reviewed_files(tmp_path)

    def rewrite_evidence(**changes):
        envelope = json.loads(evidence.read_text())
        inner = {**envelope["evidence"], **changes}
        rebound = build_evidence_envelope(inner)
        evidence.write_text(json.dumps(rebound))
        reviewed_value = json.loads(reviewed.read_text())
        reviewed_value["accepted_evidence_sha256"] = rebound["evidence_sha256"]
        reviewed.write_text(json.dumps(reviewed_value))

    rewrite_evidence(tlc_exit_status=1)
    assert generic_v2_refinement_gate(
        reviewed, evidence, CONTRACT, CONTRACT,
        esc_verified=True)["code"] == "evidence_not_validated"

    second = tmp_path / "different_tla"
    second.mkdir()
    reviewed, evidence = _reviewed_files(second)
    envelope = json.loads(evidence.read_text())
    rebound = build_evidence_envelope({**envelope["evidence"],
                                       "generated_tla_sha256": "0" * 64})
    evidence.write_text(json.dumps(rebound))
    reviewed_value = json.loads(reviewed.read_text())
    reviewed_value["accepted_evidence_sha256"] = rebound["evidence_sha256"]
    reviewed.write_text(json.dumps(reviewed_value))
    assert generic_v2_refinement_gate(
        reviewed, evidence, CONTRACT, CONTRACT,
        esc_verified=True)["code"] == "tla_serialization_mismatch"


def test_generic_gate_rejects_reviewed_model_bound_to_another_evidence_envelope(tmp_path):
    reviewed, evidence = _reviewed_files(tmp_path)
    value = json.loads(reviewed.read_text())
    value["accepted_evidence_sha256"] = "0" * 64
    reviewed.write_text(json.dumps(value))
    assert generic_v2_refinement_gate(
        reviewed, evidence, CONTRACT, CONTRACT,
        esc_verified=True)["code"] == "reviewed_evidence_mismatch"


def test_generic_gate_rejects_empty_and_non_bijective_transition_surfaces(tmp_path):
    reviewed, evidence = _reviewed_files(tmp_path)
    no_method = "public class Switch { private boolean enabled; }"
    assert generic_v2_refinement_gate(
        reviewed, evidence, no_method, no_method,
        esc_verified=True)["code"] == "empty_transition_surface"
    extra = CONTRACT.replace(
        "}\n", "  //@ assignable \\nothing;\n  public void Extra() {}\n}\n", 1)
    assert generic_v2_refinement_gate(
        reviewed, evidence, extra, extra,
        esc_verified=True)["code"] == "operation_coverage_mismatch"


def test_generic_gate_reports_guard_effect_and_frame_obligation_failures(tmp_path):
    reviewed, evidence = _reviewed_files(tmp_path)
    bad_frame = CONTRACT.replace("assignable enabled", "assignable \\nothing")
    result = generic_v2_refinement_gate(
        reviewed, evidence, bad_frame, bad_frame, esc_verified=True)
    assert result["code"] == "refinement_obligation_failed"
    assert not result["obligations"][0]["frame_aligned"]

    bad_effect = CONTRACT.replace("enabled == true", "enabled == false")
    result = generic_v2_refinement_gate(
        reviewed, evidence, bad_effect, bad_effect, esc_verified=True)
    assert result["code"] == "refinement_obligation_failed"
    assert not result["obligations"][0]["post_state_aligned"]


def test_expression_equivalence_and_conjunction_flattening_are_structural():
    field = V2Field(name="x")
    old = V2Old(expression=field)
    add = V2Binary(kind="add", left=old, right=V2Integer(value=1))
    jml_add = BinaryExpr(kind="add",
        left=OldValue(expression=FieldAccess(field="x")), right=IntegerLiteral(value=1))
    assert _equivalent(add, jml_add)
    assert not _equivalent(V2Integer(value=2), IntegerLiteral(value=1))
    assert not _equivalent(field, IntegerLiteral(value=1))
    conjunction = V2Binary(kind="and", left=field, right=V2Integer(value=1))
    assert _flatten_v2_and(conjunction) == [field, V2Integer(value=1)]
    assert _flatten_v2_and(field) == [field]
    assert not _equivalent(object(), IntegerLiteral(value=1))


def test_generic_boolean_gate_checks_combined_guard_and_explicit_failure_stutter(tmp_path):
    value = _candidate().model_dump(mode="json")
    value["operations"][0].update(
        return_type="boolean", failure_semantics="false_and_stutter",
        guards=[{"id": "disabled", "expression": {"kind": "eq",
            "left": {"kind": "field", "name": "enabled"},
            "right": {"kind": "boolean", "value": False}}},
            {"id": "not_enabled", "expression": {"kind": "neq",
             "left": {"kind": "field", "name": "enabled"},
             "right": {"kind": "boolean", "value": True}}}])
    candidate = DomainSpecV2.model_validate(value)
    reviewed, evidence = _reviewed_files(tmp_path, candidate)
    boolean_contract = r"""public class Switch {
    private /*@ spec_public @*/ boolean enabled;
    //@ assignable enabled;
    //@ ensures \result <==> \old(enabled) == false && \old(enabled) != true;
    //@ ensures \result ==> enabled == true;
    //@ ensures !\result ==> enabled == \old(enabled);
    public boolean Enable() { return false; }
}
"""
    result = generic_v2_refinement_gate(
        reviewed, evidence, boolean_contract, boolean_contract, esc_verified=True)
    assert result["status"] == "VERIFIED"
    assert result["obligations"][0]["failure_stutters"]

    no_stutter = boolean_contract.replace(
        "    //@ ensures !\\result ==> enabled == \\old(enabled);\n", "")
    result = generic_v2_refinement_gate(
        reviewed, evidence, no_stutter, no_stutter, esc_verified=True)
    assert result["code"] == "refinement_obligation_failed"
    assert not result["obligations"][0]["failure_stutters"]


def test_generic_gate_rejects_unmodeled_failure_effects(tmp_path):
    value = _candidate().model_dump(mode="json")
    value["operations"][0].update(return_type="boolean", failure_semantics="unavailable",
                                  guards=[{"id": "disabled", "expression": {
                                      "kind": "eq",
                                      "left": {"kind": "field", "name": "enabled"},
                                      "right": {"kind": "boolean", "value": False}}}])
    reviewed, evidence = _reviewed_files(tmp_path, DomainSpecV2.model_validate(value))
    contract = r"""public class Switch {
    private /*@ spec_public @*/ boolean enabled;
    //@ assignable enabled;
    //@ ensures \result <==> \old(enabled) == false;
    //@ ensures \result ==> enabled == true;
    //@ ensures !\result ==> enabled == \old(enabled);
    public boolean Enable() { return false; }
}
"""
    result = generic_v2_refinement_gate(
        reviewed, evidence, contract, contract, esc_verified=True)
    assert result["code"] == "refinement_obligation_failed"
