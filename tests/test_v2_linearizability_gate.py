import json
import hashlib
from unittest.mock import patch

from pipeline.domain_v2_evidence import build_evidence_envelope
from pipeline.domain_v2_tla import render_v2_tla
from pipeline.v2_linearizability_gate import rust_v2_linearizability_gate
from pipeline.v2_lock_serializer import render_rust_mutex
from pipeline.domain_v2_promotion import ReviewedDomainSpecV2


def reviewed_lock_domain():
    return ReviewedDomainSpecV2.model_validate({
        "schema_version": 2, "review_status": "reviewed",
        "domain_name": "LockedCounter", "module_name": "locked_counter", "actors": 2,
        "state_variables": [
            {"kind": "int", "name": "lock_state", "bound": [0, 2], "initial": 0},
            {"kind": "int", "name": "value", "bound": [0, 2], "initial": 0}],
        "concurrency": {"mode": "lock_protocol", "lock_variable": "lock_state",
            "lock_states": ["UNLOCKED", "LOCKED_A", "LOCKED_B"],
            "unlocked_value": 0, "actor_lock_values": [1, 2],
            "linearization_points": {"Increment": "effect_commit"}},
        "operations": [{"name": "Increment", "return_type": "void",
            "failure_semantics": "unavailable", "guards": [{"id": "below", "expression": {
                "kind": "lt", "left": {"kind": "field", "name": "value"},
                "right": {"kind": "integer", "value": 2}}}],
            "effects": [{"id": "increment", "target": "value", "value": {
                "kind": "add", "left": {"kind": "field", "name": "value"},
                "right": {"kind": "integer", "value": 1}}}], "frame": ["value"]}],
        "tlc_invariants": [{"id": "ValueBounded", "expression": {
            "kind": "lte", "left": {"kind": "field", "name": "value"},
            "right": {"kind": "integer", "value": 2}}}],
        "accepted_candidate_sha256": "a" * 64,
        "accepted_evidence_sha256": "b" * 64})


def _bound_files(tmp_path):
    reviewed = reviewed_lock_domain()
    tla, _ = render_v2_tla(reviewed)
    envelope = build_evidence_envelope({
        "validation_status": "VALIDATED", "tlc_exit_status": 0,
        "candidate_sha256": reviewed.accepted_candidate_sha256,
        "generated_tla_sha256": hashlib.sha256(tla.encode()).hexdigest(),
        "execution_assumption": "bounded_lock_history_abstraction",
        "abstraction_mode": "lock_protocol",
        "reachable_state_count": 21, "reachable_transition_count": 38})
    reviewed = reviewed.model_copy(update={
        "accepted_evidence_sha256": envelope["evidence_sha256"]})
    reviewed_path = tmp_path / "reviewed.json"
    validation_path = tmp_path / "validation.json"
    reviewed_path.write_text(reviewed.model_dump_json(), encoding="utf-8")
    validation_path.write_text(json.dumps(envelope), encoding="utf-8")
    return reviewed, reviewed_path, validation_path


def test_exact_rust_mutex_history_mints_restricted_linearizability_certificate(tmp_path):
    reviewed, reviewed_path, validation_path = _bound_files(tmp_path)
    code = render_rust_mutex(reviewed)
    result = rust_v2_linearizability_gate(
        reviewed_path, validation_path, code, native_checked=True)
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "CONCURRENT_LINEARIZABILITY"
    assert result["scope"] == "bounded_single_mutex_history_refinement"
    assert result["source_refinement_proved"]
    assert result["concurrent_linearizability_proved"]
    assert result["certificate_sha256"]
    assert all(item["status"] == "PROVED" for item in result["obligations"])


def test_linearizability_gate_fails_closed_on_each_trust_boundary(tmp_path):
    reviewed, reviewed_path, validation_path = _bound_files(tmp_path)
    code = render_rust_mutex(reviewed)
    assert rust_v2_linearizability_gate(
        reviewed_path, validation_path, code, native_checked=False)["code"] == "native_not_checked"
    assert rust_v2_linearizability_gate(
        reviewed_path, validation_path, code + "\n", native_checked=True)["code"] == \
        "lock_discipline_not_verified"

    atomic = reviewed.model_copy(update={"concurrency": None})
    with patch("pipeline.v2_linearizability_gate.load_bound_reviewed_domain",
               return_value=atomic):
        assert rust_v2_linearizability_gate(
            reviewed_path, validation_path, code, native_checked=True)["code"] == \
            "unsupported_concurrency_boundary"


def test_linearizability_gate_rejects_invalid_evidence(tmp_path):
    reviewed, reviewed_path, validation_path = _bound_files(tmp_path)
    validation_path.write_text("{}", encoding="utf-8")
    result = rust_v2_linearizability_gate(
        reviewed_path, validation_path, render_rust_mutex(reviewed), native_checked=True)
    assert result["status"] == "FAIL"
    assert not result["concurrent_linearizability_proved"]
    with patch("pipeline.v2_linearizability_gate.load_bound_reviewed_domain",
               side_effect=ValueError("bad reviewed data")):
        result = rust_v2_linearizability_gate(
            reviewed_path, validation_path, "", native_checked=True)
    assert result["code"] == "unsupported_refinement_boundary"
