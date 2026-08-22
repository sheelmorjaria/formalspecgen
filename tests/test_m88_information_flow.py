# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from pipeline.capability_registry import capability
from pipeline.hyperproperty_evidence import HyperpropertyEvidence
from pipeline.information_flow import (
    verify_server_policy_trace, verify_server_policy_two_run,
)


ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "examples/formalkernel/kernel/m88_information_flow_scope.candidate.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_m88_scope_is_hash_bound_and_mints_no_claim():
    raw = json.loads(SCOPE.read_text())
    evidence = HyperpropertyEvidence.model_validate(raw)
    assert evidence.status == "HYPERPROPERTY_SCOPE_CANDIDATE"
    assert evidence.claim == "NO_PROOF"
    assert evidence.scope_review_status == "candidate"
    assert evidence.reviewed_scope_sha256 is None
    assert evidence.scope.security_property_class == "two_run_noninterference"
    assert evidence.scope.termination_sensitive is False
    assert evidence.scope.timing_sensitive is False
    for name, digest in evidence.artifact_sha256.items():
        assert digest == _sha256(ROOT / name)
    assert evidence.two_run_judgment_executed is False
    assert evidence.confidentiality_mutation_rejected is False


def test_hyperproperty_schema_rejects_vacuous_proof_and_partition_overlap():
    raw = json.loads(SCOPE.read_text())
    with pytest.raises(ValidationError):
        HyperpropertyEvidence.model_validate(
            raw | {"claim": "SERVER_POLICY_NONINTERFERENCE_MODEL_PROVED",
                   "two_run_judgment_executed": True,
                   "confidentiality_mutation_rejected": True})
    scope = raw["scope"] | {
        "low_observables": raw["scope"]["low_observables"] + ["vfs.private_payload"]}
    with pytest.raises(ValidationError):
        HyperpropertyEvidence.model_validate(raw | {"scope": scope})


def test_m88_registry_keeps_relational_claims_locked():
    milestone = capability("m88_1_information_flow_scope").milestone
    assert milestone is not None
    assert milestone.current_step == 4
    assert milestone.completed_claims == (
        "SERVER_POLICY_TWO_RUN_NONINTERFERENCE_PROVED",
        "SERVER_POLICY_TRACE_NONINTERFERENCE_PROVED",
        "DECLASSIFICATION_POLICY_PROVED")
    assert milestone.current_maturity == "scoped-model-confidentiality-complete"
    assert milestone.claims[0].claim == "SERVER_POLICY_TWO_RUN_NONINTERFERENCE_PROVED"


def test_real_z3_replays_two_run_theorem_and_both_mutation_classes():
    reviewed = ROOT / "examples/formalkernel/kernel/"
    reviewed /= "m88_information_flow_scope.reviewed.json"
    evidence = json.loads((ROOT / "examples/formalkernel/kernel/"
                           "m88_information_flow.validation.json").read_text())
    replay = verify_server_policy_two_run(reviewed, ROOT)
    assert replay["status"] == "SERVER_POLICY_TWO_RUN_NONINTERFERENCE_PROVED"
    assert replay["smt_sha256"] == evidence["smt_sha256"]
    assert replay["verifier_sha256"] == _sha256(ROOT / "pipeline/information_flow.py")
    assert replay["judge_executable_sha256"] == evidence["judge_executable_sha256"]
    assert replay["verifier_sha256"] == _sha256(ROOT / "pipeline/information_flow.py")
    assert replay["reviewed_scope_sha256"] == _sha256(reviewed)
    assert replay["mutations_executed"] == replay["mutations_rejected"] == 7
    assert replay["mutation_classes"] == ["model_leakage", "scope_weakening"]
    assert "INFORMATION_FLOW_NONINTERFERENCE_PROVED" in replay["claims_locked"]


def test_real_z3_replays_bounded_trace_and_history_mutations():
    reviewed = ROOT / "examples/formalkernel/kernel/"
    reviewed /= "m88_information_flow_scope.reviewed.json"
    evidence = json.loads((ROOT / "examples/formalkernel/kernel/"
                           "m88_information_flow.trace.validation.json").read_text())
    replay = verify_server_policy_trace(reviewed, ROOT, trace_depth=3)
    assert replay["status"] == "SERVER_POLICY_TRACE_NONINTERFERENCE_PROVED"
    assert replay["smt_sha256"] == evidence["smt_sha256"]
    assert replay["trace_depth"] == 3
    assert replay["contains_multi_step_execution"] is True
    assert replay["matched_public_input_steps"] > 1
    assert replay["history_dependent_mutations_executed"] == 2
    assert replay["history_dependent_mutations_rejected"] == 2
    assert {item["id"] for item in replay["mutations"]} == {
        "hidden_then_route", "hidden_then_queue"}


def test_trace_gate_refuses_single_step_vacuity():
    reviewed = ROOT / "examples/formalkernel/kernel/"
    reviewed /= "m88_information_flow_scope.reviewed.json"
    result = verify_server_policy_trace(reviewed, ROOT, trace_depth=1)
    assert result["status"] == "TRACE_ANTI_VACUITY_FAILED"
    assert result["claim"] == "NO_PROOF"
