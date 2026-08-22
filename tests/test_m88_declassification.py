# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from pipeline import cli
from pipeline.declassification_policy import DeclassificationPolicy
from pipeline.declassification_promotion import promote_declassification_policy
from pipeline.declassification_verification import verify_declassification_policy
from pipeline.capability_registry import capability


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"
CANDIDATE = KERNEL / "m88_declassification.candidate.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture_root(tmp_path: Path) -> Path:
    destination = tmp_path / "examples/formalkernel/kernel"
    destination.mkdir(parents=True)
    for name in (
        "m88_declassification.candidate.json",
        "m88_information_flow_scope.reviewed.json",
        "m88_information_flow.trace.validation.json",
    ):
        shutil.copy2(KERNEL / name, destination / name)
    return tmp_path


def test_declassification_candidate_is_precise_and_unproved():
    policy = DeclassificationPolicy.model_validate_json(CANDIDATE.read_text())
    assert policy.claim == "NO_PROOF"
    assert policy.review_status == "candidate"
    assert policy.trace_depth == 3
    assert len(policy.rules) == 1
    rule = policy.rules[0]
    assert rule.id == "AUTH_RESULT_PUBLIC"
    assert rule.high_source == (
        "capability_token_internal_state.authorization_result")
    assert rule.low_sink == "capability_decision"
    assert rule.released_projection == "authorization_result:boolean"
    assert policy.proof_families_executed == []
    assert policy.policy_mutations_rejected == 0


def test_declassification_promotion_requires_exact_hash_and_mints_no_proof(tmp_path):
    root = _fixture_root(tmp_path)
    with pytest.raises(ValueError, match="candidate hash mismatch"):
        promote_declassification_policy(root, accept_candidate_sha256="0" * 64)
    candidate = root / "examples/formalkernel/kernel/m88_declassification.candidate.json"
    result = promote_declassification_policy(
        root, accept_candidate_sha256=_sha256(candidate))
    reviewed = json.loads((root / result["reviewed_policy"]).read_text())
    assert result["claim"] == "NO_PROOF"
    assert reviewed["status"] == "REVIEWED_DECLASSIFICATION_POLICY"
    assert reviewed["accepted_candidate_sha256"] == _sha256(candidate)
    assert reviewed["proof_families_executed"] == []


def test_declassification_promotion_command_is_explicit():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["promote-declassification-policy"])
    args = parser.parse_args([
        "promote-declassification-policy",
        "--accept-candidate-sha256", "a" * 64])
    assert args.accept_candidate_sha256 == "a" * 64


def test_real_z3_replays_all_release_families_and_policy_mutations():
    reviewed = KERNEL / "m88_declassification.reviewed.json"
    evidence = json.loads((KERNEL / "m88_declassification.validation.json").read_text())
    replay = verify_declassification_policy(reviewed, ROOT)
    assert replay["status"] == "DECLASSIFICATION_POLICY_PROVED"
    assert replay["reviewed_policy_sha256"] == _sha256(reviewed)
    assert replay["verifier_sha256"] == _sha256(
        ROOT / "pipeline/declassification_verification.py")
    assert [item["id"] for item in replay["proof_families"]] == [
        "release_authorization", "release_precision",
        "non_amplification_depth_3", "rule_isolation"]
    assert replay["mutations_executed"] == replay["mutations_rejected"] == 7
    assert {item["id"] for item in replay["mutations"]} == {
        item["id"] for item in evidence["mutations"]}
    assert "INFORMATION_FLOW_NONINTERFERENCE_PROVED" in replay["claims_locked"]


def test_m88_registry_exposes_only_scoped_model_claims():
    milestone = capability("m88_1_information_flow_scope").milestone
    assert milestone is not None
    assert milestone.current_step == 4
    assert milestone.current_maturity == "scoped-model-confidentiality-complete"
    assert milestone.completed_claims[-1] == "DECLASSIFICATION_POLICY_PROVED"
    assert "INFORMATION_FLOW_IMPLEMENTATION_REFINEMENT_PROVED" not in (
        milestone.completed_claims)
