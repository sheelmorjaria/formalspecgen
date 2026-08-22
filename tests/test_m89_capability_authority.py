# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from pipeline import cli
from pipeline.capability_authority_model import CapabilityAuthorityModel
from pipeline.capability_authority_promotion import promote_capability_authority_model
from pipeline.capability_authority_verification import verify_capability_authority
from pipeline.capability_revocation_verification import verify_capability_revocation
from pipeline.server_authority_composition import verify_server_authority_composition
from pipeline.capability_registry import capability


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"
CANDIDATE = KERNEL / "m89_capability_authority.candidate.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_m89_candidate_is_parameterized_complete_and_unproved():
    model = CapabilityAuthorityModel.model_validate_json(CANDIDATE.read_text())
    assert model.claim == "NO_PROOF"
    assert model.parameterization == "arbitrary_finite_principals_objects_rights"
    assert model.capability_fields == [
        "object", "rights", "owner", "generation", "validity"]
    assert [operation.name for operation in model.operations] == [
        "mint_root", "derive", "delegate", "revoke", "check"]
    assert model.proof_executed is False
    assert model.mutation_suite_executed is False


def test_m89_promotion_is_hash_bound_and_mints_no_claim(tmp_path):
    directory = tmp_path / "examples/formalkernel/kernel"
    directory.mkdir(parents=True)
    shutil.copy2(CANDIDATE, directory / CANDIDATE.name)
    with pytest.raises(ValueError, match="candidate hash mismatch"):
        promote_capability_authority_model(tmp_path, accept_candidate_sha256="0" * 64)
    result = promote_capability_authority_model(
        tmp_path, accept_candidate_sha256=_sha256(directory / CANDIDATE.name))
    reviewed = json.loads((tmp_path / result["reviewed_model"]).read_text())
    assert result["claim"] == "NO_PROOF"
    assert reviewed["status"] == "REVIEWED_CAPABILITY_AUTHORITY_MODEL"
    assert reviewed["proof_executed"] is False


def test_m89_promotion_command_is_explicit_and_not_a_proof_command():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["promote-capability-authority"])
    args = parser.parse_args([
        "promote-capability-authority", "--accept-candidate-sha256", "a" * 64])
    assert args.accept_candidate_sha256 == "a" * 64


def test_real_tlaps_evidence_binds_reviewed_model_and_rejects_mutations():
    reviewed = KERNEL / "m89_capability_authority.reviewed.json"
    evidence = json.loads(
        (KERNEL / "m89_capability_authority.validation.json").read_text())
    assert evidence["status"] == "CAPABILITY_TOKEN_CREATION_CLOSED_PROVED"
    assert evidence["reviewed_model_sha256"] == _sha256(reviewed)
    assert evidence["proof_sha256"] == _sha256(
        KERNEL / "capability/CapabilityAuthorityRefinement.tla")
    assert evidence["verifier_sha256"] == _sha256(
        ROOT / "pipeline/capability_authority_verification.py")
    assert evidence["tlaps_obligations_proved"] == 12
    assert evidence["mutations_executed"] == evidence["mutations_rejected"] == 4
    assert {item["id"] for item in evidence["mutations"]} == {
        "unauthorized_root_mint", "derive_rights_amplification",
        "derive_object_substitution", "forged_creation_origin"}


def test_m89_verifier_fails_closed_without_reviewed_identity(tmp_path):
    reviewed = tmp_path / "m89_capability_authority.reviewed.json"
    reviewed.write_text(json.dumps({"status": "candidate"}))
    (tmp_path / "m89_capability_authority.candidate.json").write_text("{}")
    result = verify_capability_authority(reviewed, ROOT)
    assert result["status"] == "REVIEWED_CAPABILITY_AUTHORITY_REQUIRED"
    assert result["claim"] == "NO_PROOF"


def test_m89_revocation_evidence_is_parameterized_and_mutation_sensitive():
    evidence = json.loads(
        (KERNEL / "m89_capability_revocation.validation.json").read_text())
    assert evidence["claim"] == "CAPABILITY_REVOCATION_SAFETY_PROVED"
    assert evidence["scope"] == (
        "parameterized_transitive_revocation_and_generation_safety")
    assert evidence["proof_sha256"] == _sha256(
        KERNEL / "capability/CapabilityRevocationRefinement.tla")
    assert evidence["verifier_sha256"] == _sha256(
        ROOT / "pipeline/capability_revocation_verification.py")
    assert evidence["tlaps_obligations_proved"] == 10
    assert evidence["mutations_executed"] == evidence["mutations_rejected"] == 9
    assert evidence["generation_domain"] == "unbounded_natural"
    assert evidence["fixed_width_generation_wraparound_proved"] is False


def test_m89_revocation_fails_closed_without_authority_prerequisite(tmp_path):
    result = verify_capability_revocation(
        tmp_path / "m89_capability_authority.reviewed.json", ROOT)
    assert result["status"] == "M89_AUTHORITY_PREREQUISITE_REQUIRED"
    assert result["claim"] == "NO_PROOF"


def test_m89_server_authority_composition_binds_every_layer():
    evidence = json.loads(
        (KERNEL / "m89_server_authority_composition.validation.json").read_text())
    assert evidence["claim"] == "SERVER_AUTHORITY_SECURITY_MODEL_PROVED"
    assert evidence["verifier_sha256"] == _sha256(
        ROOT / "pipeline/server_authority_composition.py")
    assert [item["id"] for item in evidence["proof_families"]] == [
        "reviewed_grant_confinement", "legal_creation_ancestry",
        "revoked_or_stale_cannot_authorize",
        "unauthorized_route_result_queue_stutter",
        "high_authority_noninterference_except_decision",
        "unrelated_revocation_route_frame",
        "failed_authority_operation_low_stutter"]
    assert evidence["mutations_executed"] == evidence["mutations_rejected"] == 7
    assert evidence["fixed_width_generation_wraparound_proved"] is False
    assert set(evidence["artifact_sha256"]) == {
        "capability_table", "syscalls", "ipc", "scope", "declassification",
        "m88_one_step", "m88_trace", "m88_declassification",
        "m89_authority", "m89_revocation"}


def test_m89_composition_fails_closed_without_bound_prerequisites(tmp_path):
    result = verify_server_authority_composition(tmp_path)
    assert result["status"] == "SERVER_AUTHORITY_COMPOSITION_PREREQUISITE_FAILED"
    assert result["claim"] == "NO_PROOF"


def test_m88_is_frozen_and_m89_exposes_only_parameterized_creation_claims():
    m88 = capability("m88_1_information_flow_scope").milestone
    m89 = capability("m89_1_capability_authority_algebra").milestone
    assert m88 is not None and m89 is not None
    assert m88.step_status == "complete"
    assert m88.current_maturity == "scoped-model-confidentiality-complete"
    assert m89.current_step == 5
    assert m89.current_maturity == "model-authority-security-complete"
    assert m89.completed_claims == (
        "CAPABILITY_AUTHORITY_ALGEBRA_PROVED",
        "CAPABILITY_TOKEN_CREATION_CLOSED_PROVED",
        "CAPABILITY_REVOCATION_SAFETY_PROVED",
        "SERVER_AUTHORITY_SECURITY_MODEL_PROVED")
    assert "CAPABILITY_TOKEN_UNFORGEABILITY_PROVED" in m89.claims_forbidden
    assert "CAPABILITY_TOKEN_UNFORGEABILITY_PROVED" in m89.claims_forbidden
