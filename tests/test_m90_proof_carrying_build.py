# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.proof_carrying_build import (
    _hash_json,
    build_evidence_root_candidate,
    validate_evidence_root_candidate,
)


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"
CANDIDATE = KERNEL / "m90_evidence_root.candidate.json"
BUNDLE = KERNEL / "m90_kernel_evidence_bundle.json"
PROFILES = [ROOT / "examples/formalkernel/profiles/n150.json",
            ROOT / "examples/formalkernel/profiles/r52.json"]


def _candidate():
    return json.loads(CANDIDATE.read_text())


def test_m90_candidate_is_canonical_non_claiming_and_reproducible():
    stored = _candidate()
    regenerated = build_evidence_root_candidate(
        ROOT, BUNDLE, KERNEL / "kernel.json", PROFILES)
    assert regenerated == stored
    assert stored["status"] == "EVIDENCE_ROOT_CANDIDATE"
    assert stored["claim"] == "NO_PROOF"
    assert stored["binary_status"] == "BINARY_BUILD_PENDING"
    assert stored["binary_sha256"] is None
    assert len(stored["claim_entries"]) == 80
    assert len(stored["source_files"]) == 19
    assert stored["human_promotions"]
    assert stored["local_tool_patches"]


def test_m90_candidate_validates_every_available_dependency():
    result = validate_evidence_root_candidate(_candidate(), ROOT)
    assert result == {
        "status": "EVIDENCE_ROOT_CANDIDATE_VALIDATED",
        "claim": "NO_PROOF", "claim_entries": 80, "source_files": 19}


def test_m90_stale_source_and_bundle_hashes_fail_closed():
    stale_source = _candidate()
    stale_source["source_files"][0]["sha256"] = "0" * 64
    assert validate_evidence_root_candidate(stale_source, ROOT)["status"] == (
        "EVIDENCE_ROOT_DEPENDENCY_STALE")
    stale_bundle = _candidate()
    stale_bundle["evidence_bundle"]["sha256"] = "0" * 64
    assert validate_evidence_root_candidate(stale_bundle, ROOT)["status"] == (
        "EVIDENCE_ROOT_DEPENDENCY_STALE")


def test_m90_claim_promotion_and_forbidden_claim_insertion_are_rejected():
    inflated = _candidate()
    inflated["binary_status"] = "BINARY_BUILD_PENDING"
    inflated["binary_sha256"] = "a" * 64
    assert validate_evidence_root_candidate(inflated, ROOT)["status"] == (
        "EVIDENCE_ROOT_BINARY_BOUNDARY_INVALID")
    forbidden = _candidate()
    forbidden["claim_entries"][0]["claim"] = (
        "CAPABILITY_TOKEN_UNFORGEABILITY_PROVED")
    forbidden["claim_graph_hash"] = _hash_json(forbidden["claim_entries"])
    assert validate_evidence_root_candidate(forbidden, ROOT)["status"] == (
        "EVIDENCE_ROOT_FORBIDDEN_CLAIM")


def test_m90_judge_change_and_deleted_promotion_are_detected():
    judge = _candidate()
    bound = next(item for item in judge["judge_versions"]
                 if item.get("resolved_executable") and item.get("executable_sha256"))
    bound["executable_sha256"] = "0" * 64
    judge["judge_manifest_hash"] = _hash_json(judge["judge_versions"])
    assert validate_evidence_root_candidate(judge, ROOT)["status"] == (
        "EVIDENCE_ROOT_JUDGE_REPLAY_REQUIRED")
    promotion = _candidate()
    promotion["human_promotions"].pop()
    assert validate_evidence_root_candidate(promotion, ROOT)["status"] == (
        "EVIDENCE_ROOT_PROMOTION_INVENTORY_STALE")


def test_m90_registry_keeps_binary_and_semantic_claims_locked():
    milestone = capability("m90_1_canonical_evidence_manifest").milestone
    assert milestone is not None
    assert milestone.current_step == 1
    assert milestone.current_maturity == "canonical-evidence-manifest"
    assert milestone.completed_claims == ()
    assert "PROOF_CARRYING_BINARY_VALIDATED" in {
        stage.claim for stage in milestone.claims}
    assert "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED" in milestone.claims_forbidden
