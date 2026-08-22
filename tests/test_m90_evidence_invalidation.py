# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.evidence_invalidation import (
    build_dependency_graph,
    evaluate_invalidation,
    qualify_invalidation_semantics,
)
from pipeline.proof_carrying_build import _hash_json


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"
EVIDENCE = KERNEL / "m90_binary_evidence.json"
VALIDATION = KERNEL / "m90_invalidation.validation.json"


def _binary():
    return json.loads(EVIDENCE.read_text())


def _validation():
    return json.loads(VALIDATION.read_text())


def test_qualification_is_reproducible_and_all_negative_cases_pass():
    stored = _validation()
    assert qualify_invalidation_semantics(_binary(), ROOT) == stored
    assert stored["status"] == "EVIDENCE_INVALIDATION_SEMANTICS_VALIDATED"
    assert stored["claims_minted"] == [
        "EVIDENCE_DEPENDENCY_CLOSURE_VALIDATED",
        "EVIDENCE_INVALIDATION_SEMANTICS_VALIDATED",
    ]
    assert all(item["passed"] for item in stored["mutation_results"])


def test_baseline_is_valid_and_unused_changes_are_ignored():
    graph = build_dependency_graph(_binary(), ROOT)
    baseline = evaluate_invalidation(graph)
    assert baseline["root_status"]["status"] == "VALID"
    assert {item["status"] for item in baseline["claim_statuses"].values()} == {"VALID"}

    unrelated = evaluate_invalidation(graph, observed_digests={
        "artifact:examples/formalkernel/kernel/vfs/Vfs.rs": "0" * 64,
        "artifact:examples/formalkernel/profiles/n150.json": "0" * 64,
    })
    assert unrelated["root_status"]["status"] == "VALID"
    assert len(unrelated["ignored_changes"]) == 2


def test_source_and_judge_invalidation_is_claim_minimal_and_causal():
    graph = build_dependency_graph(_binary(), ROOT)
    source = evaluate_invalidation(graph, observed_digests={
        "artifact:examples/formalkernel/boot/src/witness.rs": "0" * 64})
    assert source["claim_statuses"]["RUST_WITNESS_REFINEMENT_PROVED"]["status"] == (
        "STALE_SOURCE")
    assert source["claim_statuses"]["SYSTEM_COMPOSITION_PROVED"]["status"] == "VALID"
    cause = source["claim_statuses"]["RUST_WITNESS_REFINEMENT_PROVED"]["causes"][0]
    assert cause["dependency"].endswith("witness.rs")
    assert cause["old"] != cause["new"]

    judge = evaluate_invalidation(graph, observed_digests={"judge:Kani": "0" * 64})
    assert judge["claim_statuses"]["RUST_WITNESS_REFINEMENT_PROVED"]["status"] == (
        "REPLAY_REQUIRED")
    assert judge["claim_statuses"]["SYSTEM_COMPOSITION_PROVED"]["status"] == "VALID"


def test_reviewed_model_change_invalidates_only_the_dependent_claim():
    graph = copy.deepcopy(build_dependency_graph(_binary(), ROOT))
    reviewed_id = "artifact:examples/formalkernel/kernel/verus_virtio/queue_model.reviewed.json"
    graph["nodes"].append({"id": reviewed_id, "kind": "reviewed_model",
                           "digest": "a" * 64, "path": reviewed_id.removeprefix("artifact:"),
                           "claim": "RUST_WITNESS_REFINEMENT_PROVED"})
    graph["nodes"].sort(key=lambda item: item["id"])
    graph["edges"].append(["claim:RUST_WITNESS_REFINEMENT_PROVED", reviewed_id])
    graph["edges"].sort()
    graph["graph_digest"] = _hash_json({"nodes": graph["nodes"], "edges": graph["edges"]})
    result = evaluate_invalidation(graph, observed_digests={reviewed_id: "b" * 64})
    assert result["claim_statuses"]["RUST_WITNESS_REFINEMENT_PROVED"]["status"] == (
        "HUMAN_REVIEW_REQUIRED")
    assert result["claim_statuses"]["SYSTEM_COMPOSITION_PROVED"]["status"] == "VALID"


def test_removed_transitive_edge_and_forbidden_claim_fail_hard():
    graph = copy.deepcopy(build_dependency_graph(_binary(), ROOT))
    graph["edges"].pop()
    incomplete = evaluate_invalidation(graph)
    assert incomplete["root_status"]["status"] == "DEPENDENCY_UNPROVED"
    assert incomplete["root_status"]["causes"][0]["dependency"] == "dependency_graph"

    graph = build_dependency_graph(_binary(), ROOT)
    forbidden = evaluate_invalidation(
        graph, injected_claims=["TARGET_BINARY_FUNCTIONAL_CORRECTNESS_PROVED"],
        forbidden_claims=["TARGET_BINARY_FUNCTIONAL_CORRECTNESS_PROVED"])
    assert forbidden["root_status"]["status"] == "FORBIDDEN"


def test_prebuild_inventory_drift_downgrades_root_but_not_local_claims():
    graph = build_dependency_graph(_binary(), ROOT)
    result = evaluate_invalidation(graph, observed_digests={
        "artifact:examples/formalkernel/kernel/m90_evidence_root.candidate.json": "0" * 64})
    assert result["root_status"]["status"] == "CANONICAL_ROOT_REGENERATION_REQUIRED"
    assert {item["status"] for item in result["claim_statuses"].values()} == {"VALID"}


def test_m90_3_registry_uses_validation_not_semantic_proof_wording():
    milestone = capability("m90_3_evidence_invalidation").milestone
    assert milestone is not None
    assert milestone.current_step == 3
    assert milestone.completed_claims == (
        "EVIDENCE_DEPENDENCY_CLOSURE_VALIDATED",
        "EVIDENCE_INVALIDATION_SEMANTICS_VALIDATED",
    )
    assert "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED" in milestone.claims_forbidden
