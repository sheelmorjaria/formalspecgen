# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from pipeline import config
from pipeline.capability_registry import capability
from pipeline.judge_evidence import assess_proof_evidence
from pipeline.verus_evidence import assess_verus_evidence, erase_overlay


ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "examples/formalkernel/kernel/verus_smoke"
ALLOCATOR = ROOT / "examples/formalkernel/kernel/verus_allocator"
PRODUCTION = ROOT / "examples/formalkernel/kernel/user/heap.rs"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_verus_qualification_binds_positive_and_negative_judgments():
    evidence = json.loads((SMOKE / "evidence.json").read_text())
    assert evidence["status"] == "VERUS_JUDGE_QUALIFIED"
    assert evidence["positive"]["verified"] == 1
    assert evidence["positive"]["exit_code"] == 0
    assert evidence["anti_vacuity"]["exit_code"] != 0
    assert evidence["anti_vacuity"]["verified"] == 0
    assert evidence["anti_vacuity"]["failure_fingerprint"] == "postcondition not satisfied"
    assert evidence["positive"]["source_sha256"] == _sha256(SMOKE / "preserve.rs")
    assert evidence["anti_vacuity"]["source_sha256"] == _sha256(
        SMOKE / "preserve_mutated.rs")
    assert "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED" in evidence["claims_locked"]


def test_exact_allocator_feasibility_is_explicitly_no_proof():
    evidence = json.loads((ALLOCATOR / "feasibility.json").read_text())
    harness = (ALLOCATOR / "allocator_feasibility.rs").read_text()
    assert evidence["status"] == "NO_PROOF"
    assert evidence["verus_verified_obligations"] == 0
    assert evidence["production_rewritten"] is False
    assert evidence["production_source_sha256"] == _sha256(PRODUCTION)
    assert evidence["harness_sha256"] == _sha256(ALLOCATOR / "allocator_feasibility.rs")
    assert '#[path = "../user/heap.rs"]' in harness
    assert "BOUNDED_ALLOCATOR_FUNCTIONAL_CORRECTNESS_PROVED" in evidence["claims_locked"]


def test_m86_registry_mints_only_judge_qualification():
    milestone = capability("m86_verus_production_modules").milestone
    assert milestone is not None
    assert milestone.current_step == 2
    assert milestone.completed_claims == (
        "VERUS_JUDGE_QUALIFIED", "VERUS_PRODUCTION_OVERLAY_QUALIFIED")
    assert milestone.claims[2].claim == "ITERATOR_TRAVERSAL_SEMANTICS_PROVED"
    assert milestone.claims[3].claim == "GET_MUT_FRAME_SEMANTICS_PROVED"
    assert milestone.claims[4].claim == "OCCUPANCY_COUNT_CORRESPONDENCE_PROVED"
    assert milestone.claims[5].claim == "BOUNDED_ALLOCATOR_FUNCTIONAL_CORRECTNESS_PROVED"
    assert "RUST_IMPLEMENTATION_REFINEMENT_PROVED" in milestone.claims_forbidden


@pytest.mark.skipif(not Path(config.VERUS_BIN).is_file(), reason="pinned Verus unavailable")
def test_pinned_verus_replays_non_vacuous_smoke():
    positive = subprocess.run(
        [config.VERUS_BIN, "--no-cheating", "--output-json", str(SMOKE / "preserve.rs")],
        capture_output=True, text=True, timeout=30, check=False)
    mutation = subprocess.run(
        [config.VERUS_BIN, "--no-cheating", "--output-json",
         str(SMOKE / "preserve_mutated.rs")],
        capture_output=True, text=True, timeout=30, check=False)
    positive_json = json.loads(positive.stdout)
    mutation_json = json.loads(mutation.stdout)
    assert positive.returncode == 0
    assert positive_json["verification-results"]["verified"] == 1
    assert mutation.returncode != 0
    assert mutation_json["verification-results"]["verified"] == 0
    assert "postcondition not satisfied" in mutation.stderr


def test_overlay_erases_to_exact_production_bytes():
    overlay = (ALLOCATOR / "allocator_overlay.rs").read_text()
    assert erase_overlay(overlay).encode() == PRODUCTION.read_bytes()
    evidence = json.loads((ALLOCATOR / "overlay_evidence.json").read_text())
    assert evidence["status"] == "VERUS_PRODUCTION_OVERLAY_QUALIFIED"
    assert evidence["erasure"]["byte_identical"] is True
    assert evidence["erasure"]["erased_sha256"] == _sha256(PRODUCTION)
    assert evidence["erasure"]["implementation_sha256"] == _sha256(
        ROOT / "pipeline/verus_evidence.py")
    assert evidence["overlay_source_sha256"] == _sha256(
        ALLOCATOR / "allocator_overlay.rs")
    assert evidence["obligation_inventory"]["proof_obligations"] > 0
    assert evidence["anti_vacuity"]["mutation_failures"] > 0
    assert evidence["anti_vacuity_policy"]["sha256"] == _sha256(
        ROOT / "pipeline/judge_evidence.py")
    assert evidence["judge"]["qualification_evidence_sha256"] == _sha256(
        SMOKE / "evidence.json")
    assert "allocate" in evidence["excluded_from_claim"]


def test_generic_verus_policy_refuses_each_vacuity_mode():
    qualified = assess_verus_evidence(
        verification_units=1, proof_obligations=1, semantic_postconditions=1,
        mutation_failures=1, overlay_matches=True)
    assert qualified["status"] == "QUALIFIED"
    assert qualified["claim"] == "NO_PROOF"
    cases = (
        ({"verification_units": 0}, "VERUS_ZERO_OBLIGATIONS"),
        ({"proof_obligations": 0}, "VERUS_ZERO_OBLIGATIONS"),
        ({"semantic_postconditions": 0}, "VERUS_SPEC_VACUOUS"),
        ({"mutation_failures": 0}, "VERUS_MUTATION_SURVIVED"),
        ({"overlay_matches": False}, "VERUS_OVERLAY_DRIFT"),
    )
    baseline = dict(verification_units=1, proof_obligations=1,
                    semantic_postconditions=1, mutation_failures=1,
                    overlay_matches=True)
    for change, refusal in cases:
        result = assess_verus_evidence(**(baseline | change))
        assert result["status"] == "NO_PROOF"
        assert refusal in result["refusals"]


def test_system_wide_policy_uses_judge_specific_refusal_prefix():
    result = assess_proof_evidence(
        verification_units=0, proof_obligations=0, semantic_postconditions=0,
        mutation_failures=0, artifact_matches=False, refusal_prefix="ROCQ")
    assert result["status"] == "NO_PROOF"
    assert result["refusals"] == [
        "ROCQ_ARTIFACT_DRIFT", "ROCQ_ZERO_OBLIGATIONS",
        "ROCQ_SPEC_VACUOUS", "ROCQ_MUTATION_SURVIVED"]


@pytest.mark.skipif(not Path(config.VERUS_BIN).is_file(), reason="pinned Verus unavailable")
def test_pinned_verus_replays_exact_overlay_and_constructor_mutation(tmp_path):
    overlay = ALLOCATOR / "allocator_overlay.rs"
    positive = subprocess.run(
        [config.VERUS_BIN, "--no-cheating", "--output-json", str(overlay)],
        capture_output=True, text=True, timeout=30, check=False)
    mutated_text = overlay.read_text().replace(
        "occupied: [false; HEAP_BLOCKS],", "occupied: [true; HEAP_BLOCKS],")
    assert mutated_text != overlay.read_text()
    mutated = tmp_path / "allocator_overlay_mutated.rs"
    mutated.write_text(mutated_text)
    negative = subprocess.run(
        [config.VERUS_BIN, "--no-cheating", "--output-json", str(mutated)],
        capture_output=True, text=True, timeout=30, check=False)
    positive_json = json.loads(positive.stdout)
    assert positive.returncode == 0
    assert positive_json["verification-results"]["verified"] > 0
    assert "allocator_overlay::UserHeap::new" in positive_json["func-details"]
    assert negative.returncode != 0
    assert "postcondition not satisfied" in negative.stderr


def test_allocator_bridge_ledger_names_three_unproved_boundaries():
    bridge_dir = ALLOCATOR / "bridges"
    evidence = json.loads((bridge_dir / "evidence.json").read_text())
    assert evidence["status"] == "NO_PROOF"
    assert evidence["trusted_escape_hatches_used"] is False
    assert [item["id"] for item in evidence["bridges"]] == [
        "iterator_traversal_semantics",
        "get_mut_frame_semantics",
        "occupancy_count_correspondence",
    ]
    for item in evidence["bridges"]:
        assert item["status"] == "NO_PROOF"
        assert item["exit_code"] != 0
        assert item["source_sha256"] == _sha256(bridge_dir / item["source"])
        assert item["claim_locked"] in evidence["claims_locked"]
    assert "assume_specification" in evidence["rejected_shortcuts"]
    assert "BOUNDED_ALLOCATOR_FUNCTIONAL_CORRECTNESS_PROVED" in evidence["claims_locked"]


@pytest.mark.skipif(not Path(config.VERUS_BIN).is_file(), reason="pinned Verus unavailable")
def test_pinned_verus_replays_bridge_refusals():
    bridge_dir = ALLOCATOR / "bridges"
    expected = {
        "iterator_enumerate.rs": "Enumerate` is not supported",
        "get_mut.rs": "get_mut` is not supported",
        "filtered_count.rs": "Filter` is not supported",
    }
    for source, fingerprint in expected.items():
        result = subprocess.run(
            [config.VERUS_BIN, "--no-cheating", "--output-json", str(bridge_dir / source)],
            capture_output=True, text=True, timeout=30, check=False)
        assert result.returncode != 0
        assert fingerprint in result.stderr


@pytest.mark.skipif(not Path(config.VERUS_BIN).is_file(), reason="pinned Verus unavailable")
def test_pinned_verus_replays_virtio_complete_overlay_and_mutation(tmp_path):
    directory = ROOT / "examples/formalkernel/kernel/verus_virtio"
    overlay = directory / "virtio_blk_overlay.rs"
    positive = subprocess.run(
        [config.VERUS_BIN, "--no-cheating", "--output-json", str(overlay)],
        capture_output=True, text=True, timeout=30, check=False)
    mutated_text = overlay.read_text().replace(
        "self.in_flight -= 1;", "self.in_flight -= 0;")
    assert mutated_text != overlay.read_text()
    mutated = tmp_path / "virtio_blk_overlay_mutated.rs"
    mutated.write_text(mutated_text)
    negative = subprocess.run(
        [config.VERUS_BIN, "--no-cheating", "--output-json", str(mutated)],
        capture_output=True, text=True, timeout=30, check=False)
    positive_json = json.loads(positive.stdout)
    assert positive.returncode == 0
    assert positive_json["verification-results"]["verified"] > 0
    assert "virtio_blk_overlay::VirtioBlkAdapter::complete" in positive_json["func-details"]
    assert negative.returncode != 0
    assert "postcondition not satisfied" in negative.stderr
