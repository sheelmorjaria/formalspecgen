# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path

from pipeline import config
from pipeline.capability_registry import capability
from pipeline.verus_evidence import erase_overlay
from pipeline.verus_feasibility import (
    discover_production_rust,
    rank_verus_candidates,
    scan_verus_feasibility,
)
from pipeline.virtio_queue_model import validate_queue_model


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"
REPORT = KERNEL / "verus_m86_2_feasibility.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_discovery_excludes_verifier_only_rust():
    paths = [path.relative_to(ROOT).as_posix() for path in discover_production_rust(KERNEL)]
    assert paths == [
        "examples/formalkernel/kernel/loader/elf_loader.rs",
        "examples/formalkernel/kernel/net/pq_tls_pool.rs",
        "examples/formalkernel/kernel/user/heap.rs",
        "examples/formalkernel/kernel/vfs/virtio_blk.rs",
    ]


def test_scanner_reads_verus_boundary_ledger(monkeypatch, tmp_path):
    source = tmp_path / "candidate.rs"
    source.write_text("fn f(a: &mut [bool]) { let _ = a.get_mut(0); }\n")
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps({"bridges": [
        {"id": "get_mut_frame_semantics", "status": "NO_PROOF"}]}))
    monkeypatch.setattr(config, "VERUS_BOUNDARY_LEDGER", str(ledger))
    report = scan_verus_feasibility(source)
    finding = next(item for item in report["findings"]
                   if item["construct"] == "get_mut_frame_semantics")
    assert finding["classification"] == "KNOWN_BLOCKED"
    assert finding["boundary_status"] == "NO_PROOF"
    assert report["claim"] == "NO_PROOF"


def test_ranking_rewards_real_scalar_state_over_known_blockers():
    candidates = [
        (KERNEL / "vfs/virtio_blk.rs", 95, None),
        (KERNEL / "user/heap.rs", 80, "examples/formalkernel/kernel/user_heap.json"),
    ]
    ranked = rank_verus_candidates(candidates)
    assert ranked[0]["source"].endswith("virtio_blk.rs")
    assert ranked[0]["score"] > ranked[1]["score"]
    assert ranked[0]["claim"] == "NO_PROOF"


def test_m86_2_report_is_hash_bound_and_names_missing_m77_implementation():
    report = json.loads(REPORT.read_text())
    assert report["status"] == "NO_PROOF"
    assert report["m77_assessment"]["production_rust_implementation_found"] is False
    assert report["selected_candidate"]["operation"] == "VirtioBlkAdapter::complete"
    assert report["scanner_sha256"] == _sha256(ROOT / report["scanner"])
    assert report["boundary_ledger_sha256"] == _sha256(ROOT / report["boundary_ledger"])
    for candidate in report["ranked_candidates"]:
        assert candidate["source_sha256"] == _sha256(ROOT / candidate["source"])
    assert "VM_ACCOUNTING_IMPLEMENTATION_CORRECTNESS_PROVED" in report["claims_locked"]


def test_m86_2_registry_records_reviewed_model_bridge():
    milestone = capability("m86_2_verus_production_coverage").milestone
    assert milestone is not None
    assert milestone.current_step == 4
    assert milestone.completed_claims == (
        "VERUS_VIRTIO_BLK_OVERLAY_QUALIFIED",
        "VIRTIO_QUEUE_ACCOUNTING_IMPLEMENTATION_CORRECTNESS_PROVED",
        "VIRTIO_QUEUE_MODEL_BRIDGE_PROVED")
    assert milestone.claims[0].claim == "VERUS_VIRTIO_BLK_OVERLAY_QUALIFIED"
    assert "VM_ACCOUNTING_IMPLEMENTATION_CORRECTNESS_PROVED" in milestone.claims_forbidden
    assert "DRIVER_DEVICE_BEHAVIOR_PROVED" in milestone.claims_forbidden
    assert "EXTERNAL_IO_SAFETY_PROVED" in milestone.claims_forbidden


def test_virtio_overlay_erases_exactly_and_has_real_complete_obligations():
    directory = KERNEL / "verus_virtio"
    overlay = directory / "virtio_blk_overlay.rs"
    production = KERNEL / "vfs/virtio_blk.rs"
    evidence = json.loads((directory / "evidence.json").read_text())
    assert erase_overlay(overlay.read_text()).encode() == production.read_bytes()
    assert evidence["status"] == "VERUS_VIRTIO_BLK_OVERLAY_QUALIFIED"
    assert evidence["overlay_source_sha256"] == _sha256(overlay)
    assert evidence["erasure"]["erased_sha256"] == _sha256(production)
    assert evidence["obligation_inventory"]["proof_obligations"] == 12
    assert evidence["obligation_inventory"]["semantic_postconditions"] == 11
    assert evidence["anti_vacuity"]["mutation_failures"] == 1
    assert evidence["trusted_escape_hatches_used"] is False
    assert "VIRTIO_QUEUE_MODEL_BRIDGE_PROVED" in evidence["claims_locked"]


def test_virtio_functional_evidence_binds_full_mutation_closure():
    directory = KERNEL / "verus_virtio"
    evidence = json.loads((directory / "functional_evidence.json").read_text())
    mutations = json.loads((directory / "mutation_suite.json").read_text())
    assert evidence["status"] == "VIRTIO_QUEUE_ACCOUNTING_IMPLEMENTATION_CORRECTNESS_PROVED"
    assert evidence["mutation_suite_sha256"] == _sha256(directory / "mutation_suite.json")
    assert mutations["executed"] == mutations["rejected"] == 6
    assert mutations["survived"] == 0
    assert {item["id"] for item in mutations["mutations"]} == {
        "bad_constructor", "submit_no_increment", "queue_full_returns_success",
        "complete_no_decrement", "empty_complete_returns_success",
        "weakened_submit_model"}
    assert evidence["trusted_escape_hatches_used"] is False
    envelope = evidence["common_judge_envelope"]
    assert envelope["verification_units"] > 0
    assert envelope["semantic_obligations"] > 0
    assert envelope["negative_mutations_executed"] == envelope[
        "negative_mutations_rejected"] == 6
    assert envelope["artifact_identity_verified"] is True
    assert envelope["trusted_assumptions"]
    assert "VIRTIO_QUEUE_MODEL_BRIDGE_PROVED" in evidence["claims_locked"]


def test_virtio_model_bridge_binds_human_accepted_artifact():
    evidence = json.loads((KERNEL / "verus_virtio/model_bridge.json").read_text())
    reviewed = KERNEL / "verus_virtio/queue_model.reviewed.json"
    assert evidence["status"] == "VIRTIO_QUEUE_MODEL_BRIDGE_PROVED"
    assert evidence["claim"] == "VIRTIO_QUEUE_MODEL_BRIDGE_PROVED"
    assert evidence["scope"] == "production_virtio_blk_queue_accounting"
    assert evidence["reviewed_model_sha256"] == _sha256(reviewed)
    assert evidence["anti_vacuity"]["executed"] == 6
    assert evidence["anti_vacuity"]["rejected"] == 6
    assert "EXTERNAL_IO_SAFETY_PROVED" in evidence["claims_locked"]


def test_virtio_queue_candidate_is_hash_bound_and_structurally_validated():
    directory = KERNEL / "verus_virtio"
    candidate = json.loads((directory / "queue_model.candidate.json").read_text())
    validation = json.loads((directory / "queue_model.validation.json").read_text())
    reviewed = json.loads((directory / "queue_model.reviewed.json").read_text())
    assert validation["status"] == "VALIDATED_CANDIDATE"
    assert validation["claim"] == "NO_PROOF"
    assert validation["candidate_sha256"] == _sha256(
        directory / "queue_model.candidate.json")
    assert reviewed["human_review"]["accepted_candidate_sha256"] == (
        validation["candidate_sha256"])
    assert candidate["state_relation"] == (
        "model.outstanding == rust.queue_depth()")
    assert candidate["human_review"]["accepted"] is False
    assert reviewed["human_review"]["accepted"] is True
    assert validation["bridge_claim_eligible"] is False


def test_virtio_queue_validator_rejects_a_wrong_submit_relation(tmp_path):
    candidate = json.loads(
        (KERNEL / "verus_virtio/queue_model.candidate.json").read_text())
    candidate["operations"]["submit"][0]["post"] = 0
    mutated = tmp_path / "wrong_queue_model.json"
    mutated.write_text(json.dumps(candidate))
    result = validate_queue_model(mutated)
    assert result["status"] == "MODEL_VALIDATION_FAILED"
    assert result["claim"] == "NO_PROOF"
    assert "SUBMIT_RELATION_MISMATCH" in result["errors"]
