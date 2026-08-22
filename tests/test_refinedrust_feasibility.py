# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path

from pipeline import refinedrust_feasibility
from pipeline.refinedrust_feasibility import (rank_refinedrust_candidates,
                                              scan_refinedrust_feasibility)


KERNEL = Path("examples/formalkernel/kernel")
REPORT = KERNEL / "refinement/refinedrust_feasibility_report.json"


def _constructs(report: dict) -> set[str]:
    return {item["construct"] for item in report["findings"]}


def test_known_allocator_boundaries_are_classified_without_a_claim():
    report = scan_refinedrust_feasibility(KERNEL / "user/heap.rs")
    assert report["classification"] == "KNOWN_BLOCKED"
    assert report["claim"] == "NO_PROOF"
    assert {
        "named_const_array_len",
        "iterator_enumerate",
        "slice_get_or_get_mut",
    } <= _constructs(report)
    assert len(report["source_sha256"]) == 64


def test_scalar_adapter_now_inherits_open_result_try_boundary():
    report = scan_refinedrust_feasibility(KERNEL / "vfs/virtio_blk.rs")
    assert report["classification"] == "KNOWN_BLOCKED"
    assert "direct_scalar_field_mutation" in _constructs(report)
    assert "trait_or_generic" in _constructs(report)
    assert next(item for item in report["findings"]
                if item["construct"] == "result_try_branch")["boundary_status"] == "OPEN"


def test_candidate_ranking_selects_existing_scalar_adapter_first():
    candidates = rank_refinedrust_candidates([
        KERNEL / "user/heap.rs",
        KERNEL / "net/pq_tls_pool.rs",
        KERNEL / "loader/elf_loader.rs",
        KERNEL / "vfs/virtio_blk.rs",
    ])
    assert candidates[0]["source"].endswith("vfs/virtio_blk.rs")
    assert candidates[0]["claim"] == "NO_PROOF"


def test_unknown_empty_source_remains_non_evidentiary(tmp_path: Path):
    source = tmp_path / "empty.rs"
    source.write_text("pub fn marker() {}\n")
    report = scan_refinedrust_feasibility(source)
    assert report["classification"] == "UNKNOWN"
    assert report["findings"] == []


def test_report_records_real_probe_and_updated_boundary_classification():
    report = json.loads(REPORT.read_text())
    first = report["ranked_candidates"][0]
    assert report["claim"] == "NO_PROOF"
    assert first["static_classification"] == "KNOWN_BLOCKED"
    assert first["probe_result"] == "KNOWN_BLOCKED"
    assert "core::result::branch" in first["diagnostic"]
    assert report["eligible_production_primitive_found"] is False
    assert report["primitive_implementation_refinement_proved"] is False


def test_probe_overlay_erases_to_exact_virtio_production_source():
    report = json.loads(REPORT.read_text())
    overlay_path = Path(report["exact_probe_overlay"]["source"])
    overlay = overlay_path.read_text().splitlines(keepends=True)
    erased = "".join(
        line for line in overlay
        if not line.lstrip().startswith("#![rr::")
        and not line.lstrip().startswith("#[rr::")
        and not line.startswith("#![feature(")
        and not line.startswith("#![register_tool(")
    )
    production = (KERNEL / "vfs/virtio_blk.rs").read_text()
    assert erased == production
    assert report["exact_probe_overlay"]["source_sha256"] == hashlib.sha256(
        overlay_path.read_bytes()).hexdigest()
    assert report["exact_probe_overlay"]["ghost_erasure_byte_identical"] is True


def test_report_keeps_every_broad_refinement_claim_false():
    report = json.loads(REPORT.read_text())
    assert report["rust_implementation_refinement_proved"] is False
    assert report["compiler_refinement_chain_proved"] is False
    assert report["end_to_end_refinement_chain_established"] is False


def test_scanner_reacts_when_a_boundary_is_qualified(monkeypatch, tmp_path: Path):
    ledger = tmp_path / "boundaries.json"
    ledger.write_text(json.dumps({"boundaries": [
        {"id": "result_try_branch", "status": "QUALIFIED_SUPPORTED"},
        {"id": "generic_local_trait_impl_registration",
         "status": "QUALIFIED_SUPPORTED"},
    ]}))
    monkeypatch.setattr(refinedrust_feasibility.config,
                        "REFINEDRUST_BOUNDARY_LEDGER", str(ledger))
    report = scan_refinedrust_feasibility(KERNEL / "vfs/virtio_blk.rs")
    assert report["classification"] == "LIKELY_SUPPORTED"
    assert all(item["classification"] != "KNOWN_BLOCKED"
               for item in report["findings"])


def test_scanner_fails_to_static_defaults_for_malformed_ledger(monkeypatch, tmp_path: Path):
    ledger = tmp_path / "bad.json"
    ledger.write_text("not-json")
    monkeypatch.setattr(refinedrust_feasibility.config,
                        "REFINEDRUST_BOUNDARY_LEDGER", str(ledger))
    report = scan_refinedrust_feasibility(KERNEL / "user/heap.rs")
    assert report["classification"] == "KNOWN_BLOCKED"
    assert all(item["boundary_status"] == "UNTRACKED" for item in report["findings"])
