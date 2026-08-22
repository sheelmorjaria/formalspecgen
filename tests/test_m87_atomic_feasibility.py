# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path

from pipeline.atomic_feasibility import scan_atomic_production


ROOT = Path(__file__).resolve().parents[1]
FORMALKERNEL = ROOT / "examples/formalkernel"
REPORT = ROOT / "examples/formalkernel/kernel/m87_atomic_feasibility.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_exact_production_tree_has_no_atomic_transition_to_refine():
    scan = scan_atomic_production(FORMALKERNEL)
    report = json.loads(REPORT.read_text())
    assert scan["status"] == "PARKED_NO_PRODUCTION_ATOMIC_TRANSITION"
    assert scan["claim"] == "NO_PROOF"
    assert scan["eligible_candidates"] == []
    assert scan["scanned_source_count"] == report["scan_result"]["scanned_source_count"]
    assert all(not item["atomic_types"] for item in scan["sources"])
    assert report["scanner_sha256"] == _sha256(ROOT / report["scanner"])
    assert len(report["production_source_bindings"]) == scan["scanned_source_count"]
    for binding in report["production_source_bindings"]:
        assert binding["sha256"] == _sha256(ROOT / binding["source"])


def test_m61_litmus_evidence_remains_explicitly_unbound_to_rust():
    report = json.loads(REPORT.read_text())
    boundary = report["m61_boundary"]
    assert boundary["manifest_sha256"] == _sha256(
        ROOT / boundary["manifest"])
    assert boundary["x86_litmus_sha256"] == _sha256(
        ROOT / "examples/formalkernel/kernel/weak_memory/x86_message_passing.litmus")
    assert boundary["aarch64_litmus_sha256"] == _sha256(
        ROOT / "examples/formalkernel/kernel/weak_memory/aarch64_message_passing.litmus")
    assert boundary["source_atomic_binding_exists"] is False
    assert boundary["compiled_lowering_binding_exists"] is False
    assert "WEAK_MEMORY_IMPLEMENTATION_REFINEMENT_PROVED" in report["claims_locked"]


def test_scanner_detects_explicit_ordered_atomic_candidate(tmp_path):
    source = tmp_path / "atomic.rs"
    source.write_text(
        "use core::sync::atomic::{AtomicBool, Ordering};\n"
        "fn publish(flag: &AtomicBool) { flag.store(true, Ordering::Release); }\n")
    scan = scan_atomic_production(tmp_path)
    assert scan["status"] == "ATOMIC_PRODUCTION_CANDIDATE_FOUND"
    assert len(scan["eligible_candidates"]) == 1
    candidate = scan["eligible_candidates"][0]
    assert candidate["atomic_types"] == ["AtomicBool"]
    assert candidate["memory_orderings"] == ["Release"]
