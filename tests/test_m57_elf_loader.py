# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M57 bounded ELF loader and microkernel-only deployment lane."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.deployment_profile import verify_deployment_profile
from pipeline.elf_loader import verify_elf_load
from pipeline.kernel_lattice import verify_kernel
from pipeline.rust_support import check_rust_syntax, lint_rust


ROOT = Path(__file__).parents[1]
DEMO = ROOT / "examples/formalkernel"
KERNEL = DEMO / "kernel"
PROFILES = [DEMO / "profiles/n150.json", DEMO / "profiles/r52.json"]


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _artifact() -> dict:
    return _json(KERNEL / "elf_loader.json")


def _map() -> dict:
    return _json(PROFILES[0])["mmu_map"]


def test_declared_elf_plan_proves_layout_permissions_and_spatial_scope():
    for profile in PROFILES:
        verdict = verify_elf_load(_artifact(), _json(profile)["mmu_map"])
        assert verdict["status"] == "ELF_LOAD_PROVED"
        assert verdict["segments_checked"] == 2
        assert verdict["judge_pending"] == "hardware_page_table_walker_and_eret"


def test_gate_refuses_unbounded_ambiguous_or_unsafe_elf_shapes():
    cases = []
    bad = _artifact()
    bad["elf_header"]["magic"] = "00"
    cases.append((bad, "ELF_HEADER_UNSUPPORTED"))
    bad = _artifact()
    bad["segments"][0]["flags"] = 7
    cases.append((bad, "ELF_WX_VIOLATION"))
    bad = _artifact()
    bad["segments"][0]["uxn"] = True
    cases.append((bad, "ELF_PERMISSION_MISMATCH"))
    bad = _artifact()
    bad["elf_header"]["entry"] = 69632
    cases.append((bad, "ELF_ENTRY_NOT_EXECUTABLE"))
    bad = _artifact()
    bad["segments"][1]["va"] = 65536
    cases.append((bad, "ELF_SEGMENT_OVERLAP"))
    bad = _artifact()
    bad["segments"][0]["file_size"] = bad["file_size"]
    cases.append((bad, "ELF_SEGMENT_SIZE_INVALID"))
    bad = _artifact()
    bad["segments"] = bad["segments"] * 3
    cases.append((bad, "ELF_SEGMENT_BOUND_EXCEEDED"))
    for artifact, code in cases:
        verdict = verify_elf_load(artifact, _map())
        assert verdict["claim"] == "NO_PROOF"
        assert verdict["code"] == code


def test_gate_names_remaining_header_segment_and_spatial_refusals():
    cases = []
    bad = _artifact(); bad["max_load_segments"] = 0
    cases.append((bad, "ELF_SEGMENT_BOUND_INVALID"))
    bad = _artifact(); bad["file_size"] = 0
    cases.append((bad, "ELF_HEADER_INVALID"))
    bad = _artifact(); del bad["segments"][0]["frame"]
    cases.append((bad, "ELF_SEGMENT_FIELD_MISSING"))
    bad = _artifact(); bad["segments"][0]["frame"] = True
    cases.append((bad, "ELF_SEGMENT_FIELD_INVALID"))
    bad = _artifact(); bad["segments"][0]["file_size"] = 1024; bad["segments"][0]["memory_size"] = 2048
    cases.append((bad, "ELF_SEGMENT_UNALIGNED"))
    bad = _artifact(); bad["segments"][0]["flags"] = 8
    cases.append((bad, "ELF_FLAGS_INVALID"))
    bad = _artifact(); bad["segments"][0]["frame"] = 1
    cases.append((bad, "FRAME_OUTSIDE_USER_REGION"))
    for artifact, code in cases:
        assert verify_elf_load(artifact, _map())["code"] == code


def test_rust_loader_is_bounded_panic_free_and_statically_checked():
    source = (KERNEL / "loader/elf_loader.rs").read_text(encoding="utf-8")
    assert "MAX_LOAD_SEGMENTS: usize = 4" in source
    assert check_rust_syntax(source)["status"] == "RUST_CHECKED"
    assert not [item for item in lint_rust(source) if item["severity"] == "error"]
    assert _artifact()["source_sha256"] == hashlib.sha256(source.encode()).hexdigest()
    for forbidden in ("unsafe", ".unwrap(", ".expect(", "panic!(", "todo!("):
        assert forbidden not in source


def test_loader_is_a_microkernel_only_boundary_lane():
    monolith = _json(KERNEL / "monolith.json")
    contradiction = verify_deployment_profile({**monolith,
                                               "elf_loader": "elf_loader.json"})
    assert contradiction["code"] == "MONOLITH_BOUNDARY_CONTRADICTION"
    assert "elf_loader" not in monolith


def test_kernel_bundles_diverge_honestly_at_the_loader_boundary():
    micro = verify_kernel(KERNEL, PROFILES)
    mono = verify_kernel(KERNEL, PROFILES, "monolith.json")
    assert micro["status"] == mono["status"] == "KERNEL_EVIDENCE_BUNDLE"
    micro_claims = {item["claim"] for item in micro["claims"]}
    mono_claims = {item["claim"] for item in mono["claims"]}
    assert "ELF_SEGMENT_LAYOUT_PROVED" in micro_claims
    assert "ELF_PERMISSION_CORRESPONDENCE_PROVED" in micro_claims
    assert "ELF_SEGMENT_LAYOUT_PROVED" not in mono_claims
    assert any(item["claim"] == "EL0_PROCESS_LOADER_OMITTED"
               for item in mono["boundaries"])


def test_registry_keeps_silicon_and_eret_above_the_evidence_ceiling():
    lane = capability("m57_elf_loader").milestone
    assert lane is not None and lane.step_status == "complete"
    assert lane.deployment_profiles == ("microkernel",)
    assert "HARDWARE_PAGE_TABLE_WALK_PROVED" in lane.claims_forbidden
    assert "HARDWARE_EXCEPTION_LEVEL_TRANSITION_PROVED" in lane.claims_forbidden
