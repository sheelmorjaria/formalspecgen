# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M64: hash-bound fixed-capacity EL0 heap."""
import hashlib
import json
from pathlib import Path

import pytest
from pipeline.capability_registry import capability
from pipeline.kani_refinement import KANI_AVAILABLE
from pipeline.kernel_lattice import verify_kernel

ROOT = Path(__file__).parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"
PROFILES = [ROOT / "examples/formalkernel/profiles/n150.json",
            ROOT / "examples/formalkernel/profiles/r52.json"]


def test_heap_artifact_binds_exact_rust_and_kani_harness():
    artifact = json.loads((KERNEL / "user_heap.json").read_text())
    source = KERNEL / artifact["source"]
    proof = (KERNEL / artifact["proof_source"]).resolve()
    assert hashlib.sha256(source.read_bytes()).hexdigest() == artifact["source_sha256"]
    assert hashlib.sha256(proof.read_bytes()).hexdigest() == artifact["proof_sha256"]
    assert artifact["heap_blocks"] * artifact["block_bytes"] == artifact["heap_bytes"] == 4096


@pytest.mark.skipif(not KANI_AVAILABLE, reason="Kani not installed")
def test_microkernel_mints_heap_and_monolith_records_omission():
    micro = verify_kernel(KERNEL, PROFILES)
    heap = next(item for item in micro["claims"]
                if item["claim"] == "USER_HEAP_CAPACITY_PROVED")
    assert heap["judge"] == "kani"
    assert heap["evidence"]["heap_bytes"] == 4096
    assert heap["evidence"]["physical_frame_assignment_proved"] is False
    mono = verify_kernel(KERNEL, PROFILES, "monolith.json")
    assert not any(item["claim"] == "USER_HEAP_CAPACITY_PROVED"
                   for item in mono["claims"])
    assert any(item["claim"] == "EL0_USER_HEAP_OMITTED"
               for item in mono["boundaries"])


def test_registry_keeps_physical_and_general_allocator_claims_forbidden():
    lane = capability("m64_user_heap").milestone
    assert lane is not None and lane.required_judges == ("Kani",)
    assert "PHYSICAL_USER_HEAP_MAPPING_PROVED" in lane.claims_forbidden
    assert "GENERAL_PURPOSE_ALLOCATOR_PROVED" in lane.claims_forbidden
