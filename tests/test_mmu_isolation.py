# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M48: MMU spatial isolation — the frame map gate + lattice lane."""
from __future__ import annotations

import json
from pathlib import Path

from pipeline.mmu_isolation import verify_spatial_isolation

MEMORY_MAP = {
    "kernel_pools": {"kstack_pool": [0x40000000, 0x40010000],
                     "page_tables": [0x40010000, 0x40018000]},
    "dma_windows": {"nic_ring": [0x40020000, 0x40021000]},
    "user_frames": [0x40100000, 0x40200000],
    "page_table_pool": {"capacity": 64},
}
MAPPINGS = [
    {"va": 0x10000, "frame": 0x40100000, "size": 0x1000},
    {"va": 0x11000, "frame": 0x40101000, "size": 0x1000},
    {"va": 0x12000, "frame": 0x401ff000, "size": 0x1000},
]


def test_isolating_map_proves():
    verdict = verify_spatial_isolation(MEMORY_MAP, MAPPINGS)
    assert verdict["status"] == "SPATIAL_ISOLATION_PROVED"
    assert verdict["claim"] == "SPATIAL_ISOLATION_PROVED"
    assert verdict["scope"] == "deterministic_range_disjointness"
    assert verdict["mappings_checked"] == 3
    assert verdict["page_table_pool_capacity"] == 64
    # honest epistemics: the silicon walker is judge_pending
    assert verdict["judge_pending"] == "hardware_page_table_walker"
    assert "never proved here" in verdict["note"]


def test_kernel_memory_mapped_is_the_isolation_break():
    """A user mapping touching a kernel pool (or DMA window) is named
    the worst outcome — isolation is BROKEN, not merely unproven."""
    to_pool = verify_spatial_isolation(
        MEMORY_MAP, [{"va": 0x10000, "frame": 0x4000f000}])
    assert to_pool["code"] == "KERNEL_MEMORY_MAPPED"
    assert to_pool["pool"] == "kstack_pool"
    to_dma = verify_spatial_isolation(
        MEMORY_MAP, [{"va": 0x10000, "frame": 0x40020000}])
    assert to_dma["code"] == "KERNEL_MEMORY_MAPPED"
    assert to_dma["pool"] == "nic_ring"


def test_frame_bounds_double_map_and_exhaustion_refuse():
    outside = verify_spatial_isolation(
        MEMORY_MAP, [{"va": 0, "frame": 0x3ffff000}])   # below region
    assert outside["code"] == "FRAME_OUTSIDE_USER_REGION"
    straddle = verify_spatial_isolation(
        MEMORY_MAP, [{"va": 0, "frame": 0x401ff000, "size": 0x2000}])
    assert straddle["code"] == "FRAME_OUTSIDE_USER_REGION"

    aliased = verify_spatial_isolation(MEMORY_MAP, [
        {"va": 0x10000, "frame": 0x40100000},
        {"va": 0x20000, "frame": 0x40100000}])
    assert aliased["code"] == "FRAME_DOUBLE_MAPPED"
    assert "isolation break" in aliased["message"]

    exhausted = verify_spatial_isolation(
        {**MEMORY_MAP, "page_table_pool": {"capacity": 1}}, MAPPINGS)
    assert exhausted["code"] == "FRAME_EXHAUSTED"
    assert "not a guess" in exhausted["message"]


def test_map_residuals_refuse():
    gate = verify_spatial_isolation
    assert gate({"kernel_pools": {}}, MAPPINGS)["code"] == \
        "memory_map_incomplete"
    assert gate({"kernel_pools": {"k": [0, 1]}}, MAPPINGS)["code"] == \
        "memory_map_incomplete"                    # no user_frames
    assert gate({**MEMORY_MAP, "user_frames": [9, 9]},
                MAPPINGS)["code"] == "memory_map_incomplete"
    no_pool = {k: v for k, v in MEMORY_MAP.items()
               if k != "page_table_pool"}
    assert gate(no_pool, MAPPINGS)["code"] == "memory_map_incomplete"
    bad_range = {**MEMORY_MAP, "kernel_pools": {"k": [9, 1]}}
    assert gate(bad_range, MAPPINGS)["code"] == "memory_map_incomplete"
    assert gate(MEMORY_MAP, [])["code"] == "mappings_missing"
    assert gate(MEMORY_MAP, None)["code"] == "mappings_missing"
    assert gate(MEMORY_MAP, [{"frame": "big"}])["code"] == \
        "mapping_field_missing"
    assert gate(MEMORY_MAP, [{"frame": 0x40100000, "size": 0}])[
        "code"] == "mapping_field_missing"
    assert gate(MEMORY_MAP, [{}])["code"] == "mapping_field_missing"


def test_boot_transcript_fault_paths():
    """The judge's M48 branches: a FAULT line completes the runtime
    sample; MMU_ON without one refuses by name; _fail carries rings."""
    from pipeline.boot_check import parse_transcript
    composition = {"steps": [{"name": "timer_init"},
                             {"name": "pool_init"},
                             {"name": "scheduler_start"},
                             {"name": "net_start"}]}
    with_fault = (GOOD_BOOT + "MMU_ON\n"
                  "FAULT far=0x41000000 ISOLATION_TRAP\nHALT\n")
    verdict = parse_transcript(with_fault, composition)
    assert verdict["status"] == "BOOT_RUNTIME_CONFIRMED"
    assert verdict["mmu_trap_observed"] is True
    assert verdict["rings"]["NET"]["mmu_fault_far"] == "0x41000000"
    bare = GOOD_BOOT + "MMU_ON\nHALT\n"
    refused = parse_transcript(bare, composition)
    assert refused["code"] == "mmu_trap_not_observed"
    assert "incomplete" in refused["message"]
    assert refused["rings"]["NET"]["dropped"] == 9   # flood stands


GOOD_BOOT = """FormalKernel boot (QEMU virt aarch64)
BOOT timer_init
BOOT pool_init
BOOT scheduler_start
BOOT net_start
FLOOD start
NET posted=7 dropped=9 consumed=7 high_water=4 cap=4
SCHED posted=3 picked=3 dropped=0 high_water=3 cap=4
"""


def test_lattice_mmu_lane_residuals(tmp_path):
    """The verify-kernel mmu lane refuses missing/invalid artifacts and
    profiles without a physical map — named, never guessed."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from test_kernel_composition import _kernel, _profile
    from pipeline.kernel_lattice import verify_kernel
    import json
    root = _kernel(tmp_path)
    manifest = json.loads((root / "kernel.json").read_text())
    manifest["mmu"] = "ghost.json"
    (root / "kernel.json").write_text(json.dumps(manifest))
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "mmu_artifact_missing"
    (root / "bad.json").write_text("{nope", encoding="utf-8")
    manifest["mmu"] = "bad.json"
    (root / "kernel.json").write_text(json.dumps(manifest))
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "mmu_artifact_invalid"
    (root / "maps.json").write_text(json.dumps({"mappings": []}),
                                    encoding="utf-8")
    manifest["mmu"] = "maps.json"
    (root / "kernel.json").write_text(json.dumps(manifest))
    # profile has no mmu_map and the artifact has no memory_map
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "profile_field_missing"
    # an empty mappings list is the vacuous refusal
    (root / "maps.json").write_text(
        json.dumps({"memory_map": MEMORY_MAP, "mappings": []}),
        encoding="utf-8")
    assert verify_kernel(root, [_profile(tmp_path)])["failures"][0][
        "code"] == "mappings_missing"
    # and a real isolating map mints the claim for the profile
    (root / "maps.json").write_text(json.dumps(
        {"memory_map": MEMORY_MAP, "mappings": MAPPINGS}), encoding="utf-8")
    bundle = verify_kernel(root, [_profile(tmp_path)])
    assert any(e["claim"] == "SPATIAL_ISOLATION_PROVED"
               for e in bundle.get("claims", []))
