# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M49: the syscall boundary — dispatch table as a deterministic gate."""
from __future__ import annotations

import json
from pathlib import Path

from pipeline.syscall_boundary import verify_syscall_boundary

ARTIFACT = {
    "memory_map": {
        "kernel_pools": {"kstack_pool": [0x40000000, 0x40010000],
                         "page_tables": [0x40010000, 0x40018000]},
        "dma_windows": {"nic_ring": [0x40020000, 0x40021000]},
        "user_frames": [0x42000000, 0x42200000],
        "page_table_pool": {"capacity": 64},
    },
    "user_image": {"start": 0x42000000, "end": 0x42001000},
    "kernel_resources": {"uart0": [0x09000000, 0x09001000]},
    "syscalls": [
        {"id": 100, "name": "write_console", "handler": "sys_write_console",
         "resources": ["uart0"]},
    ],
}


def test_boundary_table_proves():
    verdict = verify_syscall_boundary(ARTIFACT)
    assert verdict["status"] == "SYSCALL_BOUNDARY_PROVED"
    assert verdict["claim"] == "SYSCALL_BOUNDARY_PROVED"
    assert verdict["scope"] == "deterministic_dispatch_table"
    assert verdict["syscalls_checked"] == 1
    assert verdict["user_image"] == [0x42000000, 0x42001000]
    # honest epistemics: the silicon EL1<->EL0 transition is judge_pending
    assert verdict["judge_pending"] == "hardware_exception_level_transition"
    assert "never proved here" in verdict["note"]


def test_user_image_overlap_is_the_worst_outcome():
    """A user image inside kernel memory (pools, DMA windows, or declared
    kernel resources) is named the isolation break, before placement."""
    into_pool = verify_syscall_boundary({
        **ARTIFACT, "user_image": {"start": 0x4000F000, "end": 0x40010000}})
    assert into_pool["code"] == "USER_IMAGE_OVERLAPS_KERNEL"
    assert into_pool["pool"] == "kstack_pool"
    into_res = verify_syscall_boundary({
        **ARTIFACT, "user_image": {"start": 0x09000000, "end": 0x09001000}})
    assert into_res["code"] == "USER_IMAGE_OVERLAPS_KERNEL"
    assert into_res["pool"] == "uart0"
    outside = verify_syscall_boundary({
        **ARTIFACT, "user_image": {"start": 0x41000000, "end": 0x41001000}})
    assert outside["code"] == "USER_IMAGE_OUTSIDE_USER_FRAMES"


def test_dispatch_defects_refuse():
    dup = {**ARTIFACT, "syscalls": ARTIFACT["syscalls"] + [
        {"id": 100, "name": "again", "handler": "h2", "resources": []}]}
    assert verify_syscall_boundary(dup)["code"] == "SYSCALL_ID_CONFLICT"
    no_handler = {**ARTIFACT, "syscalls": [
        {"id": 1, "name": "x", "resources": []}]}
    assert verify_syscall_boundary(no_handler)["code"] == "HANDLER_MISSING"
    wild = {**ARTIFACT, "syscalls": [
        {"id": 1, "name": "x", "handler": "h",
         "resources": ["uart0", "sdcard"]}]}
    assert verify_syscall_boundary(wild)["code"] == \
        "RESOURCE_NOT_KERNEL_OWNED"
    # an id the SVC instruction cannot carry is not a syscall
    unencodable = {**ARTIFACT, "syscalls": [
        {"id": 70000, "name": "x", "handler": "h", "resources": []}]}
    assert verify_syscall_boundary(unencodable)["code"] == \
        "SYSCALL_ID_UNENCODABLE"
    negative = {**ARTIFACT, "syscalls": [
        {"id": -1, "name": "x", "handler": "h", "resources": []}]}
    assert verify_syscall_boundary(negative)["code"] == \
        "SYSCALL_ID_UNENCODABLE"


def test_kernel_resource_in_user_region_is_a_boundary_break():
    """A "kernel resource" the user can already touch is not one — the
    boundary exists only if the resource ranges sit outside user frames."""
    bad = {**ARTIFACT, "kernel_resources": {
        "uart0": [0x09000000, 0x09001000],
        "shadow": [0x42080000, 0x42081000]}}
    assert verify_syscall_boundary(bad)["code"] == \
        "KERNEL_RESOURCE_IN_USER_REGION"


def test_gate_residuals_refuse():
    gate = verify_syscall_boundary
    assert gate({})["code"] == "syscall_table_missing"
    # an empty table is the vacuous refusal, not a proof
    assert gate({**ARTIFACT, "syscalls": []})["code"] == \
        "syscall_table_missing"
    assert gate({k: v for k, v in ARTIFACT.items()
                 if k != "user_image"})["code"] == "user_image_missing"
    assert gate({**ARTIFACT,
                 "user_image": {"start": 9, "end": 1}})["code"] == \
        "user_image_invalid"
    no_map = {k: v for k, v in ARTIFACT.items() if k != "memory_map"}
    assert gate(no_map)["code"] == "memory_map_incomplete"
    assert gate({**ARTIFACT,
                 "memory_map": {"kernel_pools": {}}})["code"] == \
        "memory_map_incomplete"
    no_resources = {k: v for k, v in ARTIFACT.items()
                    if k != "kernel_resources"}
    assert gate(no_resources)["code"] == "kernel_resources_missing"
    assert gate({**ARTIFACT, "kernel_resources": {
        "uart0": "0x09000000"}})["code"] == "kernel_resources_invalid"
    assert gate({**ARTIFACT, "syscalls": [
        {"id": "x", "handler": "h"}]})["code"] == "syscall_field_invalid"
    assert gate({**ARTIFACT, "syscalls": [
        {"id": 1, "handler": "h", "resources": "uart0"}]})["code"] == \
        "syscall_field_invalid"
    # malformed ranges and entries refuse by name too
    assert gate({**ARTIFACT, "memory_map": {
        **ARTIFACT["memory_map"], "user_frames": ["9", "ten"]}})[
        "code"] == "memory_map_incomplete"
    assert gate({**ARTIFACT, "memory_map": {
        **ARTIFACT["memory_map"], "kernel_pools": {"k": [9, 1]}}})[
        "code"] == "memory_map_incomplete"
    assert gate({**ARTIFACT, "syscalls": ["not-an-object"]})["code"] == \
        "syscall_field_invalid"


def test_lattice_syscall_lane_residuals(tmp_path):
    """The verify-kernel syscalls lane refuses missing/invalid artifacts
    by name and mints the claim per profile — never guessing."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from test_kernel_composition import _kernel, _profile
    from pipeline.kernel_lattice import verify_kernel
    root = _kernel(tmp_path)
    # strip the lockfree lane: this test judges the SYSCALLS lane
    # wiring, not the (already-judged) ESBMC witness — each verify_kernel
    # call would otherwise pay a real ESBMC run
    for mf_path in root.rglob("kernel.json"):
        mf = json.loads(mf_path.read_text())
        if mf.pop("lockfree", None) is not None:
            mf_path.write_text(json.dumps(mf))
    manifest = json.loads((root / "kernel.json").read_text())
    manifest["syscalls"] = "ghost.json"
    (root / "kernel.json").write_text(json.dumps(manifest))
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "syscalls_artifact_missing"
    (root / "bad.json").write_text("{nope", encoding="utf-8")
    manifest["syscalls"] = "bad.json"
    (root / "kernel.json").write_text(json.dumps(manifest))
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "syscalls_artifact_invalid"
    (root / "sys.json").write_text(json.dumps(
        {"user_image": ARTIFACT["user_image"],
         "kernel_resources": ARTIFACT["kernel_resources"],
         "syscalls": ARTIFACT["syscalls"]}), encoding="utf-8")
    manifest["syscalls"] = "sys.json"
    (root / "kernel.json").write_text(json.dumps(manifest))
    # the artifact carries no memory_map and the profile declares none
    assert verify_kernel(root, [_profile(tmp_path)])["code"] == \
        "profile_field_missing"
    (root / "sys.json").write_text(json.dumps(ARTIFACT), encoding="utf-8")
    bundle = verify_kernel(root, [_profile(tmp_path)])
    assert any(e["claim"] == "SYSCALL_BOUNDARY_PROVED"
               for e in bundle.get("claims", []))
    # an overlapping user image fails the bundle by name
    (root / "sys.json").write_text(json.dumps(
        {**ARTIFACT, "user_image": {"start": 0x4000F000,
                                    "end": 0x40010000}}), encoding="utf-8")
    failed = verify_kernel(root, [_profile(tmp_path)])
    assert failed["code"] == "USER_IMAGE_OVERLAPS_KERNEL"
