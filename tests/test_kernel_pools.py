# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M41: hardware trust roots — one profile derives every kernel pool."""
from __future__ import annotations

import pytest

from pipeline.hardware_profile import (HardwareProfileError, Profile,
                                       derive_kernel_pools, load_profile,
                                       safe_capacity)

PROFILE = {
    "target": "n150",
    "memory_model": "x86_tso",
    "total_sram_bytes": 128 * 1024,
    "reserved_system_bytes": 8 * 1024,
    "max_stack_depth_bytes": 4096,
    "word_size_bytes": 4,
    "sram_base_bytes": 0x20000000,
}


def _profile(tmp_path, **overrides):
    raw = {**PROFILE, **overrides}
    path = tmp_path / "hw.json"
    path.write_text(__import__("json").dumps(raw), encoding="utf-8")
    return load_profile(path)


def test_derives_disjoint_pools_from_one_profile(tmp_path):
    """The silicon decides the ceiling (usable 120 KiB, margin 0.9 →
    110 KiB); the reviewer declares each subsystem's SHARE. A 32-byte TCB
    pool on a 32 KiB share and a 64-byte buffer pool on a 16 KiB share
    land in disjoint SRAM windows inside usable SRAM."""
    verdict = derive_kernel_pools(_profile(tmp_path), {
        "scheduler": {"struct_size_bytes": 32, "sram_base": 0x20000000,
                      "budget_bytes": 0x8000},
        "network": {"struct_size_bytes": 64, "sram_base": 0x20008000,
                    "budget_bytes": 0x4000}})
    assert verdict["status"] == "HARDWARE_PROFILE_DERIVED"
    assert verdict["claim"] == "HARDWARE_PROFILE_DERIVED"
    assert verdict["scope"] == "deterministic_arithmetic"
    assert verdict["ownership"] == "human_declared_hardware_profile"
    assert verdict["memory_model"] == "x86_tso"
    ceiling = int(120 * 1024 * 0.9)
    # the share binds tighter than the ceiling here
    assert verdict["pools"]["scheduler"]["safe_capacity"] == 0x8000 // 32
    assert verdict["pools"]["network"]["safe_capacity"] == 0x4000 // 64
    sched = verdict["pools"]["scheduler"]
    assert sched["safe_capacity"] < ceiling // 32
    assert sched["footprint_bytes"] == sched["safe_capacity"] * 32
    assert sched["window_bytes"][0] == 0x20000000
    assert sched["window_bytes"][1] == 0x20000000 + sched["footprint_bytes"]


def test_two_ceiling_sized_pools_cannot_be_placed(tmp_path):
    """Without share declarations each pool claims the FULL 0.9 ceiling
    (~108 KiB of 120 KiB) — two such pools can never be disjoint. The
    gate refuses the map; it never silently shrinks a pool."""
    verdict = derive_kernel_pools(_profile(tmp_path), {
        "scheduler": {"struct_size_bytes": 32, "sram_base": 0x20000000},
        "network": {"struct_size_bytes": 64, "sram_base": 0x20008000}})
    assert verdict["code"] == "sram_overlap"


def test_capacities_without_windows_are_still_derived(tmp_path):
    """A subsystem without sram_base gets its capacity but no window —
    placement is the board designer's later declaration."""
    verdict = derive_kernel_pools(_profile(tmp_path),
                                  {"vfs": {"struct_size_bytes": 16}})
    assert verdict["pools"]["vfs"]["safe_capacity"] > 0
    assert verdict["pools"]["vfs"]["window_bytes"] is None


def test_overlapping_pools_are_refused_by_name(tmp_path):
    """Two pools claiming the same SRAM: the memory map is refused, never
    silently rebased."""
    verdict = derive_kernel_pools(_profile(tmp_path), {
        "scheduler": {"struct_size_bytes": 32, "sram_base": 0x20000000},
        "vfs": {"struct_size_bytes": 32, "sram_base": 0x20000010}})
    assert verdict["status"] == "HARDWARE_PROFILE_REFUSED"
    assert verdict["code"] == "sram_overlap"
    assert "scheduler" in verdict["message"] and "vfs" in verdict["message"]


def test_pool_outside_usable_sram_fails_closed(tmp_path):
    verdict = derive_kernel_pools(_profile(tmp_path), {
        "network": {"struct_size_bytes": 32, "sram_base": 0x10000000}})
    assert verdict["code"] == "pool_outside_sram"
    assert "network" in verdict["message"]


def test_residuals_fail_closed(tmp_path):
    derive = derive_kernel_pools
    assert derive(_profile(tmp_path), {})["code"] == "subsystems_missing"
    assert derive(_profile(tmp_path), None)["code"] == "subsystems_missing"
    assert derive(_profile(tmp_path),
                  {"sched": {}})["code"] == "subsystem_field_missing"
    assert derive(_profile(tmp_path),
                  {"sched": {"struct_size_bytes": "big"}})["code"] == \
        "subsystem_field_missing"
    assert derive(_profile(tmp_path),
                  {"sched": {"struct_size_bytes": 0}})["code"] == \
        "hardware_profile_invalid"
    assert derive(_profile(tmp_path),
                  {"sched": {"struct_size_bytes": 6}})["code"] == \
        "word_misaligned"
    # a struct larger than the whole 0.9 SRAM budget is refused outright
    huge = derive(_profile(tmp_path),
                  {"gfx": {"struct_size_bytes": 200 * 1024}})
    assert huge["code"] == "HARDWARE_MEMORY_EXCEEDED"


def test_m30_profile_shape_still_loads(tmp_path):
    """Back-compat: an M30-era profile (no memory_model/sram_base) loads
    and derives unchanged — the new fields default open, not closed."""
    raw = {k: v for k, v in PROFILE.items()
           if k not in {"memory_model", "sram_base_bytes"}}
    path = tmp_path / "stm32.json"
    path.write_text(__import__("json").dumps(raw), encoding="utf-8")
    profile = load_profile(path)
    assert profile.memory_model == ""
    verdict = derive_kernel_pools(
        profile, {"pool": {"struct_size_bytes": 8, "sram_base": 0}})
    assert verdict["status"] == "HARDWARE_PROFILE_DERIVED"
    # no declared SRAM origin → disjointness only, no containment verdict
    assert verdict["pools"]["pool"]["window_bytes"] == [0, 8 * verdict[
        "pools"]["pool"]["safe_capacity"]]


def test_safe_capacity_floor_and_refusal(tmp_path):
    profile = _profile(tmp_path)
    assert safe_capacity(profile, 1000) == int(120 * 1024 * 0.9) // 1000
    with pytest.raises(HardwareProfileError) as exc:
        safe_capacity(profile, 10 ** 9)
    assert "HARDWARE_MEMORY_EXCEEDED" in str(exc.value)


def test_profile_dataclass_defaults():
    profile = Profile(target="t", total_sram_bytes=100,
                      reserved_system_bytes=10, max_stack_depth_bytes=8,
                      word_size_bytes=4)
    assert profile.usable_sram_bytes == 90
    assert profile.memory_model == "" and profile.sram_base_bytes == 0
