"""Hardware-aware capacity bounding: physical SRAM limits drive array bounds."""
from __future__ import annotations

import json

import pytest

from pipeline.hardware_profile import (
    HardwareProfileError,
    Profile,
    derive_struct_size,
    load_profile,
    prove_fixed_pool_fits,
    safe_capacity,
    stack_depth_ok,
)

PROFILE = {
    "target": "STM32F411 (Embedded RTOS)",
    "total_sram_bytes": 131072,
    "reserved_system_bytes": 32768,
    "max_stack_depth_bytes": 4096,
    "word_size_bytes": 4,
}


def _profile(tmp_path, **overrides):
    value = {**PROFILE, **overrides}
    path = tmp_path / "hardware_profile.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_safe_capacity_applies_margin_and_truncates():      # user Test 1.1
    profile = Profile(**PROFILE)
    assert profile.usable_sram_bytes == 98304               # 131072 - 32768
    assert safe_capacity(profile, struct_size_bytes=16,
                         safety_margin=0.9) == 5529          # floor(98304*0.9/16)


def test_struct_larger_than_ram_fails_closed():             # user Test 1.2
    profile = Profile(target="TinyMCU", total_sram_bytes=2048,
                      reserved_system_bytes=1024,
                      max_stack_depth_bytes=512, word_size_bytes=4)
    with pytest.raises(HardwareProfileError, match="HARDWARE_MEMORY_EXCEEDED"):
        safe_capacity(profile, struct_size_bytes=2048)       # usable=1024 < 2048


def test_load_profile_reads_and_validates(tmp_path):
    profile = load_profile(_profile(tmp_path))
    assert profile.target == "STM32F411 (Embedded RTOS)"
    assert profile.usable_sram_bytes == 98304
    with pytest.raises(HardwareProfileError, match="reserved"):
        load_profile(_profile(tmp_path, reserved_system_bytes=200000))


def test_derive_struct_size_counts_fields():
    source = ("public class Order { public int id; public int quantity; "
              "public boolean filled; }")
    # int + int + boolean = 4 + 4 + 1 → padded to word size → 12 bytes
    assert derive_struct_size(source, word_size_bytes=4) == 12


def test_stack_depth_rejects_overflow():                    # user Test 3.1
    profile = Profile(**PROFILE)                            # 4096 stack bytes
    # 8-byte frames → max safe depth 512; a 5000-deep recursion must fail
    assert not stack_depth_ok(profile, frame_bytes=8, depth=5000)
    assert stack_depth_ok(profile, frame_bytes=8, depth=512)
    assert not stack_depth_ok(profile, frame_bytes=8, depth=513)


def test_load_profile_rejects_garbage_and_bad_word_size(tmp_path):
    garbage = tmp_path / "hardware_profile.json"
    garbage.write_text("{not json", encoding="utf-8")
    with pytest.raises(HardwareProfileError, match="unreadable"):
        load_profile(garbage)
    with pytest.raises(HardwareProfileError, match="word size"):
        load_profile(_profile(tmp_path, word_size_bytes=0))


def test_derive_struct_size_has_word_floor():
    # no scalar fields -> one word minimum; nested references are not counted
    assert derive_struct_size("public class Node { public Node next; }",
                              word_size_bytes=4) == 4


def test_fixed_pool_proof_fails_closed_when_z3_is_absent(monkeypatch):
    monkeypatch.setattr("pipeline.hardware_profile.shutil.which", lambda _name: None)
    verdict = prove_fixed_pool_fits(Profile(**PROFILE), 2, 16)
    assert verdict["status"] == "HARDWARE_BOUND_FAILED"
    assert verdict["claim"] == "NO_PROOF"
    assert verdict["code"] == "z3_unavailable"
