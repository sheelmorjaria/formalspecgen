"""E2E: capacity-bounding behavior correction judged by REAL OpenJML ESC.

CWE-400 (Uncontrolled Resource Consumption) is a deliberate behavior
CORRECTION, never a refactor: the corrected program rejects work beyond the
capacity where the original accepted it without bound. The LLM seam is
deterministically injected (mocked provider returning the strategy-satisfying
rewrite); both OpenJML ESC runs are real.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline.behavior_correction import correct_behavior

pytestmark = pytest.mark.toolchain


UNBOUNDED = """public class BatchRunner {
    public int processed;

    //@ requires iterations >= 0;
    public void run(int iterations) {
        int i = 0;
        while (true) {
            if (i >= iterations) break;
            i = i + 1;
        }
        processed = i;
    }
}
"""

# The strategy-satisfying rewrite: the capacity bound is enforced by the
# guard (i < 1000), claimed by the contract, and proved by Z3.
BOUNDED = """public class BatchRunner {
    public int processed;

    /*@ requires iterations >= 0 && iterations <= 1000;
      @ ensures processed <= 1000;
      @ assignable processed;
      @*/
    public void run(int iterations) {
        int i = 0;
        //@ loop_invariant 0 <= i && i <= iterations;
        //@ decreases iterations - i;
        while (i < iterations && i < 1000) {
            i = i + 1;
        }
        processed = i;
    }
}
"""


def _openjml_available() -> bool:
    from pipeline import config
    return bool(config.OPENJML) and Path(config.OPENJML).exists()


def test_capacity_bounding_proves_with_real_openjml(tmp_path):
    if not _openjml_available():
        pytest.skip("OpenJML unavailable")
    source = tmp_path / "BatchRunner.java"
    source.write_text(UNBOUNDED, encoding="utf-8")
    with patch("pipeline.behavior_correction._chat_fn") as chat:
        chat.return_value.return_value = (BOUNDED, "fixture", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                  strategy="bound-loop")
    assert result["status"] == "BEHAVIOR_CORRECTION_VERIFIED", result
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"      # user Test 2.2
    assert result["mitigated_cwe"] == "CWE-400"
    assert result["strategy"] == "bound-loop"
    assert result["formal_proof"] == "DEDUCTIVE_PROOF"             # user Test 2.1
    corrected = (tmp_path / "out" / "BatchRunner.java").read_text(encoding="utf-8")
    assert "while (i < iterations && i < 1000)" in corrected
    assert "while (true)" not in corrected


def test_surviving_true_loop_never_reaches_the_prover(tmp_path):
    """The deterministic strategy check fires before OpenJML is trusted."""
    if not _openjml_available():
        pytest.skip("OpenJML unavailable")
    source = tmp_path / "BatchRunner.java"
    source.write_text(UNBOUNDED, encoding="utf-8")
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify") as verify:
        chat.return_value.return_value = (UNBOUNDED, "fixture", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                  strategy="bound-loop")
    assert result["code"] == "strategy_not_satisfied"
    verify.assert_not_called()


HW_E2E_PROFILE = {
    "target": "TestMCU (e2e)",
    "total_sram_bytes": 1024,
    "reserved_system_bytes": 0,
    "max_stack_depth_bytes": 512,
    "word_size_bytes": 4,
}
# usable 1024 * 0.9 = 921 budget; element 4 bytes -> capacity 230.


def test_hardware_derived_bound_proves_with_real_openjml(tmp_path):
    """Z3 proves the array bound AND the footprint fits the physical SRAM."""
    if not _openjml_available():
        pytest.skip("OpenJML unavailable")
    import json
    profile_path = tmp_path / "hardware_profile.json"
    profile_path.write_text(json.dumps(HW_E2E_PROFILE), encoding="utf-8")
    unbounded = """public class SensorBuffer {
    public int[] samples;
    public int count;

    public void record(int sample) {
        if (samples == null) { samples = new int[1]; }
        samples[0] = sample;
        count = count + 1;
    }
}
"""
    hw_bounded = """public class SensorBuffer {
    public int[] samples = new int[230];
    public int count;

    //@ requires samples != null && samples.length == 230;
    //@ requires count >= 0 && count < 230;
    //@ ensures count >= 0 && count <= 230;
    //@ assignable samples[*], count;
    public void record(int sample) {
        if (count < 230) {
            samples[count] = sample;
            count = count + 1;
        }
    }
}
"""
    source = tmp_path / "SensorBuffer.java"
    source.write_text(unbounded, encoding="utf-8")
    with patch("pipeline.behavior_correction._chat_fn") as chat:
        chat.return_value.return_value = (hw_bounded, "fixture", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                 strategy="static-pool",
                                 hardware=profile_path, struct_size_bytes=4)
    assert result["status"] == "BEHAVIOR_CORRECTION_VERIFIED", result
    assert "HARDWARE_MEMORY_BOUND_PROVEN" in result["claims"]
    hardware = result["hardware"]
    assert hardware["derived_capacity"] == 230
    assert result["memory_footprint_bytes"] == 920     # 230 * 4 <= 921 budget
    corrected = (tmp_path / "out" / "SensorBuffer.java").read_text(encoding="utf-8")
    assert "new int[230]" in corrected                 # user Test 2.1


def test_hardware_bound_exceeding_budget_never_reaches_prover(tmp_path):
    if not _openjml_available():
        pytest.skip("OpenJML unavailable")
    import json
    profile_path = tmp_path / "hardware_profile.json"
    profile_path.write_text(json.dumps(HW_E2E_PROFILE), encoding="utf-8")
    unbounded = "public class Big { public int[] a; }\n"
    oversized = "public class Big { public int[] a = new int[900]; }\n"
    source = tmp_path / "Big.java"
    source.write_text(unbounded, encoding="utf-8")
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify") as verify:
        chat.return_value.return_value = (oversized, "fixture", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                 strategy="static-pool",
                                 hardware=profile_path, struct_size_bytes=4)
    assert result["code"] == "hardware_bound_exceeded"
    verify.assert_not_called()
