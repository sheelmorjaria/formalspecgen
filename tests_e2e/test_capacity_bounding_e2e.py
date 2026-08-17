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


# ------------------------------------------------- bounded-pool (M13) ---

POOL_SERVER = """public class Server {
    public int acquired;
    public int capacity;

    //@ requires capacity > 0 && capacity <= 76;
    public Server(int capacity) {
        this.capacity = capacity;
        this.acquired = 0;
    }

    //@ requires s != 0 && acquired >= 0 && acquired <= capacity;
    //@ ensures acquired >= 0 && acquired <= capacity;
    //@ ensures \\result <==> (\\old(acquired) < capacity);
    //@ assignable acquired;
    public boolean accept(int s) {
        if (acquired < capacity) {
            acquired = acquired + 1;
            return true;
        }
        return false;   // pool full: reject without allocating (CWE-400)
    }
}
"""


def test_bounded_pool_capacity_enforced_by_real_openjml(tmp_path):
    """User Test 2: Z3 proves pool.size() <= capacity and acquire()
    returns false when full — through the correction lane, real ESC."""
    if not _openjml_available():
        pytest.skip("OpenJML unavailable")
    import json
    profile_path = tmp_path / "hardware_profile.json"
    profile_path.write_text(json.dumps(HW_E2E_PROFILE), encoding="utf-8")
    unbounded = """import java.util.LinkedList;

public class Server {
    private LinkedList<Integer> sockets = new LinkedList<>();
    public void accept(int s) { sockets.add(s); }
}
"""
    source = tmp_path / "Server.java"
    source.write_text(unbounded, encoding="utf-8")
    with patch("pipeline.behavior_correction._chat_fn") as chat:
        chat.return_value.return_value = (POOL_SERVER, "fixture", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                 strategy="bounded-pool",
                                 hardware=profile_path, struct_size_bytes=12)
    assert result["status"] == "BEHAVIOR_CORRECTION_VERIFIED", result
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert "HARDWARE_MEMORY_BOUND_PROVEN" in result["claims"]
    assert result["mitigated_cwe"] == "CWE-400"
    corrected = (tmp_path / "out" / "Server.java").read_text(encoding="utf-8")
    assert "acquired < capacity" in corrected
    assert "sockets.add" not in corrected
    assert result["memory_footprint_bytes"] == 76 * 12


DYNAMIC_POOL_SRC = """import java.util.LinkedList;

public class Server {
    private LinkedList<Integer> sockets = new LinkedList<>();
    public void accept(int s) { sockets.add(s); }
}
"""

POOL_EXCEPTION = """public class Server {
    public static class CapacityReachedException extends Exception {
        //@ assignable \\nothing;
        //@ ensures true;
        public CapacityReachedException() { super(); }
    }

    public int acquired;
    public int capacity;

    //@ requires capacity > 0;
    //@ ensures capacity == \\old(capacity) && acquired == 0;
    public Server(int capacity) { this.capacity = capacity; this.acquired = 0; }

    //@ requires acquired >= 0 && acquired <= capacity;
    //@ ensures acquired >= 0 && acquired <= capacity;
    //@ ensures \\old(acquired) < capacity ==> acquired == \\old(acquired) + 1;
    //@ signals (CapacityReachedException e) \\old(acquired) == capacity;
    //@ assignable acquired;
    public void accept(int s) throws CapacityReachedException {
        if (acquired == capacity) { throw new CapacityReachedException(); }
        acquired = acquired + 1;
    }
}
"""


def test_exception_rejection_at_capacity_proves_with_real_openjml(tmp_path):
    """M17: the reject-by-exception boundary — Z3 proves the acquire throws
    CapacityReachedException ONLY at the capacity boundary (the signals
    clause) and advances otherwise."""
    if not _openjml_available():
        pytest.skip("OpenJML unavailable")
    source = tmp_path / "Server.java"
    source.write_text(DYNAMIC_POOL_SRC, encoding="utf-8")
    with patch("pipeline.behavior_correction._chat_fn") as chat:
        chat.return_value.return_value = (POOL_EXCEPTION, "fixture", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                  strategy="bounded-pool")
    assert result["status"] == "BEHAVIOR_CORRECTION_VERIFIED", result
    assert result["strategy"] == "bounded-pool"
    assert result["formal_proof"] == "DEDUCTIVE_PROOF"
