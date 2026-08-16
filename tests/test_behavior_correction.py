from unittest.mock import patch

from pipeline.behavior_correction import correct_behavior


SOURCE = """public class UnsafeService {
    //@ requires arr != null;
    public int getElement(int[] arr, int index) { return arr[index]; }
}
"""
STRENGTHENED = """public class UnsafeService {
    //@ requires arr != null;
    //@ ensures (0 <= index && index < arr.length) ==> \\result == arr[index];
    //@ ensures !(0 <= index && index < arr.length) ==> \\result == -1;
    public int getElement(int[] arr, int index) {
        if (index < 0 || index >= arr.length) return -1;
        return arr[index];
    }
}
"""


def test_correct_behavior_mints_hash_bound_claim(tmp_path):
    source = tmp_path / "UnsafeService.java"
    source.write_text(SOURCE)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify", side_effect=[(1, "Postcondition"), (0, "")]):
        chat.return_value.return_value = (STRENGTHENED, "test", {})
        result = correct_behavior(source, "CWE-125", tmp_path / "out")
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert result["mitigated_cwe"] == "CWE-125"
    assert result["baseline_contract_hash"] != result["strengthened_contract_hash"]
    assert result["corrected_implementation_hash"]


def test_correct_behavior_fails_closed_after_retries(tmp_path):
    source = tmp_path / "UnsafeService.java"
    source.write_text(SOURCE)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify", return_value=(1, "bad")):
        chat.return_value.return_value = (SOURCE, "test", {})
        result = correct_behavior(source, "CWE-125", tmp_path / "out", max_attempts=2)
    assert result["status"] == "CORRECTION_FAILED"
    assert result["claim"] == "NO_PROOF"


UNBOUNDED = """public class BatchRunner {
    //@ requires iterations >= 0;
    public void run(int iterations) {
        int i = 0;
        while (true) {
            if (i >= iterations) break;
            i = i + 1;
        }
    }
}
"""

BOUNDED = """public class BatchRunner {
    //@ requires iterations >= 0 && iterations <= 1000;
    //@ ensures true;
    public void run(int iterations) {
        int i = 0;
        while (i < iterations && i < 1000) {
            i = i + 1;
        }
    }
}
"""

DYNAMIC_CACHE = """import java.util.HashMap;

public class SessionCache {
    private HashMap<String, Integer> cache = new HashMap<>();
    public void put(String key, int value) { cache.put(key, value); }
}
"""

STATIC_CACHE = """public class SessionCache {
    private String[] keys = new String[100];
    private int[] values = new int[100];
    //@ requires count < 100;
    public void put(String key, int value) {
        if (count < 100) { keys[count] = key; values[count] = value; count = count + 1; }
    }
    private int count;
}
"""


def test_bound_loop_strategy_guides_prompt_and_verifies(tmp_path):
    source = tmp_path / "BatchRunner.java"
    source.write_text(UNBOUNDED)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify", side_effect=[(1, "loop"), (0, "")]):
        chat.return_value.return_value = (BOUNDED, "test", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                  strategy="bound-loop")
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"          # user Test 2.2
    assert result["mitigated_cwe"] == "CWE-400"
    assert result["strategy"] == "bound-loop"
    # the strengthening prompt carried the strategy guidance           # user Test 1.1
    prompt = chat.return_value.call_args_list[0][0][0][1]["content"]
    assert "bound-loop" in prompt and "1000" in prompt
    corrected = (tmp_path / "out" / "BatchRunner.java").read_text()
    assert "while (i < iterations && i < 1000)" in corrected           # user Test 1.2
    assert "while (true)" not in corrected


def test_static_pool_strategy_rejects_surviving_dynamic_structures(tmp_path):
    source = tmp_path / "SessionCache.java"
    source.write_text(DYNAMIC_CACHE)
    # LLM keeps the HashMap: the deterministic strategy check must fail closed
    # before any verification is trusted.
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify") as verify:
        chat.return_value.return_value = (DYNAMIC_CACHE, "test", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                  strategy="static-pool")
    assert result["status"] == "CORRECTION_FAILED"
    assert result["code"] == "strategy_not_satisfied"
    assert "new HashMap" in result["message"]
    verify.assert_not_called()

    # and accepts the fixed-array rewrite
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify", side_effect=[(0, ""), (0, "")]):
        chat.return_value.return_value = (STATIC_CACHE, "test", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out2",
                                  strategy="static-pool")
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    corrected = (tmp_path / "out2" / "SessionCache.java").read_text()
    assert "new int[100]" in corrected        # array allocation is allowed
    assert "HashMap" not in corrected


def test_bound_loop_strategy_rejects_surviving_true_loops(tmp_path):
    source = tmp_path / "BatchRunner.java"
    source.write_text(UNBOUNDED)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify") as verify:
        chat.return_value.return_value = (UNBOUNDED, "test", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                  strategy="bound-loop")
    assert result["code"] == "strategy_not_satisfied"
    verify.assert_not_called()


def test_unknown_strategy_fails_closed(tmp_path):
    source = tmp_path / "BatchRunner.java"
    source.write_text(UNBOUNDED)
    result = correct_behavior(source, "CWE-400", tmp_path / "out",
                              strategy="bound-everything")
    assert result["status"] == "CORRECTION_FAILED"
    assert result["code"] == "unknown_strategy"


HW_PROFILE = {
    "target": "STM32F411 (Embedded RTOS)",
    "total_sram_bytes": 131072,
    "reserved_system_bytes": 32768,
    "max_stack_depth_bytes": 4096,
    "word_size_bytes": 4,
}


def _hardware(tmp_path):
    import json
    path = tmp_path / "hardware_profile.json"
    path.write_text(json.dumps(HW_PROFILE), encoding="utf-8")
    return path


DYNAMIC_QUEUE = """import java.util.LinkedList;

public class OrderQueue {
    private LinkedList<Integer> orders = new LinkedList<>();
    public void enqueue(int order) { orders.add(order); }
}
"""

HW_BOUNDED = """public class OrderQueue {
    public int[] orders = new int[5529];
    public int count;

    //@ requires count < 5529;
    public void enqueue(int order) {
        if (count < 5529) { orders[count] = order; count = count + 1; }
    }
}
"""


def test_hardware_derived_bound_flows_into_prompt_and_claim(tmp_path):
    source = tmp_path / "OrderQueue.java"
    source.write_text(DYNAMIC_QUEUE)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify",
               side_effect=[(0, ""), (0, "")]):
        chat.return_value.return_value = (HW_BOUNDED, "test", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                 strategy="static-pool",
                                 hardware=_hardware(tmp_path),
                                 struct_size_bytes=16)
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert "HARDWARE_MEMORY_BOUND_PROVEN" in result["claims"]          # Test 2.1
    hardware = result["hardware"]
    assert hardware["usable_sram_bytes"] == 98304
    assert hardware["derived_capacity"] == 5529
    prompt = chat.return_value.call_args_list[0][0][0][1]["content"]
    assert "98304" in prompt and "5529" in prompt                     # bound injected
    corrected = (tmp_path / "out" / "OrderQueue.java").read_text()
    assert "new int[5529]" in corrected and "5529" in corrected


def test_generated_bound_exceeding_physical_budget_fails_closed(tmp_path):
    oversized = HW_BOUNDED.replace("5529", "9999")
    source = tmp_path / "OrderQueue.java"
    source.write_text(DYNAMIC_QUEUE)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify") as verify:
        chat.return_value.return_value = (oversized, "test", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                 strategy="static-pool",
                                 hardware=_hardware(tmp_path),
                                 struct_size_bytes=16)
    assert result["code"] == "hardware_bound_exceeded"
    assert "9999" in result["message"]
    verify.assert_not_called()   # physical check precedes the prover


def test_struct_too_large_for_target_fails_closed(tmp_path):
    source = tmp_path / "OrderQueue.java"
    source.write_text(DYNAMIC_QUEUE)
    result = correct_behavior(source, "CWE-400", tmp_path / "out",
                              strategy="static-pool",
                              hardware=_hardware(tmp_path),
                              struct_size_bytes=200000)
    assert result["code"] == "HARDWARE_MEMORY_EXCEEDED"


def test_recursive_overflow_against_stack_fails_closed(tmp_path):     # user Test 3.1
    recursive = HW_BOUNDED.replace(
        "public void enqueue(int order) {",
        "public void enqueue(int order) {\n"
        "        if (order > 0) { enqueue(order - 1); }")
    source = tmp_path / "OrderQueue.java"
    source.write_text(DYNAMIC_QUEUE)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify") as verify:
        chat.return_value.return_value = (recursive, "test", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                 strategy="static-pool",
                                 hardware=_hardware(tmp_path),
                                 struct_size_bytes=16)
    assert result["code"] == "STACK_OVERFLOW_RISK"
    verify.assert_not_called()


def test_non_positive_struct_size_fails_closed(tmp_path):
    source = tmp_path / "OrderQueue.java"
    source.write_text(DYNAMIC_QUEUE)
    with patch("pipeline.behavior_correction._chat_fn") as chat:
        chat.return_value.return_value = (HW_BOUNDED, "test", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                 strategy="static-pool",
                                 hardware=_hardware(tmp_path),
                                 struct_size_bytes=0)
    # a non-positive element size is invalid input (division by zero territory),
    # not a physical-memory violation; either way it fails before the LLM runs
    assert result["code"] == "hardware_profile_invalid"
    assert result["claim"] == "NO_PROOF"
    chat.assert_not_called()


def test_unreadable_profile_fails_closed(tmp_path):
    source = tmp_path / "OrderQueue.java"
    source.write_text(DYNAMIC_QUEUE)
    garbage = tmp_path / "broken.json"
    garbage.write_text("{", encoding="utf-8")
    result = correct_behavior(source, "CWE-400", tmp_path / "out",
                             strategy="static-pool", hardware=garbage)
    assert result["code"] == "hardware_profile_unreadable"
