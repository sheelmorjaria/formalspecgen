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


# ------------------------------------------------- bounded-pool (M13) ---

POOL_REWRITE = """public class Server {
    public int acquired;
    public int capacity;

    //@ requires capacity > 0 && capacity <= 5529;
    public Server(int capacity) { this.capacity = capacity; this.acquired = 0; }

    //@ requires s != 0 && acquired >= 0;
    //@ ensures acquired >= 0 && acquired <= capacity;
    //@ ensures \\result == (old.Acquired < capacity);
    public boolean accept(int s) {
        if (acquired < capacity) { acquired = acquired + 1; return true; }
        return false;
    }
}
"""

POOL_NO_LIMIT = """public class Server {
    public int acquired;

    public Server() { this.acquired = 0; }

    public boolean accept(int s) {
        acquired = acquired + 1;   // unbounded pool: no capacity check
        return true;
    }
}
"""


def test_bounded_pool_rewrite_flows_to_prover(tmp_path):
    """Test 1: the LLM rewrite becomes a capacity-checked pool (acquire
    returns false when full) and the hardware bound enters the prompt."""
    source = tmp_path / "Server.java"
    source.write_text(DYNAMIC_QUEUE)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify",
               side_effect=[(0, ""), (0, "")]) as verify:
        chat.return_value.return_value = (POOL_REWRITE, "fixture", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                 strategy="bounded-pool",
                                 hardware=_hardware(tmp_path),
                                 struct_size_bytes=16)
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert "HARDWARE_MEMORY_BOUND_PROVEN" in result["claims"]
    prompt = chat.return_value.call_args_list[0].args[0][1]["content"]
    assert "bounded-pool" in prompt
    assert "BoundedPool" in prompt and "acquire" in prompt
    corrected = (tmp_path / "out" / "Server.java").read_text(encoding="utf-8")
    assert "acquired < capacity" in corrected           # reject-when-full
    verify.assert_called()


def test_bounded_pool_without_capacity_fails_closed(tmp_path):
    """Test 3: a pool rewrite with no capacity limit never reaches the
    prover — strategy_not_satisfied fires first."""
    source = tmp_path / "Server.java"
    source.write_text(DYNAMIC_QUEUE)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify") as verify:
        chat.return_value.return_value = (POOL_NO_LIMIT, "fixture", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                 strategy="bounded-pool",
                                 hardware=_hardware(tmp_path),
                                 struct_size_bytes=16)
    assert result["code"] == "strategy_not_satisfied"
    assert "capacity" in result["message"]
    verify.assert_not_called()


def test_bounded_pool_surviving_dynamic_collection_fails_closed(tmp_path):
    """The pool rewrite must eliminate the dynamic collection, and a
    capacity-ARGUED but pool-less rewrite (plain ArrayList) is refused."""
    source = tmp_path / "Server.java"
    source.write_text(DYNAMIC_QUEUE)
    sneaky = POOL_REWRITE.replace("acquired = acquired + 1",
                                  "orders.add(order); acquired = acquired + 1")
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify") as verify:
        chat.return_value.return_value = (sneaky, "fixture", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                 strategy="bounded-pool",
                                 hardware=_hardware(tmp_path),
                                 struct_size_bytes=16)
    assert result["code"] == "strategy_not_satisfied"
    verify.assert_not_called()


def test_unreadable_profile_fails_closed(tmp_path):
    source = tmp_path / "OrderQueue.java"
    source.write_text(DYNAMIC_QUEUE)
    garbage = tmp_path / "broken.json"
    garbage.write_text("{", encoding="utf-8")
    result = correct_behavior(source, "CWE-400", tmp_path / "out",
                             strategy="static-pool", hardware=garbage)
    assert result["code"] == "hardware_profile_unreadable"


# ------------------------------------------------- M16: hardening strategies ---

def _run_strategy(tmp_path, source_text, cwe, strategy, rewrite):
    """Shared harness: mocked provider rewrite + mocked clean ESC."""
    source = tmp_path / "Target.java"
    source.write_text(source_text)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify",
               side_effect=[(0, ""), (0, "")]) as verify:
        chat.return_value.return_value = (rewrite, "fixture", {})
        result = correct_behavior(source, cwe, tmp_path / "out",
                                  strategy=strategy)
    return result, verify, chat


OVERFLOW_SOURCE = """public class Meter {
    public int total;

    public void add(int n) { total = total * 3 + n; }
}
"""

CHECKED_MATH_REWRITE = """public class Meter {
    public int total;

    //@ requires n >= 0 && total >= 0 && total <= 2147483647 / 3;
    //@ ensures total >= 0 && total <= 2147483647;
    public void add(int n) {
        total = Math.addExact(Math.multiplyExact(total, 3), n);
    }
}
"""


def test_checked_math_strategy_flows_to_prover(tmp_path):
    result, verify, chat = _run_strategy(
        tmp_path, OVERFLOW_SOURCE, "CWE-190", "checked-math",
        CHECKED_MATH_REWRITE)
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert result["strategy"] == "checked-math"
    prompt = chat.return_value.call_args_list[0].args[0][1]["content"]
    assert "checked-math" in prompt
    verify.assert_called()


def test_checked_math_without_overflow_bound_fails_closed(tmp_path):
    lazy = "public class Meter { public int total; public void add(int n) { total = total * 3 + n; } }\n"
    result, verify, _ = _run_strategy(
        tmp_path, OVERFLOW_SOURCE, "CWE-190", "checked-math", lazy)
    assert result["code"] == "strategy_not_satisfied"
    assert result["strategy"] == "checked-math"
    verify.assert_not_called()


LOCK_SOURCE = """public class Counter {
    private int count = 0;

    public synchronized void tick() { count = count + 1; }
    public int value() { return count; }
}
"""

LOCK_TIMEOUT_REWRITE = """import java.util.concurrent.locks.ReentrantLock;

public class Counter {
    private int count = 0;
    private final ReentrantLock lock = new ReentrantLock();

    //@ ensures \\result == count || \\result == -1;
    public int tick() {
        try {
            if (!lock.tryLock(100, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                return -1;
            }
            try { count = count + 1; return count; }
            finally { lock.unlock(); }
        } catch (InterruptedException e) { return -1; }
    }

    public int value() { return count; }
}
"""


def test_lock_timeout_strategy_flows_to_prover(tmp_path):
    result, verify, _ = _run_strategy(
        tmp_path, LOCK_SOURCE, "CWE-667", "lock-timeout", LOCK_TIMEOUT_REWRITE)
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert result["strategy"] == "lock-timeout"
    verify.assert_called()


def test_lock_timeout_with_surviving_synchronized_fails_closed(tmp_path):
    sneaky = LOCK_TIMEOUT_REWRITE.replace(
        "public int tick() {", "public synchronized int tick() {")
    result, verify, _ = _run_strategy(
        tmp_path, LOCK_SOURCE, "CWE-667", "lock-timeout", sneaky)
    assert result["code"] == "strategy_not_satisfied"
    verify.assert_not_called()


def test_lock_timeout_without_finally_unlock_fails_closed(tmp_path):
    sneaky = LOCK_TIMEOUT_REWRITE.replace(
        "finally { lock.unlock(); }", "lock.unlock();")
    result, verify, _ = _run_strategy(
        tmp_path, LOCK_SOURCE, "CWE-667", "lock-timeout", sneaky)
    assert result["code"] == "strategy_not_satisfied"
    verify.assert_not_called()


XSS_SOURCE = """public class Greeter {
    public String greet(String name) { return "<h1>" + name + "</h1>"; }
}
"""

CANONICALIZE_REWRITE = """import org.owasp.encoder.Encode;

public class Greeter {
    //@ ensures \\result != null;
    public String greet(String name) {
        return "<h1>" + Encode.forHtml(name) + "</h1>";
    }
}
"""


def test_canonicalize_strategy_flows_to_prover(tmp_path):
    result, verify, _ = _run_strategy(
        tmp_path, XSS_SOURCE, "CWE-79", "canonicalize", CANONICALIZE_REWRITE)
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert result["strategy"] == "canonicalize"
    verify.assert_called()


def test_canonicalize_without_encoding_fails_closed(tmp_path):
    result, verify, _ = _run_strategy(
        tmp_path, XSS_SOURCE, "CWE-79", "canonicalize", XSS_SOURCE)
    assert result["code"] == "strategy_not_satisfied"
    verify.assert_not_called()


ASSERT_SOURCE = """public class Validator {
    public int check(int value) {
        assert value > 0;
        return value;
    }
}
"""

FAIL_SAFE_REWRITE = """public class Validator {
    //@ requires value > 0 || value == -1;
    //@ ensures \\result == value || \\result == -1;
    public int check(int value) {
        if (!(value > 0)) { return -1; }
        return value;
    }
}
"""


def test_fail_safe_strategy_flows_to_prover(tmp_path):
    result, verify, _ = _run_strategy(
        tmp_path, ASSERT_SOURCE, "CWE-617", "fail-safe", FAIL_SAFE_REWRITE)
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert result["strategy"] == "fail-safe"
    verify.assert_called()


def test_fail_safe_with_surviving_assert_fails_closed(tmp_path):
    sneaky = FAIL_SAFE_REWRITE.replace(
        "if (!(value > 0)) { return -1; }",
        "if (!(value > 0)) { return -1; }\n        assert value < 100;")
    result, verify, _ = _run_strategy(
        tmp_path, ASSERT_SOURCE, "CWE-617", "fail-safe", sneaky)
    assert result["code"] == "strategy_not_satisfied"
    verify.assert_not_called()


RACE_SOURCE = """import java.util.ArrayList;
import java.util.List;

public class Registry {
    public List<String> names = new ArrayList<>();
    public int active = 0;

    public void add(String name) { names.add(name); }
    public List<String> view() { return names; }
}
"""

IMMUTABLE_SNAPSHOT_REWRITE = """import java.util.ArrayList;
import java.util.List;

public class Registry {
    private List<String> names;
    private int active;

    //@ requires name != null;
    //@ ensures active == old.active + 1;
    public Registry(List<String> initial) {
        this.names = List.copyOf(initial);
        this.active = 0;
    }

    public List<String> view() { return names; }
}
"""


def test_immutable_snapshot_strategy_flows_to_prover(tmp_path):
    result, verify, _ = _run_strategy(
        tmp_path, RACE_SOURCE, "CWE-362", "immutable-snapshot",
        IMMUTABLE_SNAPSHOT_REWRITE)
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert result["strategy"] == "immutable-snapshot"
    verify.assert_called()


def test_immutable_snapshot_without_copy_fails_closed(tmp_path):
    sneaky = IMMUTABLE_SNAPSHOT_REWRITE.replace(
        "List.copyOf(initial)", "initial").replace(
        "private List<String> names;", "public List<String> names;")
    result, verify, _ = _run_strategy(
        tmp_path, RACE_SOURCE, "CWE-362", "immutable-snapshot", sneaky)
    assert result["code"] == "strategy_not_satisfied"
    verify.assert_not_called()


def test_new_strategies_reject_unknown_names_and_reach_manifest_guidance(tmp_path):
    from pipeline.cwe_registry import correction_guidance, entries
    # the three new manifest CWEs load and resolve to real guidance
    for cwe in ("CWE-190", "CWE-667", "CWE-617", "CWE-362"):
        assert cwe in entries()
        assert correction_guidance(cwe)        # non-empty guidance
    result = correct_behavior(tmp_path / "no.java", "CWE-190",
                              tmp_path / "out", strategy="not-a-strategy")
    assert result["code"] == "unknown_strategy"


def test_lock_timeout_without_trylock_fails_closed(tmp_path):
    """No surviving synchronized, no bare lock(), but also no tryLock: the
    rewrite simply dropped the lock instead of bounding the wait."""
    lockless = "public class Counter { private int count = 0; public int tick() { count = count + 1; return count; } }\n"
    result, verify, _ = _run_strategy(
        tmp_path, LOCK_SOURCE, "CWE-667", "lock-timeout", lockless)
    assert result["code"] == "strategy_not_satisfied"
    assert "tryLock" in result["message"]
    verify.assert_not_called()


# --------------------------------- M17: reject-by-exception at the boundary ---

POOL_EXCEPTION_REWRITE = """public class Server {
    public static class CapacityReachedException extends Exception {
        //@ assignable \\nothing;
        //@ ensures true;
        public CapacityReachedException() { super(); }
    }

    public int acquired;
    public int capacity;

    //@ requires capacity > 0 && capacity <= 5529;
    public Server(int capacity) { this.capacity = capacity; this.acquired = 0; }

    //@ requires acquired >= 0;
    //@ ensures acquired >= 0 && acquired <= capacity;
    //@ signals (CapacityReachedException e) acquired == capacity;
    //@ assignable acquired;
    public void accept(int s) throws CapacityReachedException {
        if (acquired == capacity) { throw new CapacityReachedException(); }
        acquired = acquired + 1;
    }
}
"""


def test_bounded_pool_exception_rejection_flows_to_prover(tmp_path):
    """The reject-when-full boundary may be either a boolean false return or
    a dedicated exception whose JML signals clause pins the throw to the
    capacity boundary — Z3 judges which paths can throw."""
    result, verify, chat = _run_strategy(
        tmp_path, DYNAMIC_QUEUE, "CWE-400", "bounded-pool",
        POOL_EXCEPTION_REWRITE)
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert result["strategy"] == "bounded-pool"
    prompt = chat.return_value.call_args_list[0].args[0][1]["content"]
    assert "CapacityReachedException" in prompt
    verify.assert_called()


def test_unguarded_capacity_throw_fails_closed(tmp_path):
    """A rewrite that throws the capacity exception without a capacity guard
    (an unconditional or unrelated-condition throw) never reaches the
    prover."""
    sneaky = """public class Server {
    public static class CapacityReachedException extends Exception {}

    public int acquired;
    public int capacity;

    //@ requires acquired >= 0 && acquired <= capacity;
    public void accept(int s) throws CapacityReachedException {
        throw new CapacityReachedException();
    }
}
"""
    result, verify, _ = _run_strategy(
        tmp_path, DYNAMIC_QUEUE, "CWE-400", "bounded-pool", sneaky)
    assert result["code"] == "strategy_not_satisfied"
    assert "unguarded" in result["message"]
    verify.assert_not_called()
