"""M14: deterministic strategy routing — the AST shape picks the correction.

`route_strategy` is pure text/shape matching, no LLM: unbounded loops route
to bound-loop, dynamic map collections to bounded-cache, dynamic
list/deque/queue collections to bounded-pool (static-pool when the hardware
profile is too small to bother with on-demand allocation), and an unrecognized
shape returns None so the caller fails closed to manual review.
"""
from __future__ import annotations

import json

from pipeline.correction_router import (
    auto_route_correction, route_strategy, select_strategy,
)


LOOPS = """public class BatchRunner {
    public void run(int n) {
        while (true) { consume(); }
    }
}
"""

LISTS = """import java.util.LinkedList;

public class Server {
    private LinkedList<Integer> sockets = new LinkedList<>();
    public void accept(int s) { sockets.add(s); }
}
"""

MAPS = """import java.util.HashMap;

public class SessionCache {
    private HashMap<String, Integer> cache = new HashMap<>();
    public void put(String k, int v) { cache.put(k, v); }
}
"""

CLEAN = """public class Adder {
    public int add(int a, int b) { return a + b; }
}
"""


def test_unbounded_loops_route_to_bound_loop():
    assert route_strategy(LOOPS) == "bound-loop"


def test_map_collections_route_to_bounded_cache():
    assert route_strategy(MAPS) == "bounded-cache"


def test_list_collections_route_to_bounded_pool_by_default():
    assert route_strategy(LISTS) == "bounded-pool"


def test_list_collections_route_to_static_pool_on_tiny_hardware():
    """A pool's win over a static array is on-demand allocation; when the
    derived capacity is tiny the distinction is noise and the eager array is
    the safer, simpler target."""
    tiny = {"target": "M0", "total_sram_bytes": 1024,
            "reserved_system_bytes": 900, "max_stack_depth_bytes": 512,
            "word_size_bytes": 4}
    # usable 124 -> floor(124 * 0.9 / 8) = 13 < 16
    assert select_strategy(LISTS, tiny, struct_size_bytes=8) == "static-pool"
    assert select_strategy(MAPS, tiny, struct_size_bytes=8) == "bounded-cache"
    assert select_strategy(LOOPS, tiny, struct_size_bytes=8) == "bound-loop"


def test_unrecognized_shape_fails_closed_to_manual_review():
    assert route_strategy(CLEAN) is None


def test_auto_route_correction_runs_the_lane_and_records_the_choice(tmp_path):
    """End-to-end through correct_behavior with a mocked provider: the
    routed strategy lands in the verdict evidence."""
    from unittest.mock import patch

    from pipeline.behavior_correction import correct_behavior
    source = tmp_path / "Server.java"
    source.write_text(LISTS, encoding="utf-8")
    rewrite = """public class Server {
    public int acquired;
    public int capacity;

    //@ requires capacity > 0 && capacity <= 5529;
    public Server(int capacity) { this.capacity = capacity; acquired = 0; }

    //@ requires acquired >= 0 && acquired <= capacity;
    //@ ensures acquired >= 0 && acquired <= capacity;
    //@ ensures \\result <==> (\\old(acquired) < capacity);
    //@ assignable acquired;
    public boolean accept(int s) {
        if (acquired < capacity) { acquired = acquired + 1; return true; }
        return false;
    }
}
"""
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify",
               side_effect=[(0, ""), (0, "")]):
        chat.return_value.return_value = (rewrite, "fixture", {})
        result = auto_route_correction(source, "CWE-400", tmp_path / "out",
                                       provider="ollama")
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert result["strategy"] == "bounded-pool"
    assert result["strategy_routed"] is True       # the router chose it


def test_auto_route_correction_without_a_shape_fails_closed(tmp_path):
    source = tmp_path / "Adder.java"
    source.write_text(CLEAN, encoding="utf-8")
    result = auto_route_correction(source, "CWE-400", tmp_path / "out")
    assert result["status"] == "CORRECTION_FAILED"
    assert result["code"] == "no_routable_strategy"
    assert "manual" in result["message"]


def test_auto_route_correction_propagates_late_failure_verdicts(tmp_path):
    """A routable shape whose rewrite never argues a capacity still fails
    closed inside the lane — routing only picks the strategy, never weakens
    the downstream gates."""
    from unittest.mock import patch

    source = tmp_path / "Server.java"
    source.write_text(LISTS, encoding="utf-8")
    lazy = "public class Server { public int acquired; }\n"
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify") as verify:
        chat.return_value.return_value = (lazy, "fixture", {})
        result = auto_route_correction(source, "CWE-400", tmp_path / "out")
    assert result["code"] == "strategy_not_satisfied"
    verify.assert_not_called()


def test_correct_behavior_auto_strategy_flag_routes(tmp_path):
    """The explicit --auto-strategy opt-in routes inside the existing entry
    point; the human stays in the loop unless they ask for autonomy."""
    from unittest.mock import patch

    from pipeline.behavior_correction import correct_behavior
    source = tmp_path / "SessionCache.java"
    source.write_text(MAPS, encoding="utf-8")
    rewrite = """public class SessionCache {
    public String[] keys = new String[5529];
    public int[] values = new int[5529];
    public int count;

    //@ requires count >= 0 && count < 5529;
    //@ ensures count >= 0 && count <= 5529;
    //@ assignable keys[*], values[*], count;
    public void put(String k, int v) {
        if (count < 5529) { keys[count] = k; values[count] = v; count = count + 1; }
    }
}
"""
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify",
               side_effect=[(0, ""), (0, "")]):
        chat.return_value.return_value = (rewrite, "fixture", {})
        result = correct_behavior(source, "CWE-400", tmp_path / "out",
                                 auto_strategy=True)
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert result["strategy"] == "bounded-cache"
    assert result["strategy_routed"] is True


def test_correct_behavior_auto_strategy_without_shape_fails_closed(tmp_path):
    from pipeline.behavior_correction import correct_behavior
    source = tmp_path / "Adder.java"
    source.write_text(CLEAN, encoding="utf-8")
    result = correct_behavior(source, "CWE-400", tmp_path / "out",
                              auto_strategy=True)
    assert result["code"] == "no_routable_strategy"


def test_router_extras_collection_api_without_constructor(tmp_path):
    # injected collection: no `new` visible, but the mutating API is enough
    injected = """public class Relay {
    private java.util.List<Integer> inbox;
    public Relay(java.util.List<Integer> inbox) { this.inbox = inbox; }
    public void take(int m) { inbox.add(m); }
}
"""
    assert route_strategy(injected) == "bounded-pool"
    # injected map via put(): no map constructor visible
    injected_map = """public class Store {
    private java.util.Map<String, Integer> m;
    public void save(String k, int v) { m.put(k, v); }
}
"""
    assert route_strategy(injected_map) == "bounded-pool"
    # while(1) and for ( ; ; ) spellings route via the loop-guard regex
    assert route_strategy("public class A { void f() { while (1) { g(); } } }") \
        == "bound-loop"
    assert route_strategy("public class B { void f() { for ( ; ; ) { g(); } } }") \
        == "bound-loop"
    # select_strategy derives the struct size from the source when omitted
    import json as _json
    profile_path = tmp_path / "hw.json"
    profile_path.write_text(_json.dumps(
        {"target": "M0", "total_sram_bytes": 1024,
         "reserved_system_bytes": 900, "max_stack_depth_bytes": 512,
         "word_size_bytes": 4}), encoding="utf-8")
    # LinkedList source derives 0 int fields -> word floor of 4 bytes ->
    # capacity 27 >= 16, stays bounded-pool
    assert select_strategy(LISTS, profile_path) == "bounded-pool"


def test_auto_route_correction_missing_file_fails_closed(tmp_path):
    result = auto_route_correction(tmp_path / "nope.java", "CWE-400",
                                   tmp_path / "out")
    assert result["code"] == "input_unavailable"
