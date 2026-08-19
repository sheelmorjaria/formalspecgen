# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M42: the FormalKernel hardening strategies — pinned, not rebuilt.

The probe found checked-math / lock-timeout / fail-safe complete in
behavior_correction (each has an e2e prover-flow test) — but the
CWE-SCOPED routing for CWE-190/667/617 was unpinned. Phase 3 of the
FormalKernel plan hardens a subsystem with SEQUENTIAL human-driven
passes: one CWE per pass, the router consulting only that CWE's table.
"""
from __future__ import annotations

from pipeline.behavior_correction import _strategy_residuals
from pipeline.correction_router import route_strategy

# A kernel-shaped subsystem source carrying several weaknesses at once —
# exactly what Phase 3 hardens with sequential passes.
SUBSYSTEM = """public class Scheduler {
    public int budget;

    public synchronized void dispatch(int cost) {
        budget *= 3;
        assert budget >= 0;
    }
}
"""

LOOP_ONLY = """public class Reaper {
    public void reap() { while (true) { sweep(); } }
}
"""


def test_kernel_cwe_routing_is_scoped_not_greedy():
    """Under a CWE-190 request the overflow shape routes to checked-math;
    the SAME source under CWE-617 routes to fail-safe — and a CWE-190
    request on loop-only code returns None (never a silent cross-CWE
    rewrite)."""
    assert route_strategy(SUBSYSTEM, "CWE-190") == "checked-math"
    assert route_strategy(SUBSYSTEM, "CWE-667") == "lock-timeout"
    assert route_strategy(SUBSYSTEM, "CWE-617") == "fail-safe"
    assert route_strategy(LOOP_ONLY, "CWE-190") is None
    assert route_strategy(SUBSYSTEM, "CWE-999") is None
    assert route_strategy("public class Clean { int x; }", "CWE-617") is None
    assert route_strategy("public class Clean { int x; }", "CWE-667") is None


def test_fail_safe_residuals_demand_the_assert_is_gone():
    """The fail-safe idiom: a reachable assert must become an explicit
    SAFE_STATE transition — a rewrite that keeps the assert fails closed."""
    assert _strategy_residuals("fail-safe", SUBSYSTEM) == \
        ["assert removed-check still reachable"]
    hardened = SUBSYSTEM.replace("assert budget >= 0;",
                                  "if (budget < 0) { state = SAFE_STATE; }")
    assert _strategy_residuals("fail-safe", hardened) == []


def test_checked_math_residuals_demand_checked_arithmetic():
    assert _strategy_residuals("checked-math", SUBSYSTEM) != []
    checked = SUBSYSTEM.replace("budget *= 3;",
                                 "budget = Math.multiplyExact(budget, 3);")
    assert _strategy_residuals("checked-math", checked) == []


def test_lock_timeout_residuals_demand_trylock_and_finally():
    residuals = _strategy_residuals("lock-timeout", SUBSYSTEM)
    joined = " ".join(residuals)
    assert "synchronized still present" in joined
    assert "tryLock" in joined
    disciplined = """public class Scheduler {
    public int budget;
    private final Lock lock = new ReentrantLock();

    public void dispatch(int cost) throws InterruptedException {
        if (!lock.tryLock(5, TimeUnit.MILLISECONDS)) { return; }
        try { budget = budget + cost; }
        finally { lock.unlock(); }
    }
}
"""
    assert _strategy_residuals("lock-timeout", disciplined) == []


def test_sequential_passes_leave_no_strategy_residuals():
    """Phase 3 end state: after all three passes the hardened subsystem
    carries no residual for ANY of the kernel strategies."""
    hardened = """public class Scheduler {
    public int budget;
    private final Lock lock = new ReentrantLock();

    //@ requires cost >= 0 && budget <= 2147483647 / 3;
    public void dispatch(int cost) throws InterruptedException {
        if (!lock.tryLock(5, TimeUnit.MILLISECONDS)) {
            state = SAFE_STATE; return;
        }
        try { budget = Math.addExact(budget, cost); }
        finally { lock.unlock(); }
        if (budget < 0) { state = SAFE_STATE; }
    }
}
"""
    for strategy in ("checked-math", "lock-timeout", "fail-safe"):
        assert _strategy_residuals(strategy, hardened) == [], strategy
