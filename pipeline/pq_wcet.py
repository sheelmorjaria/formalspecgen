# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M60 deployment-split WCET and PQ workload preemption gate."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .realtime import wcet_bound


def _fail(code: str, message: str = "") -> dict:
    return {"status": "PQ_WCET_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def verify_pq_wcet(artifact: dict, workload: bytes, scheduler_path: Path,
                   profile: dict, deployment: str) -> dict:
    """Prove the appropriate declared scheduling bound for one deployment."""
    target = profile.get("target")
    if target not in {"n150", "r52"}:
        return _fail("PQ_WCET_PROFILE_UNSUPPORTED")
    if artifact.get("source_sha256") != hashlib.sha256(workload).hexdigest():
        return _fail("PQ_WCET_SOURCE_HASH_MISMATCH")
    text = workload.decode("utf-8", errors="strict")
    layers, width, operations = (artifact.get("layers"), artifact.get("width"),
                                  artifact.get("operations_per_butterfly"))
    if not all(isinstance(value, int) and not isinstance(value, bool) and value > 0
               for value in (layers, width, operations)) or width % 2:
        return _fail("PQ_WCET_BOUND_INVALID")
    if not re.search(rf"#define\s+NTT_LAYERS\s+{layers}\b", text) \
            or not re.search(rf"#define\s+NTT_WIDTH\s+{width}\b", text):
        return _fail("PQ_WCET_SOURCE_BOUND_MISMATCH")
    cost = profile.get("cost_model")
    if not isinstance(cost, dict) or not all(
            isinstance(cost.get(name), int) and cost[name] > 0
            for name in ("instruction", "memory", "branch")):
        return _fail("PQ_WCET_COST_MODEL_MISSING")
    butterfly_cycles = operations * max(cost.values())
    layer_cycles = (width // 2) * butterfly_cycles
    total_cycles = layers * layer_cycles

    if deployment == "microkernel":
        spec = artifact.get("microkernel", {})
        if spec.get("execution_level") != "EL0":
            return _fail("PQ_PREEMPTION_LEVEL_INVALID")
        expected = spec.get("scheduler_source_sha256")
        try:
            scheduler_hash = hashlib.sha256(scheduler_path.read_bytes()).hexdigest()
        except OSError as exc:
            return _fail("PQ_SCHEDULER_SOURCE_MISSING", str(exc))
        if expected != scheduler_hash:
            return _fail("PQ_SCHEDULER_SOURCE_HASH_MISMATCH")
        limits = spec.get("max_preemption_cycles", {})
        limit = limits.get(target) if isinstance(limits, dict) else None
        if not isinstance(limit, int) or limit <= 0:
            return _fail("PQ_PREEMPTION_DEADLINE_MISSING")
        timing = {**profile.get("timing", {}), "max_cycles": limit,
                  "cost_model": cost}
        scheduler = wcet_bound(scheduler_path, timing)
        if scheduler.get("status") != "WCET_BOUND_PROVEN":
            return _fail("PQ_PREEMPTION_DEADLINE_MISSED",
                         scheduler.get("message", ""))
        return {
            "status": "PQ_PREEMPTION_BOUND_PROVED",
            "claim": "PQ_PREEMPTION_BOUND_PROVED",
            "scope": f"el0_timer_preemption_{target}", "judge": "static_wcet",
            "scheduler_wcet_cycles": scheduler["wcet_cycles"],
            "max_preemption_cycles": limit, "pq_total_cycles": total_cycles,
            "hardware_interrupt_delivery_proved": False,
            "note": "EL0 work cannot extend the statically bounded EL1 scheduler handler",
        }
    if deployment in {"monolithic", "unikernel"}:
        spec = artifact.get("monolithic", {})
        symbol = artifact.get("cooperative_yield_symbol")
        if spec.get("execution_level") != "EL1" or not isinstance(symbol, str) \
                or text.count(f"{symbol}();") != 1:
            return _fail("PQ_COOPERATIVE_YIELD_MISSING")
        limits = spec.get("max_non_yielding_chunk_cycles", {})
        limit = limits.get(target) if isinstance(limits, dict) else None
        if not isinstance(limit, int) or layer_cycles > limit:
            return _fail("PQ_COOPERATIVE_WCET_MISSED",
                         f"chunk {layer_cycles} exceeds {limit}")
        return {
            "status": "PQ_COOPERATIVE_WCET_BOUND_PROVED",
            "claim": "PQ_COOPERATIVE_WCET_BOUND_PROVED",
            "scope": f"el1_cooperative_layer_{target}",
            "judge": "deterministic_cost_equation",
            "non_yielding_chunk_cycles": layer_cycles,
            "max_non_yielding_chunk_cycles": limit,
            "pq_total_cycles": total_cycles,
            "preemptive_isolation_proved": False,
        }
    return _fail("PQ_WCET_DEPLOYMENT_UNSUPPORTED")
