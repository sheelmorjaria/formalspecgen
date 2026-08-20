# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M60 deployment-split PQ workload timing evidence."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.kernel_lattice import verify_kernel
from pipeline.pq_wcet import verify_pq_wcet


ROOT = Path(__file__).parents[1]
DEMO = ROOT / "examples/formalkernel"
NET = DEMO / "kernel/net"
PROFILES = [DEMO / "profiles/n150.json", DEMO / "profiles/r52.json"]


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _inputs():
    artifact = _json(NET / "pq_wcet.json")
    workload = (NET / artifact["source"]).read_bytes()
    scheduler = (NET / artifact["microkernel"]["scheduler_source"]).resolve()
    return artifact, workload, scheduler


def test_microkernel_bounds_scheduler_handler_not_whole_pq_loop():
    artifact, workload, scheduler = _inputs()
    expected = {"n150": (68, 27648), "r52": (133, 46080)}
    for path in PROFILES:
        profile = _json(path)
        verdict = verify_pq_wcet(artifact, workload, scheduler,
                                 profile, "microkernel")
        assert verdict["status"] == "PQ_PREEMPTION_BOUND_PROVED"
        assert (verdict["scheduler_wcet_cycles"], verdict["pq_total_cycles"]) == \
            expected[profile["target"]]
        assert verdict["hardware_interrupt_delivery_proved"] is False


def test_monolith_proves_only_the_cooperative_non_yielding_chunk():
    artifact, workload, scheduler = _inputs()
    expected = {"n150": 3456, "r52": 5760}
    for path in PROFILES:
        profile = _json(path)
        verdict = verify_pq_wcet(artifact, workload, scheduler,
                                 profile, "monolithic")
        assert verdict["status"] == "PQ_COOPERATIVE_WCET_BOUND_PROVED"
        assert verdict["non_yielding_chunk_cycles"] == expected[profile["target"]]
        assert verdict["preemptive_isolation_proved"] is False


def test_hash_yield_and_deadline_drift_fail_closed():
    artifact, workload, scheduler = _inputs()
    profile = _json(PROFILES[0])
    changed = copy.deepcopy(artifact)
    changed["source_sha256"] = "0" * 64
    assert verify_pq_wcet(changed, workload, scheduler, profile,
                          "microkernel")["code"] == "PQ_WCET_SOURCE_HASH_MISMATCH"
    no_yield = workload.replace(b"cooperative_yield();", b"pq_checkpoint();")
    changed = copy.deepcopy(artifact)
    import hashlib
    changed["source_sha256"] = hashlib.sha256(no_yield).hexdigest()
    assert verify_pq_wcet(changed, no_yield, scheduler, profile,
                          "monolithic")["code"] == "PQ_COOPERATIVE_YIELD_MISSING"
    changed = copy.deepcopy(artifact)
    changed["monolithic"]["max_non_yielding_chunk_cycles"]["n150"] = 100
    assert verify_pq_wcet(changed, workload, scheduler, profile,
                          "monolithic")["code"] == "PQ_COOPERATIVE_WCET_MISSED"


def test_bundle_claims_diverge_at_the_execution_boundary():
    micro = verify_kernel(DEMO / "kernel", PROFILES)
    mono = verify_kernel(DEMO / "kernel", PROFILES, "monolith.json")
    assert micro["status"] == mono["status"] == "KERNEL_EVIDENCE_BUNDLE"
    micro_claims = {item["claim"] for item in micro["claims"]}
    mono_claims = {item["claim"] for item in mono["claims"]}
    assert "PQ_PREEMPTION_BOUND_PROVED" in micro_claims
    assert "PQ_PREEMPTION_BOUND_PROVED" not in mono_claims
    assert "PQ_COOPERATIVE_WCET_BOUND_PROVED" in mono_claims
    assert "PQ_COOPERATIVE_WCET_BOUND_PROVED" not in micro_claims
    mono_boundary = next(item for item in mono["boundaries"]
                         if item["claim"] == "PQ_PREEMPTIVE_ISOLATION_NOT_AVAILABLE")
    assert mono_boundary["cooperative_yield_required"] is True


def test_registry_forbids_silicon_and_monolith_preemption_overclaims():
    lane = capability("m60_pq_wcet").milestone
    assert lane is not None and lane.current_maturity == "bounded-evidence"
    assert "HARDWARE_INTERRUPT_DELIVERY_PROVED" in lane.claims_forbidden
    assert "MONOLITH_PREEMPTIVE_ISOLATION_PROVED" in lane.claims_forbidden
