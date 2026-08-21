# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M63: per-task temporal liveness under an explicit fairness assumption."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pipeline.capability_registry import capability
from pipeline.kernel_lattice import verify_kernel
from pipeline.scheduler_liveness import (render_scheduler_liveness,
                                         verify_scheduler_liveness_evidence,
                                         write_scheduler_validation)

ROOT = Path(__file__).parents[1]
SCHED = ROOT / "examples/formalkernel/kernel/scheduler"
KERNEL = ROOT / "examples/formalkernel/kernel"
PROFILES = [ROOT / "examples/formalkernel/profiles/n150.json",
            ROOT / "examples/formalkernel/profiles/r52.json"]


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_real_tlc_evidence_is_bound_and_explicitly_fair():
    artifact = _json(SCHED / "liveness.json")
    evidence = _json(SCHED / artifact["validation"])
    verdict = verify_scheduler_liveness_evidence(artifact, SCHED, evidence)
    assert verdict["status"] == "SCHEDULER_LIVENESS_EVIDENCE_BOUND"
    assert verdict["task_count"] == 3
    assert verdict["policy"] == "bounded_round_robin"
    assert verdict["distinct_states"] == 36
    assert verdict["fairness"] == "WF_vars(Schedule)"
    assert evidence["hardware_timer_fairness_proved"] is False
    assert evidence["source_model_refinement_proved"] is False


def test_renderer_uses_per_task_leads_to_not_global_ready():
    tla, cfg = render_scheduler_liveness("SchedulerStarvationFreedom", 3)
    assert "TaskProgress(i)" in tla
    assert "(i \\in ready) ~> (running = i \\/ i \\notin ready)" in tla
    assert "WF_vars(Schedule)" in tla
    assert "PROPERTY StarvationFreedom" in cfg
    with pytest.raises(ValueError, match="TASK_BOUND_INVALID"):
        render_scheduler_liveness("SchedulerStarvationFreedom", 0)


def test_source_model_or_fairness_drift_fails_closed():
    artifact = _json(SCHED / "liveness.json")
    evidence = _json(SCHED / artifact["validation"])
    drifted = copy.deepcopy(evidence)
    drifted["fairness"] = "SF_vars(Schedule)"
    assert verify_scheduler_liveness_evidence(artifact, SCHED, drifted)[
        "code"] == "SCHEDULER_LIVENESS_EVIDENCE_BINDING_MISMATCH"
    bad_source = copy.deepcopy(artifact)
    bad_source["source_sha256"] = "0" * 64
    assert verify_scheduler_liveness_evidence(bad_source, SCHED, evidence)[
        "claim"] == "NO_PROOF"


def test_publication_refuses_nonproof(tmp_path):
    with pytest.raises(ValueError, match="PUBLICATION_REFUSED"):
        write_scheduler_validation(tmp_path / "bad.json", {"status": "failed"})


def test_both_deployments_mint_the_same_shared_liveness_claim():
    micro = verify_kernel(KERNEL, PROFILES)
    mono = verify_kernel(KERNEL, PROFILES, "monolith.json")
    for bundle in (micro, mono):
        claims = [item for item in bundle["claims"] if item["claim"] ==
                  "SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED"]
        assert len(claims) == 1
        assert claims[0]["judge"] == "tlc"
        assert claims[0]["evidence"]["task_count"] == 3
        assert claims[0]["evidence"]["hardware_timer_fairness_proved"] is False


def test_registry_keeps_unbounded_and_hardware_claims_forbidden():
    lane = capability("m63_scheduler_liveness").milestone
    assert lane is not None and lane.required_judges == ("TLC",)
    assert lane.current_maturity == "temporal-model-evidence"
    assert "UNBOUNDED_SCHEDULER_LIVENESS_PROVED" in lane.claims_forbidden
    assert "HARDWARE_TIMER_FAIRNESS_PROVED" in lane.claims_forbidden
