# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M91.5a HS/VS model qualification and human-review boundary."""
from __future__ import annotations
import copy
import json
from pathlib import Path
from pipeline.capability_registry import capability
from pipeline.riscv_guest_privilege import (render_guest_privilege,
                                            validate_guest_policy,
                                            verify_guest_evidence)
from pipeline.riscv_guest_promotion import promote_riscv_guest_policy
ROOT = Path(__file__).parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"
def _json(name: str) -> dict:
    return json.loads((KERNEL / name).read_text(encoding="utf-8"))
def test_promoted_policy_is_bound_to_published_tlc_evidence():
    policy = _json("riscv_hs_vs_policy.json")
    evidence = _json("riscv_hs_vs.qualification.json")
    assert validate_guest_policy(policy) == []
    assert evidence["claim"] == "NO_PROOF"
    assert evidence["base_status"] == "VERIFIED"
    assert evidence["distinct_states"] == 15
    assert evidence["semantic_mutations_rejected"] == 4
    assert all(value == "TLC_FAILED" for value in evidence["mutation_results"].values())
    artifact = _json("riscv_hs_vs.json")
    published = _json(artifact["validation"])
    verdict = verify_guest_evidence(artifact, ROOT, published)
    assert verdict["status"] == "RISCV_GUEST_PRIVILEGE_EVIDENCE_BOUND"
    assert verdict["distinct_states"] == 15
    assert published["g_stage_isolation_proved"] is False
    assert published["vs_interrupt_routing_proved"] is False
def test_model_covers_hs_vs_trap_dispatch_resume_and_cross_guest_rejection():
    policy = _json("riscv_hs_vs_policy.reviewed.json")
    tla, cfg = render_guest_privilege(policy)
    for action in ("PrepareGuest", "EnterVS", "GuestTrap", "ValidateDispatch",
                   "RejectCrossGuest", "ResumeVS"):
        assert action in tla
    assert "CrossGuestSelectionRejected" in cfg
    assert "TrappedResumeRequiresDispatch" in cfg
def test_guest_policy_rejects_duplicate_vmid_and_context():
    policy = _json("riscv_hs_vs_policy.json")
    bad = copy.deepcopy(policy); bad["guests"][1]["vmid"] = 1
    assert "vmid" in validate_guest_policy(bad)
    bad = copy.deepcopy(policy); bad["guests"][1]["context"] = bad["guests"][0]["context"]
    assert "context" in validate_guest_policy(bad)
def test_promotion_is_human_only_and_claim_remains_locked():
    try:
        promote_riscv_guest_policy(ROOT, accept_candidate_sha256="0" * 64)
    except ValueError as exc:
        assert "candidate hash mismatch" in str(exc)
    else:
        raise AssertionError("wrong hash accepted")
    spec = capability("promote_riscv_guest_policy")
    assert spec.trust_action is True and spec.mcp_tool is None
    lane = capability("m91_1_riscv_platform_feasibility").milestone
    assert lane is not None and lane.current_step >= 5
    assert "RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED" in lane.completed_claims
