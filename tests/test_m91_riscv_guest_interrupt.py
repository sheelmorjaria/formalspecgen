# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations
import copy, json
from pathlib import Path
from pipeline.capability_registry import capability
from pipeline.riscv_guest_interrupt import validate_guest_interrupt_policy
from pipeline.riscv_guest_interrupt_promotion import promote_riscv_guest_interrupt_policy

ROOT=Path(__file__).parents[1]; K=ROOT/"examples/formalkernel/kernel"
def policy(): return json.loads((K/"riscv_vs_imsic_policy.json").read_text())

def test_candidate_is_nonproof_and_six_mutations_are_rejected():
    q=json.loads((K/"riscv_vs_imsic.qualification.json").read_text())
    assert validate_guest_interrupt_policy(policy()) == []
    assert q["claim"] == "NO_PROOF" and q["distinct_states"] == 60
    assert q["semantic_mutations_rejected"] == 6
    assert set(q["mutation_results"].values()) == {"TLC_FAILED"}

def test_policy_identity_file_and_state_mutations_fail():
    p=policy(); p["guest_files"][1]["vgein"]=1
    assert "guest_file_ownership" in validate_guest_interrupt_policy(p)
    p=policy(); p["guest_files"][1]["interrupt_id"]=48
    assert "vmid_or_identity_partition" in validate_guest_interrupt_policy(p)
    p=policy(); p["s_mode_file"]["vs_visible"]=True
    assert "s_mode_file_separation" in validate_guest_interrupt_policy(p)
    p=policy(); p["state_fields"].remove("hgeie")
    assert "interrupt_state_incomplete" in validate_guest_interrupt_policy(p)

def test_qemu_probe_is_configuration_only():
    result=json.loads((K/"riscv_vs_imsic_qemu.json").read_text())
    assert result["status"] == "RISCV_VS_IMSIC_QEMU_CONFIGURATION_OBSERVED"
    assert result["dtb_emitted"] is True and result["vs_routing_executed"] is False
    assert result["claim"] == "NO_PROOF" and result["qemu_semantics_proved"] is False

def test_human_promotion_boundary_and_lane_state():
    try: promote_riscv_guest_interrupt_policy(ROOT,accept_candidate_sha256="0"*64)
    except ValueError as e: assert "candidate hash mismatch" in str(e)
    else: raise AssertionError("wrong hash accepted")
    c=capability("promote_riscv_guest_interrupt_policy")
    assert c.trust_action and c.mcp_tool is None
    lane=capability("m91_1_riscv_platform_feasibility").milestone
    assert lane and lane.current_step==9 and lane.step_status=="complete"
    assert lane.current_maturity=="sealed-rv64-deployment-evidence-frozen"
    assert "RISCV_GUEST_INTERRUPT_ROUTING_MODEL_PROVED" in lane.completed_claims
