# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations
import copy, json
from pathlib import Path
from pipeline.capability_registry import capability
from pipeline.riscv_gstage import validate_gstage_plan, verify_gstage_evidence
from pipeline.riscv_gstage_promotion import promote_riscv_gstage_plan
ROOT=Path(__file__).parents[1]; K=ROOT/"examples/formalkernel/kernel"
def plan(): return json.loads((K/"riscv_gstage_plan.json").read_text())
def test_candidate_qualified_and_claim_locked():
    q=json.loads((K/"riscv_gstage.qualification.json").read_text())
    assert validate_gstage_plan(plan()) == []
    assert q["claim"] == "NO_PROOF" and q["distinct_states"] == 28
    assert q["semantic_mutations_rejected"] == 3
    artifact=json.loads((K/"riscv_gstage.json").read_text())
    evidence=json.loads((K/artifact["validation"]).read_text())
    verdict=verify_gstage_evidence(artifact,ROOT,evidence)
    assert verdict["status"]=="RISCV_G_STAGE_EVIDENCE_BOUND"
    assert verdict["distinct_states"]==28
    assert evidence["g_stage_tlb_coherence_proved"] is False
    assert evidence["hardware_g_stage_walk_proved"] is False
def test_cross_guest_hs_vmid_alignment_walk_and_gpa_mutations_fail():
    p=plan(); p["guests"][0]["mappings"][0]["spa"]=p["guests"][1]["owned_spa"][0]["start"]
    assert "ownership:guest1" in validate_gstage_plan(p)
    p=plan(); p["guests"][0]["mappings"][0]["spa"]=p["hs_protected"][0]["start"]
    assert "ownership:guest1" in validate_gstage_plan(p)
    p=plan(); p["guests"][1]["vmid"]=1
    assert "active_vmid_separation" in validate_gstage_plan(p)
    p=plan(); p["guests"][0]["hgatp_root"] += 4096
    assert "root_alignment:guest1" in validate_gstage_plan(p)
    p=plan(); p["guests"][0]["vs_page_table_spa"][0]=p["hs_protected"][0]["start"]
    assert "vs_walk_page_ownership:guest1" in validate_gstage_plan(p)
    p=plan(); p["guests"][0]["mappings"][0]["gpa"]=1<<41
    assert "gpa:guest1" in validate_gstage_plan(p)
    p=plan(); p["guests"][0]["mappings"][0]["permissions"]="RWX"
    assert "permissions:guest1" in validate_gstage_plan(p)
def test_human_promotion_boundary():
    try: promote_riscv_gstage_plan(ROOT,accept_candidate_sha256="0"*64)
    except ValueError as e: assert "candidate hash mismatch" in str(e)
    else: raise AssertionError("wrong hash accepted")
    c=capability("promote_riscv_gstage_plan")
    assert c.trust_action and c.mcp_tool is None
    lane=capability("m91_1_riscv_platform_feasibility").milestone
    assert lane and lane.current_step==9
    assert lane.current_maturity=="sealed-rv64-deployment-evidence-frozen"
    assert "RISCV_G_STAGE_ISOLATION_PROVED" in lane.completed_claims
