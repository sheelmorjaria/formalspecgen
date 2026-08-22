# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M91.4 reviewed-policy boundary for APLIC/IMSIC S-mode routing."""
from __future__ import annotations
import copy
import json
from pathlib import Path
from pipeline.capability_registry import capability
from pipeline.riscv_aia import (render_aia_model, validate_aia_policy,
                                verify_aia_evidence)
from pipeline.riscv_aia_promotion import promote_riscv_aia_policy

ROOT = Path(__file__).parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"

def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def test_promoted_policy_and_published_tlc_evidence_are_exactly_bound():
    policy = _json(KERNEL / "riscv_aia_policy.json")
    qualification = _json(KERNEL / "riscv_aia.qualification.json")
    assert validate_aia_policy(policy) == []
    assert qualification["claim"] == "NO_PROOF"
    assert qualification["base_status"] == "VERIFIED"
    assert qualification["semantic_mutations_rejected"] == 5
    artifact = _json(KERNEL / "riscv_aia.json")
    evidence = _json(KERNEL / artifact["validation"])
    verdict = verify_aia_evidence(artifact, ROOT, evidence)
    assert verdict["status"] == "RISCV_AIA_EVIDENCE_BOUND"
    assert verdict["distinct_states"] == 37
    assert evidence["hardware_interrupt_delivery_proved"] is False
    assert evidence["aia_implementation_refinement_proved"] is False

def test_model_contains_aplic_imsic_reconfiguration_and_m91_trap_path():
    policy = _json(KERNEL / "riscv_aia_policy.reviewed.json")
    tla, cfg = render_aia_model(policy)
    for name in ("AplicRoute", "ImsicRecord", "SupervisorTrap", "ValidateHandler",
                 "Acknowledge", "Reconfigure"):
        assert name in tla
    assert "TrapUsesValidatedM91Path" in cfg
    assert "DisabledSourceNeverActive" in cfg
    assert 'epoch\' = "Reconfigured"' in tla

def test_policy_rejects_wrong_hart_file_duplicate_id_and_enabled_debug():
    policy = _json(KERNEL / "riscv_aia_policy.json")
    wrong = copy.deepcopy(policy)
    wrong["grants"][0]["initial"]["hart"] = 9
    assert any(item.startswith("route:") for item in validate_aia_policy(wrong))
    wrong = copy.deepcopy(policy)
    wrong["grants"][0]["initial"]["imsic_address"] += 4096
    assert "imsic_address:initial" in validate_aia_policy(wrong)
    wrong = copy.deepcopy(policy)
    wrong["grants"][1]["initial"].update(
        hart=0, interrupt_id=32, imsic_address=671088640)
    assert "duplicate_identity:initial" in validate_aia_policy(wrong)
    wrong = copy.deepcopy(policy)
    wrong["grants"][2]["enabled"] = True
    assert "disabled_source" in validate_aia_policy(wrong)

def test_promotion_is_human_only_and_wrong_hash_fails():
    try:
        promote_riscv_aia_policy(ROOT, accept_candidate_sha256="0" * 64)
    except ValueError as exc:
        assert "candidate hash mismatch" in str(exc)
    else:
        raise AssertionError("wrong candidate hash accepted")
    spec = capability("promote_riscv_aia_policy")
    assert spec.trust_action is True and spec.mcp_tool is None
    lane = capability("m91_1_riscv_platform_feasibility").milestone
    assert lane is not None and lane.current_step >= 4
    assert "RISCV_INTERRUPT_ROUTING_MODEL_PROVED" in lane.completed_claims
