# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M91.2 reviewed-profile-bound RISC-V privilege transition theorem."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pipeline.capability_registry import capability
from pipeline.riscv_privilege_transition import (
    render_riscv_privilege_transition, verify_riscv_privilege_evidence,
    write_riscv_privilege_validation)

ROOT = Path(__file__).parents[1]
KERNEL = ROOT / "examples/formalkernel/kernel"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_m91_2_published_tlc_evidence_is_exactly_bound_and_scoped():
    artifact = _json(KERNEL / "riscv_privilege_transition.json")
    evidence = _json(KERNEL / artifact["validation"])
    verdict = verify_riscv_privilege_evidence(artifact, ROOT, evidence)
    assert verdict["status"] == "RISCV_PRIVILEGE_TRANSITION_EVIDENCE_BOUND"
    assert evidence["scope"] == "reviewed_qemu_virt_smode_umode_trap_return"
    assert evidence["distinct_states"] >= 7
    assert evidence["qemu_semantics_proved"] is False
    assert evidence["hardware_privilege_transition_proved"] is False
    assert evidence["compiled_trap_vector_refinement_proved"] is False
    assert evidence["physical_execution_proved"] is False


def test_m91_2_model_covers_preparation_trap_validation_and_hostile_resume():
    tla, cfg = render_riscv_privilege_transition()
    for action in ("PrepareUser", "SretToUser", "UserTrap", "ValidateDispatch",
                   "RejectSupervisorResume", "RemainRejected", "ReturnToUser"):
        assert action in tla
    assert 'requestedResume\' \\in {"U", "S"}' in tla
    assert 'satpRoot = "ReviewedRoot"' in tla
    assert "TrappedReturnRequiresValidatedDispatch" in cfg
    assert "UserCannotSelectSupervisorResume" in cfg
    with pytest.raises(ValueError, match="RISCV_PRIVILEGE_MODULE_INVALID"):
        render_riscv_privilege_transition("bad-module")


def test_m91_2_profile_and_evidence_drift_fail_closed(tmp_path):
    artifact = _json(KERNEL / "riscv_privilege_transition.json")
    evidence = _json(KERNEL / artifact["validation"])
    drifted = copy.deepcopy(artifact)
    drifted["reviewed_profile"]["sha256"] = "0" * 64
    assert verify_riscv_privilege_evidence(drifted, ROOT, evidence)["claim"] == "NO_PROOF"
    weakened = copy.deepcopy(evidence)
    weakened["properties"].remove("USER_CANNOT_SELECT_SUPERVISOR_RESUME")
    assert verify_riscv_privilege_evidence(artifact, ROOT, weakened)["claim"] == "NO_PROOF"
    with pytest.raises(ValueError, match="PUBLICATION_REFUSED"):
        write_riscv_privilege_validation(tmp_path / "no.json", {"status": "failed"})


def test_m91_2_registry_mints_only_model_claim_and_parks_iommu():
    lane = capability("m91_1_riscv_platform_feasibility").milestone
    assert lane is not None and lane.current_step >= 2
    assert "TLC" in lane.required_judges
    assert "RISCV_PRIVILEGE_TRANSITION_MODEL_PROVED" in lane.completed_claims
    assert "RISCV_HARDWARE_PRIVILEGE_TRANSITION_PROVED" in lane.claims_forbidden
    assert "RISCV_COMPILED_TRAP_VECTOR_REFINEMENT_PROVED" in lane.claims_forbidden
    iommu = capability("m91_riscv_iommu").milestone
    assert iommu is not None
    assert iommu.current_maturity == "parked-no-qemu-iommu-device"
    assert iommu.completed_claims == ()
