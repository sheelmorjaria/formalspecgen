# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations
import copy, hashlib, json
from pathlib import Path
from pipeline.capability_registry import capability
from pipeline.riscv_guest_isolation_composition import verify_guest_isolation_evidence

ROOT=Path(__file__).parents[1]; K=ROOT/"examples/formalkernel/kernel"
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def test_composed_guest_isolation_binds_all_three_component_evidences():
    artifact=json.loads((K/"riscv_guest_isolation_composition.json").read_text())
    evidence=json.loads((K/artifact["validation"]).read_text())
    verdict=verify_guest_isolation_evidence(artifact,ROOT,evidence)
    assert verdict["status"] == "RISCV_GUEST_ISOLATION_EVIDENCE_BOUND"
    assert evidence["scope"] == "reviewed_qemu_virt_hs_vs_gstage_imsic_composition"
    assert evidence["vmidlen_assumption"] == 7
    assert evidence["guest_transition_evidence_sha256"] == sha(K/"riscv_hs_vs.validation.json")
    assert evidence["gstage_evidence_sha256"] == sha(K/"riscv_gstage.validation.json")
    assert evidence["guest_interrupt_evidence_sha256"] == sha(K/"riscv_vs_imsic.validation.json")
    assert evidence["mutations_executed"] == evidence["mutations_rejected"] == 9
    assert len(evidence["mutation_results"]) == 9
    assert evidence["composition_model_sha256"] == evidence["generated_tla_sha256"]

def test_composition_preserves_physical_and_iommu_boundaries():
    e=json.loads((K/"riscv_guest_isolation_composition.validation.json").read_text())
    for key in ("qemu_h_extension_semantics_proved", "hardware_g_stage_walk_proved",
                "hardware_guest_interrupt_delivery_proved", "compiled_hypervisor_refinement_proved",
                "physical_guest_isolation_proved", "guest_device_dma_isolation_proved",
                "direct_device_assignment_proved", "iommu_guest_msi_remap_proved"):
        assert e[key] is False

def test_substituted_component_hash_fails_closed():
    a=json.loads((K/"riscv_guest_isolation_composition.json").read_text())
    e=json.loads((K/a["validation"]).read_text()); e["gstage_evidence_sha256"]="0"*64
    assert verify_guest_isolation_evidence(a,ROOT,e)["claim"] == "NO_PROOF"

def test_registry_advances_to_composed_guest_isolation():
    lane=capability("m91_1_riscv_platform_feasibility").milestone
    assert lane and lane.current_step == 9 and lane.step_status == "complete"
    assert lane.current_maturity == "sealed-rv64-deployment-evidence-frozen"
    assert "RISCV_GUEST_ISOLATION_MODEL_PROVED" in lane.completed_claims
