# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations
import copy, json
from pathlib import Path
import pytest
from pipeline.capability_registry import capability
from pipeline.riscv_deployment import (MODEL_CLAIMS, PARKED, SCOPE,
    seal_riscv_deployment_evidence, validate_riscv_binary_evidence)

ROOT=Path(__file__).parents[1]; K=ROOT/"examples/formalkernel/kernel"
def load(name): return json.loads((K/name).read_text())

def test_exact_rv64_elf_has_one_honest_applicable_claim():
    evidence=load("m91_riscv_binary_evidence.json")
    verdict=validate_riscv_binary_evidence(evidence,ROOT)
    assert verdict == {"status":"PROOF_CARRYING_BINARY_VALIDATED",
        "claim":"PROOF_CARRYING_BINARY_VALIDATED", "scope":SCOPE,
        "elf_sha256":evidence["elf"]["sha256"], "applicable_claims":1,
        "coverage":"1/1"}
    assert [x["claim"] for x in evidence["applicable_claims"]] == ["SYSTEM_COMPOSITION_PROVED"]
    assert evidence["elf"]["identity"]["machine"] == "RISC-V"
    assert evidence["elf"]["identity"]["entry_point"] == 0x80200000

def test_uncompiled_guest_stack_is_excluded_not_inherited():
    evidence=load("m91_riscv_binary_evidence.json")
    inventory={x["claim"]:x["status"] for x in evidence["compiled_mechanism_inventory"]}
    assert all(inventory[claim] == "MODEL_ONLY_NOT_COMPILED" for claim in MODEL_CLAIMS)
    assert all(inventory[claim] == "PARKED" for claim in PARKED)
    assert not any(x["claim"].startswith("RISCV_") for x in evidence["applicable_claims"])

def test_boot_observation_is_empirical_and_matches_compiled_inventory():
    boot=load("m91_riscv_boot.validation.json")
    assert boot["claim"] == "RISCV_QEMU_BOOT_OBSERVED"
    assert boot["hardware_semantics_proved"] is False
    assert boot["transcript"][-2].startswith("NOT_COMPILED su_transition sv39 aia")

def test_invalidation_is_minimal_and_reproducibility_is_raw():
    invalidation=load("m91_riscv_invalidation.validation.json")
    statuses={x["mutation"]:x["status"] for x in invalidation["cases"]}
    assert statuses["compiled_rv64_source"] == "REBUILD_REQUIRED"
    assert statuses["m91_guest_model_evidence"] == "UNCHANGED_OUTSIDE_APPLICABLE_CLOSURE"
    assert statuses["aarch64_binary_evidence"] == "UNCHANGED_OUTSIDE_APPLICABLE_CLOSURE"
    assert statuses["fabricate_guest_claim_applicability"] == "HARD_REFUSAL"
    repro=load("m91_riscv_reproducibility.validation.json")
    assert repro["claims_minted"] == ["REPRODUCIBLE_RISCV_BINARY_BUILD_OBSERVED",
                                      "REPRODUCIBLE_RISCV_EVIDENCE_ROOT_OBSERVED"]
    assert repro["raw_elf_reproducible"] is True
    assert repro["normalization"]["elf_bytes"] == "NONE"

def test_inventory_inflation_and_component_drift_fail_closed():
    evidence=load("m91_riscv_binary_evidence.json")
    inflated=copy.deepcopy(evidence)
    next(x for x in inflated["compiled_mechanism_inventory"]
         if x["claim"]=="RISCV_GUEST_ISOLATION_MODEL_PROVED")["status"]="COMPILED_AND_APPLICABLE"
    assert validate_riscv_binary_evidence(inflated,ROOT)["status"] == "M91_RISCV_INVENTORY_INFLATION"
    stale=copy.deepcopy(evidence); stale["applicable_claims"][0]["dependencies"][0]["sha256"]="0"*64
    assert validate_riscv_binary_evidence(stale,ROOT)["claim"] == "NO_PROOF"

def test_human_seal_requires_both_exact_hashes_and_stays_outside_mcp():
    with pytest.raises(ValueError,match="ELF hash mismatch"):
        seal_riscv_deployment_evidence(ROOT,accept_elf_sha256="0"*64,
            accept_evidence_root_sha256="0"*64,release="m91-test")
    cap=capability("seal_riscv_deployment_evidence")
    assert cap.trust_action and cap.mcp_tool is None

def test_registry_reports_sealed_rv64_deployment_frozen():
    lane=capability("m91_1_riscv_platform_feasibility").milestone
    assert lane and lane.current_step==9 and lane.step_status=="complete"
    assert lane.current_maturity=="sealed-rv64-deployment-evidence-frozen"
    assert "PROOF_CARRYING_BINARY_VALIDATED" in lane.completed_claims

def test_sealed_release_binds_residuals_and_is_not_a_proof_claim():
    release=json.loads((ROOT/"examples/formalkernel/releases/formalkernel-m91-qemu-riscv64-2026.08.22.sealed.json").read_text())
    binary=load("m91_riscv_binary_evidence.json")
    assert release["status"] == "SEALED_DEPLOYMENT_EVIDENCE"
    assert release["claim"] == "NO_PROOF"
    assert release["binary"]["sha256"] == binary["elf"]["sha256"]
    assert release["applicable_claims"] == ["SYSTEM_COMPOSITION_PROVED"]
    assert set(release["parked_claims"]) == set(PARKED)
