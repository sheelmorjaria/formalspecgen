# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import shutil
from pathlib import Path

import pytest

from pipeline.capability_registry import capability
from pipeline.deployment_profile import BOUNDARY_LANES, verify_deployment_profile
from pipeline.unikernel_profile import verify_unikernel_build


MANIFEST = Path("examples/formalkernel/unikernel/Cargo.toml")


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo not installed")
def test_real_cargo_builds_feature_gated_no_std_profile():
    verdict = verify_unikernel_build(MANIFEST)
    assert verdict["status"] == "UNIKERNEL_BUILD_PROVED"
    assert verdict["feature"] == "unikernel"
    assert verdict["execution_level"] == "EL1"
    assert verdict["mmu_present"] is False
    assert verdict["syscalls_present"] is False
    assert verdict["ipc_present"] is False
    assert verdict["bootable_image_proved"] is False
    assert len(verdict["manifest_sha256"]) == 64
    assert len(verdict["source_sha256"]) == 64


def test_unikernel_rejects_every_boundary_lane():
    base = {"deployment": "unikernel", "unikernel_build": "Cargo.toml"}
    for lane in BOUNDARY_LANES:
        failed = verify_deployment_profile({**base, lane: "artifact.json"})
        assert failed["code"] == "UNIKERNEL_BOUNDARY_CONTRADICTION"


def test_m66_registry_records_the_claim_ceiling():
    milestone = capability("m66_unikernel_profile").milestone
    assert milestone is not None
    assert milestone.required_judges == ("Cargo",)
    assert milestone.completed_claims == ("UNIKERNEL_BUILD_PROVED",)
    assert "UNIKERNEL_BOOT_PROVED" in milestone.claims_forbidden
    assert "UNIKERNEL_FAULT_CONTAINMENT_PROVED" in milestone.claims_forbidden


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo not installed")
def test_unikernel_bundle_builds_and_records_stripped_boundaries():
    from pipeline.kernel_lattice import verify_kernel

    bundle = verify_kernel(
        "examples/formalkernel/kernel",
        ["examples/formalkernel/profiles/n150.json",
         "examples/formalkernel/profiles/r52.json"],
        manifest_name="unikernel.json")
    assert bundle["status"] == "KERNEL_EVIDENCE_BUNDLE"
    assert bundle["deployment"] == "unikernel"
    claims = {entry["claim"] for entry in bundle["claims"]}
    assert "UNIKERNEL_BUILD_PROVED" in claims
    assert "R52_TCM_PLACEMENT_PROVED" in claims
    assert "SMMU_CONFIGURATION_CORRESPONDENCE_PROVED" in claims
    assert "N150_PLATFORM_CONFIGURATION_PROVED" in claims
    assert "CERTIFICATION_TRACEABILITY_COMPLETE" in claims
    assert "MULTICORE_INTERFERENCE_CHANNELS_ENUMERATED" in claims
    assert "RCU_RECLAMATION_SAFETY_PROVED" in claims
    assert "FILESYSTEM_CRASH_ATOMICITY_PROVED" in claims
    assert "TCP_RESOURCE_CONTAINMENT_PROVED" in claims
    assert not ({"SPATIAL_ISOLATION_PROVED", "SYSCALL_BOUNDARY_PROVED",
                 "IPC_ENDPOINT_TABLE_PROVED", "USER_HEAP_CAPACITY_PROVED",
                 "SERVER_CAPABILITY_NONINTERFERENCE_PROVED"} & claims)
    stripped = next(entry for entry in bundle["boundaries"]
                    if entry["claim"] == "UNIKERNEL_BOUNDARIES_STRIPPED")
    assert stripped["omitted_lanes"] == sorted(BOUNDARY_LANES)
    assert stripped["runtime_behavior_proved"] is False
    assert "MICROARCH_MITIGATION_POLICY_PROVED" in claims
    assert "MITIGATION_WCET_BUDGET_PROVED" in claims
    assert "TOOL_QUALIFICATION_EVIDENCE_READY" in claims
    assert len(bundle["claims"]) == 40
