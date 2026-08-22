# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.riscv_feasibility import inspect_riscv_feasibility
from pipeline.riscv_platform_promotion import promote_riscv_platform


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples/formalkernel/profiles/riscv64-qemu.candidate.json"
EVIDENCE = ROOT / "examples/formalkernel/kernel/m91_riscv_feasibility.json"


def test_exact_candidate_feasibility_is_reproducible_and_non_claiming():
    stored = json.loads(EVIDENCE.read_text())
    assert inspect_riscv_feasibility(ROOT, PROFILE) == stored
    assert stored["status"] == "RISCV_PLATFORM_FEASIBILITY_RECORDED"
    assert stored["claim"] == "NO_PROOF"
    assert stored["profile_candidate"]["review_status"] == "HUMAN_REVIEW_PENDING"
    assert stored["profile_candidate"]["sha256"] == (
        "ee9aac65f24fefd33279729bae609f2c9a9338683c786f3947d53dae1b67233a")
    assert stored["blockers"] == []
    assert stored["toolchain"]["rust_target"]["status"] == "INSTALLED"
    assert stored["emulator"]["machine_probe"] == {
        "machine": "virt", "status": "AVAILABLE",
        "aclint": "AVAILABLE_CONFIGURABLE",
        "aia": "AVAILABLE_APLIC_IMSIC_CONFIGURABLE",
        "h_extension": "AVAILABLE_IN_RV64_CPU_MODEL",
        "iommu": "RISCV_IOMMU_DEVICE_ABSENT",
    }
    assert stored["claims_locked"]


def test_profile_pins_narrow_platform_and_unhashed_official_spec_releases():
    profile = json.loads(PROFILE.read_text())
    assert profile["isa"] == "RV64GC"
    assert profile["page_table_mode"] == "Sv39"
    assert profile["privilege_modes"] == ["M", "S", "U"]
    assert profile["qemu_machine"] == "virt"
    assert profile["virtualization"]["h_extension"] == "desired_unprobed"
    assert profile["iommu"]["availability"] == "desired_unprobed"
    assert all(item["official_url"].startswith("https://docs.riscv.org/")
               for item in profile["normative_specifications"])
    assert all(item["content_sha256"] is None and
               item["hash_status"] == "JUDGE_PENDING_UNTIL_VENDORED"
               for item in profile["normative_specifications"])


def test_overlapping_memory_or_fake_unvendored_spec_hash_fails_closed(tmp_path):
    profile = json.loads(PROFILE.read_text())
    profile["memory_map"]["uart0"] = dict(profile["memory_map"]["plic"])
    overlap = tmp_path / "overlap.json"
    overlap.write_text(json.dumps(profile))
    result = inspect_riscv_feasibility(ROOT, overlap)
    assert result["status"] == "RISCV_PROFILE_CANDIDATE_INVALID"
    assert any(item.startswith("memory_overlap:") for item in result["failures"])

    profile = json.loads(PROFILE.read_text())
    profile["normative_specifications"][0]["content_sha256"] = "0" * 64
    fake_hash = tmp_path / "fake-hash.json"
    fake_hash.write_text(json.dumps(profile))
    result = inspect_riscv_feasibility(ROOT, fake_hash)
    assert result["status"] == "RISCV_PROFILE_CANDIDATE_INVALID"
    assert "unvendored_spec_hash_overclaim" in result["failures"]


def test_m91_registry_advances_only_the_reviewed_privilege_model_claim():
    milestone = capability("m91_1_riscv_platform_feasibility").milestone
    assert milestone is not None
    assert milestone.current_step >= 2
    assert "RISCV_PRIVILEGE_TRANSITION_MODEL_PROVED" in milestone.completed_claims
    assert {stage.claim for stage in milestone.claims} == {
        "RISCV_PRIVILEGE_TRANSITION_MODEL_PROVED",
        "RISCV_SPATIAL_ISOLATION_PROVED",
        "RISCV_INTERRUPT_ROUTING_MODEL_PROVED",
        "RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED",
        "RISCV_G_STAGE_ISOLATION_PROVED",
        "RISCV_GUEST_INTERRUPT_ROUTING_MODEL_PROVED",
        "RISCV_GUEST_ISOLATION_MODEL_PROVED",
        "PROOF_CARRYING_BINARY_VALIDATED",
    }


def test_platform_promotion_is_hash_bound_and_human_only(tmp_path):
    try:
        promote_riscv_platform(ROOT, accept_candidate_sha256="0" * 64)
    except ValueError as exc:
        assert "candidate hash mismatch" in str(exc)
    else:
        raise AssertionError("wrong profile hash was accepted")
    spec = capability("promote_riscv_platform")
    assert spec.trust_action is True
    assert spec.mcp_tool is None
