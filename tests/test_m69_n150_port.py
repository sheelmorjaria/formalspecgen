# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.n150_port import verify_n150_port


ARTIFACT = Path("examples/formalkernel/kernel/n150_port.json")
PROFILE = Path("examples/formalkernel/profiles/n150.json")


def test_n150_layout_and_vtd_correspond_to_profile():
    verdict = verify_n150_port(ARTIFACT, json.loads(PROFILE.read_text()))
    assert verdict["status"] == "N150_PLATFORM_CONFIGURATION_PROVED"
    assert verdict["memory_model"] == "x86_tso"
    assert verdict["requester_ids"] == ["00:17.0", "00:1f.6"]
    assert verdict["physical_boot_proved"] is False
    assert verdict["physical_vtd_proved"] is False
    assert verdict["physical_tso_conformance_proved"] is False
    assert verdict["judge_pending"] == "physical_intel_n150"


def test_n150_profile_and_physical_result_drift_fail_closed(tmp_path):
    profile = json.loads(PROFILE.read_text())
    profile["memory_model"] = "armv8_sc"
    assert verify_n150_port(ARTIFACT, profile)["code"] == \
        "N150_PROFILE_MISMATCH"

    artifact = copy.deepcopy(json.loads(ARTIFACT.read_text()))
    artifact["physical_tests"]["boot_observed"] = True
    drifted = tmp_path / "n150_port.json"
    artifact["linker_script"] = str(
        Path("examples/formalkernel/boot/layout-n150.ld").resolve())
    drifted.write_text(json.dumps(artifact))
    assert verify_n150_port(drifted, json.loads(PROFILE.read_text()))[
        "code"] == "N150_PHYSICAL_PROTOCOL_INVALID"


def test_m69_registry_keeps_physical_stage_pending():
    milestone = capability("m69_intel_n150_port").milestone
    assert milestone is not None
    assert milestone.current_step == 1
    assert milestone.maturity_requires_step == 2
    assert milestone.step_status == "partial"
    assert milestone.completed_claims == ("N150_PLATFORM_CONFIGURATION_PROVED",)
    assert "N150_PHYSICAL_BOOT_PROVED" in milestone.claims_forbidden
    assert "N150_PHYSICAL_VTD_PROVED" in milestone.claims_forbidden
