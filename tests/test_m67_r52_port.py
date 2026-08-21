# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.r52_port import verify_r52_tcm_port


PORT = Path("examples/formalkernel/kernel/r52_port.json")
PROFILE = Path("examples/formalkernel/profiles/r52.json")


def test_r52_tcm_map_is_bound_to_linker_and_profile():
    verdict = verify_r52_tcm_port(PORT, json.loads(PROFILE.read_text()))
    assert verdict["status"] == "R52_TCM_PLACEMENT_PROVED"
    assert verdict["judge"] == "deterministic_gate"
    assert verdict["itcm_bytes"] == verdict["dtcm_bytes"] == 16384
    assert verdict["kernel_pool"] == [16384, 32768]
    assert verdict["physical_boot_proved"] is False
    assert verdict["measured_wcet_proved"] is False
    assert verdict["judge_pending"] == "physical_cortex_r52_board"


def test_r52_profile_or_linker_drift_fails_closed(tmp_path):
    profile = json.loads(PROFILE.read_text())
    profile["memory_map"]["kernel_pools"]["tcm_kernel"] = [0, 16384]
    assert verify_r52_tcm_port(PORT, profile)["code"] == \
        "R52_KERNEL_POOL_OUTSIDE_DTCM"

    artifact = copy.deepcopy(json.loads(PORT.read_text()))
    artifact["linker_sha256"] = "0" * 64
    drifted = tmp_path / "r52_port.json"
    artifact["linker_script"] = str(
        Path("examples/formalkernel/boot/layout-r52.ld").resolve())
    drifted.write_text(json.dumps(artifact))
    assert verify_r52_tcm_port(drifted, json.loads(PROFILE.read_text()))[
        "code"] == "R52_LINKER_HASH_MISMATCH"


def test_m67_registry_forbids_physical_claim_inflation():
    milestone = capability("m67_cortex_r52_port").milestone
    assert milestone is not None
    assert milestone.completed_claims == ("R52_TCM_PLACEMENT_PROVED",)
    assert "R52_PHYSICAL_BOOT_PROVED" in milestone.claims_forbidden
    assert "R52_MEASURED_WCET_PROVED" in milestone.claims_forbidden
