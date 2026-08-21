# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.r52_smmu import verify_r52_smmu


ARTIFACT = Path("examples/formalkernel/kernel/r52_smmu.json")
PROFILE = Path("examples/formalkernel/profiles/r52.json")


def test_smmu_streams_match_dma_contracts_and_protect_tcm():
    verdict = verify_r52_smmu(ARTIFACT, json.loads(PROFILE.read_text()))
    assert verdict["status"] == "SMMU_CONFIGURATION_CORRESPONDENCE_PROVED"
    assert verdict["stream_ids"] == [32, 33]
    assert verdict["protected_ranges"] == {"tcm_kernel": [16384, 32768]}
    assert verdict["physical_dma_block_proved"] is False
    assert verdict["external_io_safety_proved"] is False
    assert verdict["judge_pending"] == "physical_r52_smmu_fault_injection"


def test_smmu_policy_drift_fails_closed(tmp_path):
    artifact = copy.deepcopy(json.loads(ARTIFACT.read_text()))
    artifact["streams"]["nic_dev"]["allowed_dma"] = [16384, 16896]
    drifted = tmp_path / "r52_smmu.json"
    drifted.write_text(json.dumps(artifact))
    assert verify_r52_smmu(drifted, json.loads(PROFILE.read_text()))[
        "code"] == "R52_SMMU_DMA_CONTRACT_MISMATCH"

    artifact = copy.deepcopy(json.loads(ARTIFACT.read_text()))
    artifact["physical_test"]["observed"] = "claimed_without_board"
    drifted.write_text(json.dumps(artifact))
    assert verify_r52_smmu(drifted, json.loads(PROFILE.read_text()))[
        "code"] == "R52_SMMU_PHYSICAL_PROTOCOL_INVALID"


def test_m68_registry_names_incomplete_physical_step():
    milestone = capability("m68_r52_smmu_validation").milestone
    assert milestone is not None
    assert milestone.current_step == 1
    assert milestone.maturity_requires_step == 2
    assert milestone.step_status == "partial"
    assert milestone.completed_claims == \
        ("SMMU_CONFIGURATION_CORRESPONDENCE_PROVED",)
    assert "EXTERNAL_IO_SAFETY_PROVED" in milestone.claims_forbidden
    assert "PHYSICAL_SMMU_DMA_BLOCK_PROVED" in milestone.claims_forbidden
