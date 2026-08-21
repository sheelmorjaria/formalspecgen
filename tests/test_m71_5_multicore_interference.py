# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.multicore_interference import (
    CHANNELS, enumerate_interference_channels,
)


ARTIFACT = Path("examples/formalkernel/kernel/multicore_interference.json")
PROFILES = [json.loads(Path("examples/formalkernel/profiles/n150.json").read_text()),
            json.loads(Path("examples/formalkernel/profiles/r52.json").read_text())]


def test_all_shared_hardware_channels_are_dispositioned():
    verdict = enumerate_interference_channels(ARTIFACT, PROFILES)
    assert verdict["status"] == "MULTICORE_INTERFERENCE_CHANNELS_ENUMERATED"
    assert verdict["targets"] == ["n150", "r52"]
    assert verdict["channel_count"] == 2 * len(CHANNELS) == 12
    assert verdict["target_wcet_interference_bound_validated"] is False
    assert verdict["physical_multicore_timing_proved"] is False
    assert verdict["judge_pending"] == \
        "authenticated_target_interference_measurements"


def test_missing_channel_or_untrusted_measurement_fails_closed(tmp_path):
    artifact = copy.deepcopy(json.loads(ARTIFACT.read_text()))
    artifact["targets"]["n150"]["channels"].pop("smt")
    drifted = tmp_path / "interference.json"
    drifted.write_text(json.dumps(artifact))
    assert enumerate_interference_channels(drifted, PROFILES)["code"] == \
        "INTERFERENCE_CHANNEL_SET_INCOMPLETE"

    artifact = copy.deepcopy(json.loads(ARTIFACT.read_text()))
    artifact["targets"]["r52"]["wcet_interference_measurement"] = {
        "max_inflation_ppm": 1}
    drifted.write_text(json.dumps(artifact))
    assert enumerate_interference_channels(drifted, PROFILES)["code"] == \
        "UNAUTHENTICATED_INTERFERENCE_MEASUREMENT"


def test_registry_keeps_measurement_claims_locked():
    milestone = capability("m71_5_multicore_interference").milestone
    assert milestone is not None
    assert milestone.current_step == 1
    assert milestone.maturity_requires_step == 2
    assert milestone.step_status == "partial"
    assert milestone.completed_claims == \
        ("MULTICORE_INTERFERENCE_CHANNELS_ENUMERATED",)
    assert "TARGET_WCET_INTERFERENCE_BOUND_VALIDATED" in \
        milestone.claims_forbidden
    assert "MULTICORE_TIMING_INTERFERENCE_PROVED" in \
        milestone.claims_forbidden
