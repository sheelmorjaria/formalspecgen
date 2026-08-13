# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Real-OpenJML E2E for multi-tier composition over the reviewed smart_lock domain."""
import json
from pathlib import Path

import pytest

from pipeline import composition_render

pytestmark = pytest.mark.toolchain

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "domains" / "examples" / "composition" / "secure_entry.composition.json"
V2_DIR = REPO / "domains" / "v2"


def _example_value() -> dict:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def test_composition_real_esc_proves_orchestrator_glue(openjml_tool):
    """compose runs check + real ESC internally; require the scoped proof claim."""
    verdict = composition_render.verify_composition(_example_value(), V2_DIR)
    assert verdict["status"] == "COMPOSITION_VERIFIED", verdict
    assert verdict["claim"] == "SCOPED_COMPOSITION_PROOF"
    assert verdict["exit_code"] == 0
    assert verdict["concurrent_linearizability_proved"] is False
    assert {"SmartLock.java", "SmartLockAPI.java",
            "SecureCloseAndLockOrchestrator.java",
            "PanelSecuresEntryOrchestrator.java"} <= set(verdict["files"])
    # Deterministic effect bodies must be present so ESC has real code to prove.
    assert "this.door_state = 1;" in verdict["files"]["SmartLock.java"]


def test_reverify_real_esc_after_smart_lock_change(openjml_tool):
    verdict = composition_render.reverify_composition(
        _example_value(), "smart_lock", V2_DIR)
    assert verdict["status"] == "REVERIFIED", verdict
    assert verdict["impacted_components"] == ["access_panel", "lock"]
    assert verdict["impacted_use_cases"] == ["SecureCloseAndLock", "PanelSecuresEntry"]
