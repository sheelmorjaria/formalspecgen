# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.vfs_crash import (render_vfs_crash_model,
                                verify_vfs_crash_evidence)


ROOT = Path("examples/formalkernel/kernel/vfs")
ARTIFACT = json.loads((ROOT / "journal.json").read_text())
EVIDENCE = json.loads((ROOT / "journal.validation.json").read_text())


def test_real_tlc_envelope_is_bound_to_exact_crash_model():
    verdict = verify_vfs_crash_evidence(ARTIFACT, EVIDENCE)
    assert verdict["status"] == "VFS_CRASH_EVIDENCE_BOUND"
    assert verdict["claim"] == "FILESYSTEM_CRASH_ATOMICITY_PROVED"
    assert verdict["scope"] == "declared_persistence_contract"
    assert verdict["distinct_states"] == 39
    assert verdict["physical_fua_semantics_proved"] is False
    assert verdict["device_firmware_proved"] is False
    assert verdict["crash_injection_validated"] is False


def test_model_contains_reorder_torn_write_and_crash_during_recovery():
    tla, cfg = render_vfs_crash_model(ARTIFACT["module"])
    assert "FlushIntent" in tla and "FlushData" in tla
    assert 'log\' \\in {"Intent", "Torn"}' in tla
    assert 'fs\' \\in {1, 2}' in tla
    assert 'phase \\in {"Active", "RecoveringClear"}' in tla
    assert "INVARIANT CrashAtomicity" in cfg


def test_contract_or_evidence_drift_fails_closed():
    artifact = copy.deepcopy(ARTIFACT)
    artifact["persistence_contract"]["recovery_may_crash"] = False
    assert verify_vfs_crash_evidence(artifact, EVIDENCE)["claim"] == "NO_PROOF"
    evidence = copy.deepcopy(EVIDENCE)
    evidence["generated_tla_sha256"] = "0" * 64
    assert verify_vfs_crash_evidence(ARTIFACT, evidence)["code"] == \
        "VFS_CRASH_EVIDENCE_BINDING_MISMATCH"


def test_m72_registry_keeps_physical_device_claims_locked():
    milestone = capability("m72_crash_consistent_vfs").milestone
    assert milestone is not None
    assert milestone.current_step == 1
    assert milestone.maturity_requires_step == 2
    assert milestone.completed_claims == ("FILESYSTEM_CRASH_ATOMICITY_PROVED",)
    assert "PHYSICAL_FUA_SEMANTICS_PROVED" in milestone.claims_forbidden
    assert "PHYSICAL_CRASH_INJECTION_VALIDATED" in milestone.claims_forbidden
