# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json
import shutil
from pathlib import Path

import pytest
from pipeline.capability_registry import capability
from pipeline.microarch_policy import verify_microarch_policy


ARTIFACT = Path("examples/formalkernel/kernel/n150_mitigations.json")
PROFILE = json.loads(Path("examples/formalkernel/profiles/n150.json").read_text())


@pytest.mark.skipif(shutil.which("z3") is None, reason="real Z3 not installed")
def test_declared_n150_policy_is_complete_and_within_budget():
    verdict = verify_microarch_policy(ARTIFACT, PROFILE)
    assert verdict["status"] == "MICROARCH_MITIGATION_POLICY_PROVED"
    assert set(verdict["claims"]) == {
        "MICROARCH_MITIGATION_POLICY_PROVED", "MITIGATION_WCET_BUDGET_PROVED"}
    assert verdict["declared_cost_cycles"] == 105
    assert verdict["budget_cycles"] == 160
    assert verdict["runtime_cpuid_validated"] is False
    assert verdict["measured_cost_validated"] is False
    assert verdict["speculative_noninterference_proved"] is False
    assert len(verdict["artifact_sha256"]) == 64
    assert len(verdict["smt_sha256"]) == 64


def _mutate(tmp_path: Path, mutate) -> dict:
    artifact = json.loads(ARTIFACT.read_text())
    mutate(artifact)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(artifact))
    return verify_microarch_policy(path, PROFILE)


def test_missing_required_mitigation_fails_closed(tmp_path):
    verdict = _mutate(
        tmp_path, lambda value: value["selected_mitigations"].__setitem__(
            "verw_clear", False))
    assert verdict["status"] == "MICROARCH_POLICY_FAILED"
    assert verdict["code"] == "MICROARCH_MITIGATION_INCOMPLETE"


def test_declared_cost_above_budget_fails_closed(tmp_path):
    verdict = _mutate(
        tmp_path, lambda value: value.__setitem__("mitigation_budget_cycles", 100))
    assert verdict["code"] == "MITIGATION_WCET_BUDGET_EXCEEDED"


def test_runtime_or_speculative_overclaim_is_rejected(tmp_path):
    verdict = _mutate(
        tmp_path, lambda value: value.__setitem__(
            "speculative_noninterference_proved", True))
    assert verdict["code"] == "MICROARCH_EPISTEMIC_BOUNDARY_INVALID"


def test_selected_mitigation_requires_declared_cpuid_capability(tmp_path):
    verdict = _mutate(
        tmp_path, lambda value: value["cpuid"].__setitem__(
            "md_clear_available", False))
    assert verdict["code"] == "MITIGATION_CAPABILITY_UNAVAILABLE"


def test_registry_permanently_locks_stronger_microarch_claims():
    milestone = capability("m74_microarch_mitigation_policy").milestone
    assert milestone is not None
    assert milestone.step_status == "partial"
    assert milestone.completed_claims == (
        "MICROARCH_MITIGATION_POLICY_PROVED", "MITIGATION_WCET_BUDGET_PROVED")
    assert "SPECULATIVE_NONINTERFERENCE_PROVED" in milestone.claims_forbidden
    assert "RUNTIME_CPUID_PROFILE_PROVED" in milestone.claims_forbidden
    assert "MEASURED_MITIGATION_WCET_PROVED" in milestone.claims_forbidden
