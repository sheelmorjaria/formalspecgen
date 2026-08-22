# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.certification_matrix import verify_certification_traceability


ARTIFACT = Path("examples/formalkernel/kernel/certification_traceability.json")


def _claims(deployment: str) -> list[dict]:
    artifact = json.loads(ARTIFACT.read_text())
    return [{"claim": row["claim"], "scope": "test", "profile": None,
             "source": f"{row['id']}.json", "judge": "test_judge"}
            for row in artifact["requirements"]
            if deployment in row["profiles"]]


def test_complete_matrix_is_not_a_certification_claim():
    boundaries = [
        {"claim": "R52_PHYSICAL_EXECUTION_PENDING"},
        {"claim": "R52_PHYSICAL_SMMU_VALIDATION_PENDING"},
        {"claim": "N150_PHYSICAL_EXECUTION_PENDING"},
    ]
    verdict = verify_certification_traceability(
        ARTIFACT, "microkernel", _claims("microkernel"), boundaries)
    assert verdict["status"] == "CERTIFICATION_TRACEABILITY_COMPLETE"
    assert verdict["mapped"] == verdict["total"] == 31
    assert verdict["certification_ready"] is False
    assert verdict["regulatory_certification_proved"] is False
    assert len(verdict["physical_closures_pending"]) == 3
    assert len(verdict["evidence_fingerprint_sha256"]) == 64


def test_missing_or_pending_evidence_never_maps():
    claims = _claims("unikernel")
    claims[0]["status"] = "judge_pending"
    verdict = verify_certification_traceability(
        ARTIFACT, "unikernel", claims, [])
    assert verdict["status"] == "CERTIFICATION_TRACEABILITY_PENDING"
    assert verdict["claim"] == "NO_PROOF"
    assert verdict["missing_requirements"]


def test_m70_registry_forbids_certification_inflation():
    milestone = capability("m70_hard_realtime_traceability").milestone
    assert milestone is not None
    assert milestone.step_status == "partial"
    assert milestone.current_maturity == "pre-certification"
    assert milestone.completed_claims == \
        ("CERTIFICATION_TRACEABILITY_COMPLETE",)
    assert "DO_178C_LEVEL_A_CERTIFIED" in milestone.claims_forbidden
    assert "ISO_26262_CERTIFIED" in milestone.claims_forbidden
    assert "PHYSICAL_HARD_REALTIME_PROVED" in milestone.claims_forbidden
