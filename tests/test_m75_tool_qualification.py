# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

from pipeline.capability_registry import capability
from pipeline.tool_qualification import verify_tool_qualification_evidence


ARTIFACT = Path("examples/formalkernel/kernel/tool_qualification.json")
ORACLE = Path("pipeline/qualification_oracle.py")


def test_independent_oracle_checks_reviewed_golden_corpus():
    verdict = verify_tool_qualification_evidence(ARTIFACT, ORACLE)
    assert verdict["status"] == "TOOL_QUALIFICATION_EVIDENCE_READY"
    assert verdict["vector_count"] == 3
    assert verdict["do330_qualified"] is False
    assert verdict["general_transformation_correctness_proved"] is False
    assert len(verdict["artifact_sha256"]) == 64
    assert len(verdict["oracle_sha256"]) == 64


def _write(tmp_path, artifact):
    path = tmp_path / "qualification.json"
    path.write_text(json.dumps(artifact))
    return verify_tool_qualification_evidence(path, ORACLE)


def test_serializer_semantic_drift_fails_closed(tmp_path):
    artifact = json.loads(ARTIFACT.read_text())
    artifact["vectors"][0]["emitted_ast"]["state"]["count"]["max"] = 5
    verdict = _write(tmp_path, artifact)
    assert verdict["status"] == "TOOL_QUALIFICATION_EVIDENCE_FAILED"
    assert verdict["code"] == "AST_SEMANTIC_DRIFT"


def test_smt_mapping_drift_fails_closed(tmp_path):
    artifact = json.loads(ARTIFACT.read_text())
    artifact["vectors"][2]["emitted_assertions"][0] = \
        "(assert (= hazard_MDS false))"
    verdict = _write(tmp_path, artifact)
    assert verdict["code"] == "SMT_SEMANTIC_DRIFT"


def test_qualification_overclaim_is_rejected(tmp_path):
    artifact = json.loads(ARTIFACT.read_text())
    artifact["do330_qualified"] = True
    verdict = _write(tmp_path, artifact)
    assert verdict["code"] == "TOOL_QUALIFICATION_OVERCLAIM"


def test_oracle_importing_system_under_test_is_rejected(tmp_path):
    oracle = tmp_path / "oracle.py"
    oracle.write_text("import pipeline\n")
    verdict = verify_tool_qualification_evidence(ARTIFACT, oracle)
    assert verdict["code"] == "ORACLE_IMPORTS_SYSTEM_UNDER_TEST"


def test_registry_locks_self_qualification_claims():
    milestone = capability("m75_tool_qualification_evidence").milestone
    assert milestone is not None
    assert milestone.current_maturity == "qualification-evidence"
    assert milestone.step_status == "partial"
    assert "DO330_QUALIFIED" in milestone.claims_forbidden
    assert "TOOL_CORRECTNESS_PROVED" in milestone.claims_forbidden
