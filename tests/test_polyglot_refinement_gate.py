# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline import polyglot_implementation as implementation
from pipeline.polyglot_refinement_gate import polyglot_v2_refinement_gate
from pipeline.v2_acsl_serializer import render_reviewed_v2_acsl_file
from pipeline.v2_prusti_serializer import render_reviewed_v2_prusti_file


ROOT = Path(__file__).resolve().parents[1]
REVIEWED = ROOT / "domains/v2/digital_safe.json"
EVIDENCE = ROOT / "domains/candidates/digital_safe.v2.validation.json"


@pytest.mark.parametrize("language,renderer", [
    ("c", render_reviewed_v2_acsl_file),
    ("rust", render_reviewed_v2_prusti_file),
])
def test_polyglot_gate_binds_canonical_surface_and_native_proof(language, renderer):
    _, source = renderer(REVIEWED)
    result = polyglot_v2_refinement_gate(
        REVIEWED, EVIDENCE, source, source, language, backend_verified=True)
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "SOURCE_MODEL_REFINEMENT"
    assert result["source_refinement_proved"]
    assert not result["concurrent_linearizability_proved"]
    assert len(result["obligations"]) == 5
    assert all(row["status"] == "PROVED" for row in result["obligations"])
    assert len(result["certificate_sha256"]) == 64


def test_polyglot_gate_fails_closed_without_proof_or_with_surface_drift():
    _, source = render_reviewed_v2_acsl_file(REVIEWED)
    assert polyglot_v2_refinement_gate(
        REVIEWED, EVIDENCE, source, source, "c",
        backend_verified=False)["code"] == "backend_not_verified"
    drifted = source.replace("counter->safe_state == 1;",
                             "counter->safe_state == 0;", 1)
    assert polyglot_v2_refinement_gate(
        REVIEWED, EVIDENCE, drifted, drifted, "c",
        backend_verified=True)["code"] == "canonical_contract_mismatch"
    assert polyglot_v2_refinement_gate(
        REVIEWED, EVIDENCE, source, source, "java",
        backend_verified=True)["code"] == "unsupported_language"
    assert polyglot_v2_refinement_gate(
        REVIEWED, EVIDENCE, source, source, "c",
        backend_verified=True, tlc_verified=False)["code"] == "tlc_not_verified"
    changed_implementation = source.replace(
        "ensures counter->safe_state == 1;",
        "ensures counter->safe_state == 0;", 1)
    assert polyglot_v2_refinement_gate(
        REVIEWED, EVIDENCE, source, changed_implementation, "c",
        backend_verified=True)["code"] == "trusted_contract_changed"
    assert polyglot_v2_refinement_gate(
        REVIEWED, EVIDENCE.with_name("missing.json"), source, source, "c",
        backend_verified=True)["code"] == "unsupported_refinement_boundary"
    with patch("pipeline.polyglot_refinement_gate.load_bound_reviewed_domain",
               side_effect=KeyError("bad envelope")):
        assert polyglot_v2_refinement_gate(
            REVIEWED, EVIDENCE, source, source, "c",
            backend_verified=True)["code"] == "unsupported_refinement_boundary"


def test_polyglot_implementation_composes_c_proof_and_refinement(tmp_path):
    _, source = render_reviewed_v2_acsl_file(REVIEWED)
    with patch.object(implementation, "lint_acsl", return_value=[]), \
         patch.object(implementation, "verify_c",
                      return_value={"status": "VERIFIED", "exit_code": 0, "vcs": []}):
        result = implementation.synthesize_polyglot_implementation(
            source, "c", candidate=source, out_dir=tmp_path, max_attempts=1,
            v2_reviewed_domain=REVIEWED, v2_validation_evidence=EVIDENCE)
    assert result["final_status"] == "VERIFIED"
    assert result["claim"] == "SOURCE_MODEL_REFINEMENT"
    assert result["claims"] == ["DEDUCTIVE_PROOF", "SOURCE_MODEL_REFINEMENT"]
    assert result["source_refinement_proved"]
    verdict = json.loads((tmp_path / "verdict.json").read_text())
    assert verdict["refinement"]["status"] == "VERIFIED"


def test_polyglot_implementation_requires_complete_refinement_inputs(tmp_path):
    _, source = render_reviewed_v2_prusti_file(REVIEWED)
    with pytest.raises(ValueError, match="requires both"):
        implementation.synthesize_polyglot_implementation(
            source, "rust", candidate=source, out_dir=tmp_path,
            v2_reviewed_domain=REVIEWED)


def test_polyglot_implementation_marks_requested_refinement_failure(tmp_path):
    _, source = render_reviewed_v2_prusti_file(REVIEWED)
    with patch.object(implementation, "lint_rust", return_value=[]), \
         patch.object(implementation, "verify_rust",
                      return_value={"status": "VERIFY_FAILED", "exit_code": 1, "vcs": []}):
        result = implementation.synthesize_polyglot_implementation(
            source, "rust", candidate=source, out_dir=tmp_path, max_attempts=1,
            v2_reviewed_domain=REVIEWED, v2_validation_evidence=EVIDENCE)
    assert result["final_status"] == "REFINEMENT_FAILED"
    assert not result["source_refinement_proved"]
    assert result["refinement"]["code"] == "backend_not_verified"
