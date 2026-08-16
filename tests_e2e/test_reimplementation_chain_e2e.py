"""E2E: the Rosetta-Stone lane — legacy C -> reviewed math -> proven Rust.

Chains the full bidirectional loop against the REAL TLC and REAL Prusti:

1. ``analyze-codebase`` extracts the bounded connection state machine from
   legacy C and registers an unreviewed V2 candidate.
2. ``validate-domain`` proves the extracted state machine with real TLC.
3. ``promote-domain`` binds the human review to the candidate hash.
4. ``draft --canonical-domain --lang rust`` lowers the reviewed math into a
   deterministic Prusti contract whose bodies transcribe the effects.
5. The implementation loop verifies it with real Prusti ESC and the V2
   refinement gate mints SOURCE_MODEL_REFINEMENT against the SAME hash.

The only non-live step is the LLM seam: the deterministic candidate (the
canonical rendering itself, whose bodies the reviewed effects fully
determine) is injected through the loop's ``candidate`` parameter. Every
formal gate — TLC, Prusti, hash-bound refinement — runs for real.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import cli

pytestmark = pytest.mark.toolchain

REPO_ROOT = Path(__file__).resolve().parents[1]


def _prusti_available() -> bool:
    from pipeline import config
    return bool(config.PRUSTI_BIN) and Path(config.PRUSTI_BIN).exists()


def test_c_to_rust_reimplementation_chain(tmp_path, monkeypatch, tlc_tool):
    if not _prusti_available():
        pytest.skip("Prusti unavailable")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "legacy_c").mkdir()
    (tmp_path / "legacy_c" / "connection.c").write_text(
        (REPO_ROOT / "legacy_c" / "connection.c").read_text(encoding="utf-8"),
        encoding="utf-8")

    # 1. Extract: C AST -> bounded V2 candidate with compiled transitions.
    assert cli.main(["analyze-codebase", "legacy_c", "--out-dir", "extracted",
                     "--project-root", "."]) == 0
    candidate = tmp_path / "domains" / "candidates" / "connection.v2.yaml"
    assert candidate.exists(), "C extraction must register a V2 candidate"

    # 2. Validate: real TLC proves the extracted machine is bounded and safe.
    from pipeline.domain_v2_validation import validate_domain
    evidence = validate_domain("connection", project_root=tmp_path,
                               tlc_jar=tlc_tool)
    assert evidence.validation_status == "VALIDATED", str(evidence)
    envelope = json.loads(
        (tmp_path / "domains" / "candidates" / "connection.v2.validation.json")
        .read_text(encoding="utf-8"))
    assert envelope["evidence"]["reachable_state_count"] == 3  # 0,1,2
    assert envelope["evidence"]["reachable_transition_count"] >= 3

    # 3. Promote: the human gate binds review to the extraction hash.
    candidate_hash = envelope["evidence"]["candidate_sha256"]
    from pipeline.domain_v2_promotion import promote_domain
    promote_domain("connection", accept_candidate_sha256=candidate_hash,
                   project_root=tmp_path)
    reviewed = tmp_path / "domains" / "v2" / "connection.json"
    assert json.loads(reviewed.read_text(encoding="utf-8"))[
        "accepted_candidate_sha256"] == candidate_hash

    # 4. Lower: reviewed math -> deterministic Prusti contract (bodies
    #    transcribed from the reviewed effects, no LLM involved).
    assert cli.main(["draft", "connection port", "--canonical-domain",
                     "connection", "--lang", "rust", "--no-clarify",
                     "--out-file", "Connection.rs"]) == 0
    stub = (tmp_path / "Connection.rs").read_text(encoding="utf-8")
    assert "pub struct Connection" in stub
    assert "pub fn connection_open" in stub and "self.conn_state = 1;" in stub

    # 5. Prove: real Prusti ESC + the V2 refinement gate against the SAME hash.
    from pipeline.polyglot_implementation import synthesize_polyglot_implementation
    result = synthesize_polyglot_implementation(
        stub, "rust", provider="ollama", candidate=stub,
        v2_reviewed_domain=str(reviewed),
        v2_validation_evidence=str(
            tmp_path / "domains" / "candidates" / "connection.v2.validation.json"))
    assert result["final_status"] == "VERIFIED", json.dumps(result, default=str)[:1200]
    assert result["refinement"]["status"] == "VERIFIED"
    assert result["claim"] == "SOURCE_MODEL_REFINEMENT"
    assert result["claims"] == ["DEDUCTIVE_PROOF", "SOURCE_MODEL_REFINEMENT"]
    assert result["verification_backend"] == "prusti"


def test_unbounded_c_state_fails_closed_without_a_candidate(tmp_path):
    """Dynamic-structure C code cannot mint a reimplementation candidate."""
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.chdir(tmp_path)
    (tmp_path / "legacy_c").mkdir()
    (tmp_path / "legacy_c" / "linked.c").write_text(
        "struct Node { int value; };\n"
        "void node_push(struct Node *n) { n->value = n->value + 1; }\n",
        encoding="utf-8")
    assert cli.main(["analyze-codebase", "legacy_c", "--out-dir", "extracted",
                     "--project-root", "."]) == 0
    result = json.loads((tmp_path / "extracted" / "extracted_architecture.json")
                        .read_text(encoding="utf-8"))
    assert any(warning["code"] == "UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW"
               for warning in result["warnings"])
    monkeypatch.undo()
