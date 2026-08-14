# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
from unittest.mock import patch

import pytest

from pipeline import polyglot_implementation as implementation
from pipeline.llm import LLMError

RUST = """use prusti_contracts::*;
pub trait Counter {
    #[requires(amount > 0)]
    #[ensures(result > 0)]
    fn add(&mut self, amount: i32) -> i32;
}
pub struct ValueCounter { value: i32 }
impl Counter for ValueCounter {
    #[requires(amount > 0)]
    #[ensures(result > 0)]
    fn add(&mut self, amount: i32) -> i32 { 1 }
}
"""

C = r"""/*@ requires x < 2147483647;
assigns \nothing;
ensures \result == x + 1;
*/
int increment(int x) { return x + 1; }
"""


def test_surfaces_detect_contract_and_signature_changes():
    assert implementation.trusted_surface_matches(RUST, RUST, "rust") == (True, {})
    ok, diff = implementation.trusted_surface_matches(
        RUST, RUST.replace("amount > 0", "amount >= 0", 1), "rust")
    assert not ok and "contracts" in diff
    assert implementation.trusted_surface_matches(C, C, "c") == (True, {})
    ok, diff = implementation.trusted_surface_matches(C, C.replace("int x", "long x"), "c")
    assert not ok and "signatures" in diff
    loop_annotated = C.replace("return x + 1;", "/*@ loop invariant x > 0; */\nreturn x + 1;")
    assert implementation.trusted_surface_matches(C, loop_annotated, "c") == (True, {})
    assert implementation._c_function_contracts("int plain(void) { return 0; }") == []
    detached = "/*@ assigns \\nothing; */\nint global;\nint plain(void) { return 0; }"
    assert implementation._c_function_contracts(detached) == []


def test_source_fence_extraction_is_language_specific():
    assert implementation._source_from_response("```rust\nfn f() {}\n```", "rust") == "fn f() {}\n"
    assert implementation._source_from_response("```c\nint f(void){}\n```", "c") == "int f(void){}\n"


def test_rust_verified_candidate_and_trust_violation(tmp_path):
    with patch.object(implementation, "lint_rust", return_value=[]), \
         patch.object(implementation, "verify_rust",
                      return_value={"status": "VERIFIED", "exit_code": 0, "vcs": []}):
        result = implementation.synthesize_polyglot_implementation(
            RUST, "rust", out_dir=tmp_path / "ok", candidate=RUST, max_attempts=1)
    assert result["final_status"] == "VERIFIED"
    assert result["claim"] == "DEDUCTIVE_PROOF"
    assert (tmp_path / "ok" / "verdict.json").exists()

    changed = RUST.replace("amount > 0", "amount >= 0", 1)
    result = implementation.synthesize_polyglot_implementation(
        RUST, "rust", out_dir=tmp_path / "bad", candidate=changed, max_attempts=1)
    assert result["final_status"] == "TRUST_BOUNDARY_VIOLATION"


def test_c_verified_and_check_only_candidates(tmp_path):
    with patch.object(implementation, "lint_acsl", return_value=[]), \
         patch.object(implementation, "verify_c",
                      return_value={"status": "VERIFIED", "exit_code": 0, "vcs": []}):
        result = implementation.synthesize_polyglot_implementation(
            C, "c", out_dir=tmp_path / "proof", candidate=C, max_attempts=1)
    assert result["claim"] == "DEDUCTIVE_PROOF"

    with patch.object(implementation, "lint_acsl", return_value=[]), \
         patch.object(implementation, "verify_c",
                      return_value={"status": "C_CHECKED", "exit_code": 0}):
        result = implementation.synthesize_polyglot_implementation(
            C, "c", out_dir=tmp_path / "check", candidate=C, max_attempts=1,
            verification_mode="check")
    assert result["final_status"] == "STATIC_CHECKED"
    assert result["claim"] == "STATIC_CHECK"

    with patch.object(implementation, "lint_acsl", return_value=[]), \
         patch.object(implementation, "collect_polyglot_runtime_evidence",
                      return_value={"status": "NO_RUNTIME_FAILURE_FOUND", "exit_code": 0}), \
         patch.object(implementation, "verify_c",
                      return_value={"status": "C_CHECKED", "exit_code": 0}):
        result = implementation.synthesize_polyglot_implementation(
            C, "c", out_dir=tmp_path / "runtime", candidate=C, max_attempts=1,
            verification_mode="check", runtime_gate=True)
    assert result["claim"] == "STATIC_CHECKED_RUNTIME_TESTED"

    pointer = r"""/*@ assigns \nothing; ensures \result == *p; */
int read(const int *p) { return *p; }
"""
    with patch.object(implementation, "lint_acsl", return_value=[]), \
         patch.object(implementation, "verify_c",
                      return_value={"status": "VERIFIED", "exit_code": 0, "vcs": []}):
        accepted = implementation.synthesize_polyglot_implementation(
            pointer, "c", out_dir=tmp_path / "c-pass", candidate=pointer, max_attempts=1,
            accepted_passes=["inject_null_checks"])
    assert accepted["attempts"][0]["postprocess"]["accepted"] is True
    assert r"\valid_read(p)" in accepted["implementation_code"]


def test_invalid_stub_and_lint_failure_fail_closed(tmp_path):
    result = implementation.synthesize_polyglot_implementation(
        "fn f() {}", "rust", out_dir=tmp_path / "invalid")
    assert result["final_status"] == "INVALID_STUB"
    with patch.object(implementation, "lint_acsl",
                      return_value=[{"severity": "error", "message": "bad"}]):
        result = implementation.synthesize_polyglot_implementation(
            C, "c", out_dir=tmp_path / "lint", candidate=C, max_attempts=1)
    assert result["final_status"] == "ACSL_LINT_FAILED"


def test_runtime_counterexample_gate_precedes_formal_verifier(tmp_path):
    counterexample = {"status": "RUNTIME_FAILURES_FOUND", "exit_code": 1,
                      "claim": "COUNTEREXAMPLE_EVIDENCE", "log": "input 4 overflow"}
    with patch.object(implementation, "lint_rust", return_value=[]), \
         patch.object(implementation, "collect_polyglot_runtime_evidence",
                      return_value=counterexample), \
         patch.object(implementation, "verify_rust") as verifier:
        result = implementation.synthesize_polyglot_implementation(
            RUST, "rust", out_dir=tmp_path / "cex", candidate=RUST, max_attempts=1,
            runtime_gate=True)
    verifier.assert_not_called()
    assert result["final_status"] == "RUNTIME_FAILURES_FOUND"
    assert result["runtime_evidence"]["claim"] == "COUNTEREXAMPLE_EVIDENCE"


def test_argument_validation_helpers_and_rust_check(tmp_path):
    with pytest.raises(ValueError, match="language"):
        implementation.synthesize_polyglot_implementation(RUST, "java")
    with pytest.raises(ValueError, match="verification_mode"):
        implementation.synthesize_polyglot_implementation(RUST, "rust", verification_mode="parse")
    rows = [{"file": "x.rs", "line": 3, "category": "Postcondition", "extra": "ignored"}]
    assert implementation._shared_vcs(rows)[0].line == 3
    assert implementation._shared_vcs(None) == []
    with patch.object(implementation, "lint_rust", return_value=[]), \
         patch.object(implementation, "verify_rust",
                      return_value={"status": "RUST_CHECKED", "exit_code": 0}), \
         patch.object(implementation, "apply_rust_passes",
                      return_value={"code": RUST, "changed": False}):
        result = implementation.synthesize_polyglot_implementation(
            RUST, "rust", out_dir=tmp_path / "rust-check", candidate=RUST,
            accepted_passes=["inject_pure"], verification_mode="check", max_attempts=1)
    assert result["final_status"] == "STATIC_CHECKED"
    assert result["attempts"][0]["postprocess"]["accepted"] is True


def test_llm_sample_feedback_and_api_error_paths(tmp_path):
    responses = [
        (f"```c\n{C.replace('return x + 1', 'return x')}\n```", "m1", {}),
        (f"```c\n{C}\n```", "m2", {}),
    ]
    with patch.object(implementation, "_chat_fn", return_value=lambda *_: responses.pop(0)), \
         patch.object(implementation, "lint_acsl", return_value=[]), \
         patch.object(implementation, "verify_c", side_effect=[
             {"status": "VERIFY_FAILED", "exit_code": 1, "output": "postcondition",
              "vcs": [{"file": "candidate.c", "line": 4, "category": "Postcondition"}]},
             {"status": "VERIFIED", "exit_code": 0, "output": "proved", "vcs": []},
         ]):
        result = implementation.synthesize_polyglot_implementation(
            C, "c", out_dir=tmp_path / "repair", max_attempts=2,
            resample_budget=1, feedback_budget=1)
    assert result["final_status"] == "VERIFIED"
    assert len(result["attempts"]) == 2

    error = LLMError("NETWORK", "offline")
    with patch.object(implementation, "_chat_fn",
                      return_value=lambda *_: (_ for _ in ()).throw(error)):
        result = implementation.synthesize_polyglot_implementation(
            C, "c", out_dir=tmp_path / "api", max_attempts=1)
    assert result["final_status"] == "API_ERROR"


def test_empty_generation_is_bounded(tmp_path):
    with patch.object(implementation, "_chat_fn", return_value=lambda *_: ("", "m", {})):
        result = implementation.synthesize_polyglot_implementation(
            C, "c", out_dir=tmp_path / "empty", max_attempts=1)
    assert result["final_status"] == "GEN_EMPTY"
