# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import json
from unittest.mock import patch

from pipeline import profile


STUB = r"""public class Counter {
  private /*@ spec_public @*/ int value;
  //@ requires amount > 0;
  //@ assignable value;
  //@ ensures value == \old(value) + amount;
  public void add(int amount) { }
}
"""


def implementation(status, code="public class Counter {}"):
    return {"final_status": status, "implementation_code": code, "attempts": []}


def test_critical_requires_tlc_and_esc(tmp_path):
    with patch.object(profile, "check_stub", return_value=(True, [])), \
         patch.object(profile, "generate_and_check", return_value={"status": "VERIFIED"}), \
         patch.object(profile, "refinement_gate", return_value={"status": "VERIFIED"}), \
         patch.object(profile, "synthesize_implementation",
                      return_value=implementation("VERIFIED")) as synth:
        result = profile.run_assured_implementation(STUB, "critical", out_dir=tmp_path)
    assert result["final_status"] == "VERIFIED"
    assert result["final_claim_type"] == "DEDUCTIVE_PROOF"
    assert synth.call_args.kwargs["verification_mode"] == "esc"
    assert json.loads((tmp_path / "assurance-verdict.json").read_text())["assurance_level"] == "critical"


def test_critical_stops_when_architecture_is_unsupported():
    with patch.object(profile, "check_stub", return_value=(True, [])), \
         patch.object(profile, "generate_and_check", return_value={"status": "UNSUPPORTED_BOUNDARY"}), \
         patch.object(profile, "synthesize_implementation") as synth:
        result = profile.run_assured_implementation(STUB, "critical")
    assert result["final_status"] == "ASSURANCE_INCOMPLETE"
    assert "tla" in result["failed_required_gates"]
    synth.assert_not_called()


def test_standard_requires_checked_candidate_and_nonempty_rac_sample():
    runtime = {"status": "NO_RUNTIME_FAILURE_FOUND", "passed": 3, "failed": 0}
    with patch.object(profile, "check_stub", return_value=(True, [])), \
         patch.object(profile, "synthesize_implementation",
                      return_value=implementation("STATIC_CHECKED")) as synth, \
         patch.object(profile, "collect_rac_evidence", return_value=runtime):
        result = profile.run_assured_implementation(STUB, "standard")
    assert result["final_status"] == "STATIC_CHECKED_RUNTIME_TESTED"
    assert result["final_claim_type"] == "RUNTIME_SAMPLE"
    assert synth.call_args.kwargs["verification_mode"] == "check"

    with patch.object(profile, "check_stub", return_value=(True, [])), \
         patch.object(profile, "synthesize_implementation",
                      return_value=implementation("STATIC_CHECKED")), \
         patch.object(profile, "collect_rac_evidence",
                      return_value={"status": "NO_RUNTIME_FAILURE_FOUND", "passed": 0}):
        empty = profile.run_assured_implementation(STUB, "standard")
    assert empty["final_status"] == "ASSURANCE_INCOMPLETE"
    assert empty["failed_required_gates"] == ["rac_junit"]


def test_lightweight_compiles_and_lints_without_claiming_runtime_evidence():
    with patch.object(profile, "check_stub") as checked, \
         patch.object(profile, "synthesize_implementation",
                      return_value=implementation("COMPILED")) as synth:
        result = profile.run_assured_implementation(STUB, "lightweight")
    checked.assert_not_called()
    assert synth.call_args.kwargs["verification_mode"] == "compile"
    assert result["final_status"] == "COMPILED_LINTED"
    assert result["final_claim_type"] == "STATIC_CHECK"
    assert result["deductive_proof_provided"] is False


def test_lint_and_static_check_fail_closed_before_generation():
    finding = {"line": 1, "code": "missing-postcondition", "message": "missing", "advice": "add"}
    with patch.object(profile, "lint_spec", return_value=[finding]), \
         patch.object(profile, "synthesize_implementation") as synth:
        lint_failed = profile.run_assured_implementation(STUB, "lightweight")
    assert lint_failed["final_status"] == "ASSURANCE_INCOMPLETE"
    synth.assert_not_called()

    with patch.object(profile, "check_stub", return_value=(False, ["bad JML"])), \
         patch.object(profile, "synthesize_implementation") as synth:
        check_failed = profile.run_assured_implementation(STUB, "standard")
    assert check_failed["final_status"] == "ASSURANCE_INCOMPLETE"
    synth.assert_not_called()


def test_failed_generation_marks_javac_gate_failed():
    with patch.object(profile, "synthesize_implementation",
                      return_value=implementation("COMPILE_FAILED", "")):
        result = profile.run_assured_implementation(STUB, "lightweight")
    assert result["final_status"] == "ASSURANCE_INCOMPLETE"
    assert result["failed_required_gates"] == ["javac"]
