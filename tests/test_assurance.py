import pytest

from pipeline.assurance import (
    AssuranceLevel, assurance_verdict, gate_plan, parse_assurance_level,
)


def passing(plan):
    return {gate.name: "PASS" for gate in plan if gate.required}


def test_profiles_have_explicit_required_and_skipped_gates():
    critical = gate_plan("critical")
    assert {gate.name for gate in critical if gate.required} >= {
        "javac", "spec_lint", "openjml_check", "tla", "openjml_esc", "refinement",
        "boundary_fallback"}
    standard = gate_plan(AssuranceLevel.STANDARD)
    assert {gate.name for gate in standard if gate.required} == {
        "javac", "spec_lint", "openjml_check", "rac_junit"}
    lightweight = gate_plan("lightweight")
    assert {gate.name for gate in lightweight if gate.required} == {
        "javac", "spec_lint"}
    assert all(gate.skip_reason for gate in lightweight if not gate.required)


def test_unknown_profile_fails_closed():
    with pytest.raises(ValueError, match="unknown assurance level"):
        parse_assurance_level("fast-and-loose")


@pytest.mark.parametrize(
    ("level", "status", "claim"),
    [
        ("critical", "VERIFIED", "DEDUCTIVE_PROOF"),
        ("standard", "STATIC_CHECKED_RUNTIME_TESTED", "RUNTIME_SAMPLE"),
        ("lightweight", "COMPILED_LINTED", "STATIC_CHECK"),
    ],
)
def test_claim_is_bounded_by_assurance_evidence(level, status, claim):
    result = assurance_verdict(level, passing(gate_plan(level)))
    assert result["final_status"] == status
    assert result["final_claim_type"] == claim
    assert result["deductive_proof_provided"] is (level == "critical")
    if level != "critical":
        assert next(gate for gate in result["gates"] if gate["gate"] == "openjml_esc")["status"] == "SKIPPED"


def test_missing_required_gate_never_produces_assurance_claim():
    statuses = passing(gate_plan("standard"))
    statuses["rac_junit"] = "NOT_RUN"
    result = assurance_verdict("standard", statuses)
    assert result["final_status"] == "ASSURANCE_INCOMPLETE"
    assert result["final_claim_type"] == "NO_PROOF"
    assert result["failed_required_gates"] == ["rac_junit"]
    assert not result["source_refinement_proved"]


def test_critical_boundary_fallback_may_be_explicitly_not_applicable():
    statuses = passing(gate_plan("critical"))
    statuses["boundary_fallback"] = "NOT_APPLICABLE"
    statuses["refinement"] = "VERIFIED"
    result = assurance_verdict("critical", statuses)
    assert result["final_status"] == "VERIFIED"
    assert result["source_refinement_proved"] is True
    assert result["warnings"] == []


def test_critical_without_refinement_is_incomplete_and_never_overclaims():
    statuses = passing(gate_plan("critical"))
    statuses["refinement"] = "FAIL"
    result = assurance_verdict("critical", statuses)
    assert result["final_status"] == "ASSURANCE_INCOMPLETE"
    assert result["source_refinement_proved"] is False
    assert result["failed_required_gates"] == ["refinement"]
    assert result["warnings"]


def test_failed_required_gate_carries_failure_reason():
    statuses = {"javac": "PASS", "spec_lint": "PASS", "openjml_check": "PASS",
                "rac_junit": "FAIL"}
    result = assurance_verdict("standard", statuses,
                               fail_reasons={"rac_junit":
                                             "RAC runtime gate: RUNTIME_FAILURES_FOUND "
                                             "(0/3 tests passed)"})
    gate = next(g for g in result["gates"] if g["gate"] == "rac_junit")
    assert "RUNTIME_FAILURES_FOUND" in gate["reason"] and "0/3" in gate["reason"]
    assert result["final_status"] == "ASSURANCE_INCOMPLETE"


def test_failed_gate_without_reason_stays_empty():
    statuses = {"javac": "PASS", "spec_lint": "PASS", "openjml_check": "FAIL"}
    result = assurance_verdict("standard", statuses)
    gate = next(g for g in result["gates"] if g["gate"] == "openjml_check")
    assert gate["reason"] == ""


def test_profile_gate_fail_reasons_summarize_evidence():
    from pipeline.profile import _gate_fail_reasons
    statuses = {"rac_junit": "FAIL", "openjml_check": "FAIL"}
    evidence = {
        "rac_junit": {"status": "RUNTIME_FAILURES_FOUND", "passed": 1, "failed": 2,
                      "log": "x" * 300},
        "openjml_check": {"errors": ["line 3: bogus clause"]},
    }
    reasons = _gate_fail_reasons(statuses, evidence)
    assert "RUNTIME_FAILURES_FOUND" in reasons["rac_junit"]
    assert "1 passed / 2 failed" in reasons["rac_junit"]
    assert "bogus clause" in reasons["openjml_check"]
    # passing gates and absent evidence produce nothing
    assert _gate_fail_reasons({"javac": "PASS"}, {}) == {}
    assert _gate_fail_reasons({"tla": "FAIL"}, {})["tla"]
