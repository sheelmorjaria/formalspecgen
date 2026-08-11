import pytest

from pipeline.assurance import (
    AssuranceLevel, assurance_verdict, gate_plan, parse_assurance_level,
)


def passing(plan):
    return {gate.name: "PASS" for gate in plan if gate.required}


def test_profiles_have_explicit_required_and_skipped_gates():
    critical = gate_plan("critical")
    assert {gate.name for gate in critical if gate.required} >= {
        "javac", "spec_lint", "openjml_check", "tla", "openjml_esc", "boundary_fallback"}
    standard = gate_plan(AssuranceLevel.STANDARD)
    assert {gate.name for gate in standard if gate.required} == {
        "javac", "spec_lint", "openjml_check", "rac_junit"}
    lightweight = gate_plan("lightweight")
    assert {gate.name for gate in lightweight if gate.required} == {
        "javac", "spec_lint", "rac_junit"}
    assert all(gate.skip_reason for gate in lightweight if not gate.required)


def test_unknown_profile_fails_closed():
    with pytest.raises(ValueError, match="unknown assurance level"):
        parse_assurance_level("fast-and-loose")


@pytest.mark.parametrize(
    ("level", "status", "claim"),
    [
        ("critical", "VERIFIED", "DEDUCTIVE_PROOF"),
        ("standard", "STATIC_CHECKED_RUNTIME_TESTED", "RUNTIME_SAMPLE"),
        ("lightweight", "COMPILED_LINTED", "RUNTIME_SAMPLE"),
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
    assert assurance_verdict("critical", statuses)["final_status"] == "VERIFIED"
