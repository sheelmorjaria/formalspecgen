# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Admission coverage must never be reported as complete workflow parity."""

from __future__ import annotations

from copy import deepcopy

from pipeline.parity_inventory import _workflow_completion


ADMITTED = {"status": "admitted", "profiles": [{"name": "partial"}]}
SCHEMA = {"field_names": ["source", "mode"], "fields": []}


def _plan() -> dict:
    return {
        "workflow_kind": "direct",
        "argument_mappings": [
            {"proposed_mcp_field": "source", "implementation_status": "verified"},
            {"proposed_mcp_field": "mode", "implementation_status": "verified"},
        ],
    }


def _acceptance(revision: str = "abc1234") -> list[dict]:
    return [
        {"kind": kind,
         "test": f"tests/test_parity_completion_semantics.py::test_{kind}",
         "result": "passed", "revision": revision}
        for kind in (
            "request_equivalence", "argument_delivery", "effect_enforcement",
            "result_equivalence", "mcp_transport")
    ]


def test_admitted_profile_without_completion_contract_is_incomplete():
    result = _workflow_completion(_plan(), ADMITTED, SCHEMA)
    assert result["complete"] is False
    assert "completion_contract_missing" in result["blockers"]


def test_restricted_handler_schema_cannot_complete_broader_command():
    plan = _plan()
    plan["argument_mappings"].append({
        "proposed_mcp_field": "backend", "implementation_status": "verified"})
    plan["completion_contract"] = {
        "required_variants": ["java", "rust"],
        "covered_variants": ["java", "rust"],
        "evidence_revision": "abc1234",
        "acceptance_cases": _acceptance(),
    }
    result = _workflow_completion(plan, ADMITTED, SCHEMA)
    assert result["complete"] is False
    assert result["missing_mcp_fields"] == ["backend"]


def test_partial_variant_coverage_remains_incomplete_with_passing_tests():
    plan = _plan()
    plan["completion_contract"] = {
        "required_variants": ["deterministic", "provider-assisted"],
        "covered_variants": ["deterministic"],
        "evidence_revision": "abc1234",
        "acceptance_cases": _acceptance(),
    }
    result = _workflow_completion(plan, ADMITTED, SCHEMA)
    assert result["complete"] is False
    assert "workflow_variants_incomplete" in result["blockers"]


def test_acceptance_results_are_bound_to_one_revision():
    plan = _plan()
    plan["completion_contract"] = {
        "required_variants": ["java"], "covered_variants": ["java"],
        "evidence_revision": "abcdef0", "acceptance_cases": _acceptance("1234567"),
    }
    result = _workflow_completion(plan, ADMITTED, SCHEMA)
    assert result["complete"] is False
    assert "required_acceptance_cases_missing_or_unpassed" in result["blockers"]


def test_complete_is_derived_from_schema_variants_and_acceptance_results():
    plan = _plan()
    plan["completion_contract"] = {
        "required_variants": ["java"], "covered_variants": ["java"],
        "evidence_revision": "abc1234", "acceptance_cases": _acceptance(),
    }
    result = _workflow_completion(plan, ADMITTED, SCHEMA)
    assert result["complete"] is True
    assert result["blockers"] == []


def test_resumable_and_approval_workflows_require_specialized_cases():
    plan = _plan()
    plan["workflow_kind"] = "resumable_with_approval"
    plan["completion_contract"] = {
        "required_variants": ["default"], "covered_variants": ["default"],
        "evidence_revision": "abc1234", "acceptance_cases": _acceptance(),
    }
    missing = _workflow_completion(plan, ADMITTED, SCHEMA)
    assert missing["complete"] is False
    cases = deepcopy(plan["completion_contract"]["acceptance_cases"])
    cases.extend([
        {"kind": "session_replay",
         "test": "tests/test_parity_completion_semantics.py::test_session_replay",
         "result": "passed", "revision": "abc1234"},
        {"kind": "approval_security",
         "test": "tests/test_parity_completion_semantics.py::test_approval_replay",
         "result": "passed", "revision": "abc1234"},
    ])
    plan["completion_contract"]["acceptance_cases"] = cases
    assert _workflow_completion(plan, ADMITTED, SCHEMA)["complete"] is True
