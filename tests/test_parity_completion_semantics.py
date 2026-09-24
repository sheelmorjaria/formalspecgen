# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Admission coverage must never be reported as complete workflow parity."""

from __future__ import annotations

from copy import deepcopy

from pipeline.parity_inventory import (
    ACCEPTANCE_EVIDENCE_SCHEMA,
    _workflow_completion,
)


ADMITTED = {"status": "admitted", "profiles": [{"name": "partial"}]}
SCHEMA = {"field_names": ["source", "mode"], "fields": []}


def _plan() -> dict:
    return {
        "cli_command": "fixture",
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
         "variants": ["java"]}
        for kind in (
            "request_equivalence", "argument_delivery", "effect_enforcement",
            "result_equivalence", "mcp_transport")
    ]


def _evidence(plan: dict, revision: str = "a" * 40) -> dict:
    cases = [{
        **case, "result": "passed", "revision": revision,
        "output_sha256": "0" * 64,
        "junit_sha256": "3" * 64,
        "junit": {"tests": 1, "failures": 0, "errors": 0, "skipped": 0},
    } for case in plan["completion_contract"]["acceptance_cases"]]
    return {
        "schema": ACCEPTANCE_EVIDENCE_SCHEMA,
        "revision": revision,
        "tree": "b" * 40,
        "workspace_dirty": False,
        "run": {"provider": "github-actions", "id": "1", "attempt": "1"},
        "commands": [{
            "cli_command": plan["cli_command"],
            "cases": cases,
            "transport_observation": {
                "schema_sha256": "1" * 64, "result_sha256": "2" * 64},
        }],
    }


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
        "acceptance_cases": _acceptance(),
    }
    result = _workflow_completion(plan, ADMITTED, SCHEMA)
    assert result["complete"] is False
    assert result["missing_mcp_fields"] == ["backend"]


def test_partial_variant_coverage_remains_incomplete_with_passing_tests():
    plan = _plan()
    plan["completion_contract"] = {
        "required_variants": ["deterministic", "provider-assisted"],
        "acceptance_cases": [
            {**case, "variants": ["deterministic"]}
            for case in _acceptance()],
    }
    result = _workflow_completion(
        plan, ADMITTED, SCHEMA, acceptance_evidence=_evidence(plan))
    assert result["complete"] is False
    assert "workflow_variants_incomplete" in result["blockers"]


def test_acceptance_results_are_bound_to_one_revision():
    plan = _plan()
    plan["completion_contract"] = {
        "required_variants": ["java"], "acceptance_cases": _acceptance(),
    }
    evidence = _evidence(plan)
    evidence["commands"][0]["cases"][0]["revision"] = "b" * 40
    result = _workflow_completion(
        plan, ADMITTED, SCHEMA, acceptance_evidence=evidence)
    assert result["complete"] is False
    assert "required_acceptance_cases_missing_or_unpassed" in result["blockers"]


def test_complete_is_derived_from_schema_variants_and_acceptance_results():
    plan = _plan()
    plan["completion_contract"] = {
        "required_variants": ["java"], "acceptance_cases": _acceptance(),
    }
    result = _workflow_completion(
        plan, ADMITTED, SCHEMA, acceptance_evidence=_evidence(plan))
    assert result["complete"] is True
    assert result["blockers"] == []


def test_resumable_and_approval_workflows_require_specialized_cases():
    plan = _plan()
    plan["workflow_kind"] = "resumable_with_approval"
    plan["completion_contract"] = {
        "required_variants": ["java"], "acceptance_cases": _acceptance(),
    }
    missing = _workflow_completion(
        plan, ADMITTED, SCHEMA, acceptance_evidence=_evidence(plan))
    assert missing["complete"] is False
    cases = deepcopy(plan["completion_contract"]["acceptance_cases"])
    cases.extend([
        {"kind": "session_replay",
         "test": "tests/test_parity_completion_semantics.py::test_session_replay",
         "variants": ["java"]},
        {"kind": "approval_security",
         "test": "tests/test_parity_completion_semantics.py::test_approval_replay",
         "variants": ["java"]},
    ])
    plan["completion_contract"]["acceptance_cases"] = cases
    assert _workflow_completion(
        plan, ADMITTED, SCHEMA,
        acceptance_evidence=_evidence(plan))["complete"] is True
