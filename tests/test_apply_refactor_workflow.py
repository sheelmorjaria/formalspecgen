# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Shared deterministic refactor workflow and strict MCP publication tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import mcp_server
import pytest
from pipeline import cli
from pipeline.execution import ExecutionObservation
from pipeline.isolated_verification import IsolatedVerificationResult
from pipeline.mcp_policy import authorize_mcp_invocation
from pipeline.parity_inventory import handler_input_schema
from pipeline.workflow_contracts import (
    ApplyRefactorWorkflowRequest,
    WorkflowContext,
    WorkflowContractError,
    WorkflowInterface,
)
from pipeline.workflow_services import run_apply_refactor


C_SOURCE = """/*@ requires \\valid(count); requires value >= 0; */
void add(int* count, int value) {
    *count += value;
}
"""
RUST_SOURCE = """use prusti_contracts::*;
#[ensures(result == 1)]
pub fn value() -> i32 { 1 }
"""
CPP_SOURCE = """#include <cassert>
class Counter {
public:
    void add(int value) { assert(value >= 0); count += value; }
private:
    int count = 0;
};
"""


def _observation(stage: str) -> ExecutionObservation:
    return ExecutionObservation(
        status="COMPLETED", exit_code=0, output=stage,
        requested_policy={"network": "denied"},
        enforced_policy={"network": "denied"},
        policy_compliance="ENFORCED",
        snapshot_manifest_sha256=f"snapshot-{stage}",
        tool="frama-c", command=("frama-c", "-wp"),
    )


def _verified(path: Path, **_options) -> IsolatedVerificationResult:
    stage = path.parent.name
    observation = _observation(stage)
    return IsolatedVerificationResult({
        "status": "VERIFIED", "claim": "DEDUCTIVE_PROOF",
        "exit_code": 0, "output": "proved",
    }, (observation,))


def _request(source: Path, **overrides) -> ApplyRefactorWorkflowRequest:
    values = {
        "source": str(source), "inspection": None,
        "pattern": "extract-method", "method": "add",
        "out": "candidates/add.c", "result_export": None,
    }
    values.update(overrides)
    return ApplyRefactorWorkflowRequest(**values)


def test_request_schema_effects_and_admission_cover_all_cli_fields(tmp_path):
    source = tmp_path / "add.c"
    source.write_text(C_SOURCE, encoding="utf-8")
    request = _request(source, result_export="results/add.json")
    effects = request.required_effects(WorkflowInterface.MCP)
    admission = authorize_mcp_invocation(
        "apply_refactor", mode=request.mode, language=request.language,
        backend=request.effective_backend, effects=effects)
    assert admission.admitted
    assert admission.profile.name == "c-framac-deterministic-refactor"
    assert set(effects) == {
        "workspace_read", "workspace_write_new", "external_execution",
        "evidence_publication",
    }
    schema = handler_input_schema(mcp_server.apply_refactor)
    assert schema["field_names"] == [
        "source", "method", "out", "pattern", "inspection", "result_export"]
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") == "1":
        from scripts.mcp_acceptance_adapters import collect_tool_schema
        discovered = collect_tool_schema("apply_refactor")["input_schema"]
        assert set(discovered["properties"]) == set(schema["field_names"])
        assert discovered["required"] == ["source", "method", "out"]


def test_cli_and_mcp_requests_normalize_equivalently(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "add.c"
    source.write_text(C_SOURCE, encoding="utf-8")
    parsed = cli.build_parser().parse_args([
        "apply-refactor", "add.c", "--pattern", "extract-method",
        "--method", "add", "--out", "candidates/add.c",
        "--json", "results/add.json",
    ])
    cli_request = ApplyRefactorWorkflowRequest(
        parsed.source, parsed.inspection, parsed.pattern, parsed.method,
        parsed.out, result_export=parsed.json)
    mcp_request = ApplyRefactorWorkflowRequest(
        "add.c", None, "extract-method", "add", "candidates/add.c",
        result_export="results/add.json")
    assert cli_request == mcp_request


def test_request_rejects_unsupported_pattern_and_missing_java_inspection(tmp_path):
    source = tmp_path / "add.c"
    source.write_text(C_SOURCE, encoding="utf-8")
    try:
        _request(source, pattern="strategy")
    except WorkflowContractError as exc:
        assert "unsupported c refactor pattern" in str(exc)
    else:
        raise AssertionError("unsupported C strategy profile was admitted")

    java = tmp_path / "Counter.java"
    java.write_text("public class Counter {}\n", encoding="utf-8")
    try:
        _request(java)
    except WorkflowContractError as exc:
        assert "inspection evidence" in str(exc)
    else:
        raise AssertionError("Java refactor without inspection was admitted")


def test_shared_service_stages_candidate_and_retains_both_observations(tmp_path):
    source = tmp_path / "add.c"
    source.write_text(C_SOURCE, encoding="utf-8")
    request = _request(source)
    context = WorkflowContext.for_cli(
        request.required_effects(WorkflowInterface.CLI), workspace_root=tmp_path,
        resource_budget={"max_input_bytes": 65536, "max_input_files": 8,
                         "max_result_bytes": 65536})
    calls = []

    def execute(path: Path, **options):
        calls.append((path.read_bytes(), options["backend"]))
        return _verified(path, **options)

    result = run_apply_refactor(request, context, execute_native=execute)
    assert result.payload["status"] == "VERIFIED"
    assert result.payload["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert result.payload["candidate_publication"] == "PENDING"
    assert len(result.stages) == 2
    assert all(stage["execution"]["policy_compliance"] == "ENFORCED"
               for stage in result.stages)
    assert [backend for _content, backend in calls] == ["frama-c", "frama-c"]
    candidate = result.artifacts["add.c"].decode("utf-8")
    assert "static void add_helper" in candidate
    assert not (tmp_path / "candidates" / "add.c").exists()


@pytest.mark.parametrize(("name", "source_text", "method", "backend", "claim"), [
    ("value.rs", RUST_SOURCE, "value", "prusti",
     "REFACTOR_CONTRACT_PRESERVED"),
    ("add.c", C_SOURCE, "add", "frama-c",
     "REFACTOR_CONTRACT_PRESERVED"),
    ("Counter.cpp", CPP_SOURCE, "add", "esbmc",
     "BOUNDED_REFACTOR_CONTRACT_PRESERVED"),
])
def test_native_language_results_preserve_backend_claim_ceiling(
        tmp_path, name, source_text, method, backend, claim):
    source = tmp_path / name
    source.write_text(source_text, encoding="utf-8")
    request = _request(source, method=method, out=f"out/{name}")
    context = WorkflowContext.for_cli(
        request.required_effects(WorkflowInterface.CLI), workspace_root=tmp_path,
        resource_budget={"max_input_bytes": 65536, "max_input_files": 8,
                         "max_result_bytes": 65536})
    result = run_apply_refactor(request, context, execute_native=_verified)
    assert result.payload["status"] == "VERIFIED"
    assert result.payload["backend"] == backend
    assert result.payload["claim"] == claim


def test_transform_rejection_stops_before_backend_and_returns_no_artifacts(tmp_path):
    source = tmp_path / "add.c"
    source.write_text(C_SOURCE, encoding="utf-8")
    request = _request(source, method="missing")
    context = WorkflowContext.for_cli(
        request.required_effects(WorkflowInterface.CLI), workspace_root=tmp_path,
        resource_budget={"max_input_bytes": 65536, "max_input_files": 8})
    with patch("pipeline.workflow_services.execute_isolated_verification") as execute:
        result = run_apply_refactor(request, context)
    execute.assert_not_called()
    assert result.payload["status"] == "FAIL"
    assert result.payload["claim"] == "NO_PROOF"
    assert result.artifacts == {}


def test_input_budget_is_enforced_before_transformation_or_execution(tmp_path):
    source = tmp_path / "add.c"
    source.write_text(C_SOURCE, encoding="utf-8")
    request = _request(source)
    context = WorkflowContext.for_cli(
        request.required_effects(WorkflowInterface.CLI), workspace_root=tmp_path,
        resource_budget={"max_input_bytes": 8, "max_input_files": 1})
    with patch("pipeline.workflow_services._apply_deterministic_transform") as transform, \
            patch("pipeline.workflow_services.execute_isolated_verification") as execute:
        with pytest.raises(ValueError, match="configured limit"):
            run_apply_refactor(request, context)
    transform.assert_not_called()
    execute.assert_not_called()


def test_candidate_failure_retains_successful_baseline_stage(tmp_path):
    source = tmp_path / "add.c"
    source.write_text(C_SOURCE, encoding="utf-8")
    request = _request(source)
    context = WorkflowContext.for_cli(
        request.required_effects(WorkflowInterface.CLI), workspace_root=tmp_path,
        resource_budget={"max_input_bytes": 65536, "max_input_files": 8,
                         "max_result_bytes": 65536})
    outcomes = iter((True, False))

    def execute(path: Path, **_options):
        if next(outcomes):
            return _verified(path)
        observation = _observation("candidate-failed")
        return IsolatedVerificationResult({
            "status": "VERIFY_FAILED", "claim": "NO_PROOF",
            "exit_code": 1, "output": "postcondition failed",
        }, (observation,))

    result = run_apply_refactor(request, context, execute_native=execute)
    assert result.payload["status"] == "FAIL"
    assert result.payload["claim"] == "NO_PROOF"
    assert result.stages[0]["status"] == "VERIFIED"
    assert result.stages[1]["status"] == "VERIFY_FAILED"
    assert result.artifacts


def test_mcp_publishes_candidate_evidence_and_negative_export_without_replace(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "add.c"
    source.write_text(C_SOURCE, encoding="utf-8")
    with patch("pipeline.workflow_services.execute_isolated_verification",
               side_effect=_verified):
        result = mcp_server.apply_refactor(
            "add.c", pattern="extract-method", method="add",
            out="candidates/add.c", result_export="results/add.json")
    assert result["status"] == "VERIFIED"
    assert result["candidate_publication"]["status"] == "COMMITTED"
    assert result["evidence"]["publication_status"] == "COMMITTED"
    assert result["result_export"]["status"] == "COMMITTED"
    output = tmp_path / ".formalspecgen" / "mcp-output"
    assert (output / "candidates" / "add.c").is_file()
    exported = json.loads((output / "results" / "add.json").read_text())
    assert exported["workflow_result"]["request"]["method"] == "add"

    with patch("pipeline.workflow_services.execute_isolated_verification",
               side_effect=_verified):
        collision = mcp_server.apply_refactor(
            "add.c", pattern="extract-method", method="add",
            out="candidates/add.c", result_export="results/other.json")
    assert collision["status"] == "CANDIDATE_PUBLICATION_FAILED"
    assert collision["claim"] == "NO_PROOF"
    assert collision["request_satisfied"] is False


def test_mcp_negative_transformation_result_can_be_exported(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "add.c").write_text(C_SOURCE, encoding="utf-8")
    result = mcp_server.apply_refactor(
        "add.c", pattern="extract-method", method="missing",
        out="candidates/missing.c", result_export="results/rejected.json")
    assert result["status"] == "FAIL"
    assert result["claim"] == "NO_PROOF"
    assert result["evidence"]["publication_status"] == "COMMITTED"
    assert result["result_export"]["status"] == "COMMITTED"
    assert not (tmp_path / ".formalspecgen/mcp-output/candidates/missing.c").exists()


def test_evidence_publication_failure_downgrades_verified_candidate(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "add.c").write_text(C_SOURCE, encoding="utf-8")
    with patch("pipeline.workflow_services.execute_isolated_verification",
               side_effect=_verified), \
            patch("mcp_server.publish_multistage_evidence",
                  side_effect=OSError("ledger unavailable")):
        result = mcp_server.apply_refactor(
            "add.c", pattern="extract-method", method="add",
            out="candidates/add.c")
    assert result["status"] == "EVIDENCE_PUBLICATION_FAILED"
    assert result["claim"] == "NO_PROOF"
    assert result["request_satisfied"] is False
    assert result["evidence"]["publication_status"] == "FAILED"


def test_cli_and_mcp_semantic_results_are_equivalent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "add.c"
    source.write_text(C_SOURCE, encoding="utf-8")
    args = cli.build_parser().parse_args([
        "apply-refactor", "add.c", "--pattern", "extract-method",
        "--method", "add", "--out", "cli/add.c", "--json", "cli/result.json",
    ])
    ui = SimpleNamespace(console=SimpleNamespace(print=lambda *_a, **_k: None))
    with patch("pipeline.workflow_services.execute_isolated_verification",
               side_effect=_verified):
        assert cli.command_apply_refactor(args, ui) == 0
        mcp_result = mcp_server.apply_refactor(
            "add.c", pattern="extract-method", method="add",
            out="mcp/add.c", result_export="mcp/result.json")
    cli_result = json.loads((tmp_path / "cli/result.json").read_text())
    keys = ("status", "claim", "request_satisfied", "behavior_equivalence_proved")
    assert {key: cli_result.get(key) for key in keys} == {
        key: mcp_result.get(key) for key in keys}
    assert cli_result["transformation"] == mcp_result["transformation"]


def test_real_mcp_transport_exercises_apply_refactor_languages():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        import pytest
        pytest.skip("real stdio MCP acceptance is required only in provisioned CI")
    from scripts.mcp_acceptance_adapters import collect_transport_observation
    observation = collect_transport_observation("apply-refactor")
    assert "apply_refactor" in observation["discovered_tools"]
    assert set(observation["variants"]) == {
        "java-extract-method", "rust-extract-method", "c-extract-method",
        "cpp-extract-method", "negative-transform-export",
    }
