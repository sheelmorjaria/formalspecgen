# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Shared refactor service, admission, publication, and interface acceptance."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import mcp_server
from pipeline import cli
from pipeline.execution import ExecutionObservation
from pipeline.isolated_verification import IsolatedVerificationResult
from pipeline.lifecycle import RunLedger
from pipeline.mcp_policy import authorize_mcp_invocation
from pipeline.parity_inventory import handler_input_schema
from pipeline.verify import VerificationExecutionResult
from pipeline.workflow_contracts import (
    RefactorWorkflowRequest,
    WorkflowContext,
    WorkflowInterface,
)
from pipeline.workflow_services import run_refactor_verification
from scripts.mcp_acceptance_adapters import (
    collect_tool_schema,
    collect_transport_observation,
)


JAVA_BASE = """public class Account {
    //@ ensures \\result == 1;
    public int value() { return 1; }
}
"""
JAVA_REFACTORED = JAVA_BASE.replace(
    "return 1;", "int result = 1; return result;")
RUST_BASE = """#[ensures(result == 1)]
pub fn value() -> i32 { let result = 1; result }
"""
RUST_REFACTORED = """#[ensures(result == 1)]
pub fn value() -> i32 { 1 }
"""
C_BASE = """/*@ ensures \\result == 1; */
int value(void) { int result = 1; return result; }
"""
C_REFACTORED = """/*@ ensures \\result == 1; */
int value(void) { return 1; }
"""
CPP_BASE = """class Counter {
public:
    Counter() : count_(0) {}
    void increment() {
        if (count_ < 5) { count_ = count_ + 1; }
        assert(count_ >= 0 && count_ <= 5);
    }
private:
    int count_;
};
"""
CPP_REFACTORED = """class Counter {
public:
    Counter() : count_(0) {}
    void increment() {
        count_ = (count_ < 5) ? count_ + 1 : count_;
        assert(count_ >= 0 && count_ <= 5);
    }
private:
    int count_;
};
"""


def _pair(tmp_path: Path, suffix: str, before: str, after: str,
          name: str = "Account") -> tuple[Path, Path]:
    baseline = tmp_path / "baseline" / f"{name}{suffix}"
    candidate = tmp_path / "candidate" / f"{name}{suffix}"
    baseline.parent.mkdir(parents=True)
    candidate.parent.mkdir(parents=True)
    baseline.write_text(before, encoding="utf-8")
    candidate.write_text(after, encoding="utf-8")
    return baseline, candidate


def _observation(stage: str, exit_code: int = 0) -> ExecutionObservation:
    return ExecutionObservation(
        status="COMPLETED" if exit_code == 0 else "TOOL_FAILED",
        exit_code=exit_code, output=stage,
        requested_policy={"network": "denied"},
        enforced_policy={"network": "denied"},
        policy_compliance="ENFORCED",
        snapshot_manifest_sha256=f"snapshot-{stage}",
        snapshot_files=({"path": "Account.java", "size": 1,
                         "sha256": "0" * 64},),
        tool="openjml", command=("openjml", f"-{stage}"),
    )


def _java_success(_files: tuple[Path, ...], mode: str) -> VerificationExecutionResult:
    return VerificationExecutionResult(0, f"{mode} completed", _observation(mode))


def _context(request: RefactorWorkflowRequest, root: Path) -> WorkflowContext:
    return WorkflowContext.for_cli(
        request.required_effects(WorkflowInterface.CLI), workspace_root=root)


def test_refactor_request_resolves_language_effects_and_admission(tmp_path):
    baseline, candidate = _pair(tmp_path, ".java", JAVA_BASE, JAVA_REFACTORED)
    request = RefactorWorkflowRequest(
        str(baseline), str(candidate), result_export="results/refactor.json")
    assert request.language == "java"
    assert request.effective_backend == "openjml"
    assert request.as_dict()["workflow"] == "verify-refactor"
    effects = request.required_effects(WorkflowInterface.MCP)
    admission = authorize_mcp_invocation(
        "verify_refactor", mode=request.mode, language=request.language,
        backend=request.effective_backend, effects=effects)
    assert admission.admitted
    assert admission.profile.name == "java-openjml-refactor-preservation-export"
    assert set(admission.granted_effects) == set(effects)


def test_cli_parser_and_mcp_schema_cover_refactor_inputs():
    parsed = cli.build_parser().parse_args([
        "verify-refactor", "baseline/Account.java", "candidate/Account.java",
        "--json", "results/refactor.json", "--signing-key", "reviewer",
    ])
    assert (parsed.baseline, parsed.refactored, parsed.json, parsed.signing_key) == (
        "baseline/Account.java", "candidate/Account.java",
        "results/refactor.json", "reviewer")
    static = handler_input_schema(mcp_server.verify_refactor)
    assert static["field_names"] == [
        "baseline", "refactored", "result_export", "signing_intent"]
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("real stdio MCP acceptance is required only in provisioned CI")
    schema = collect_tool_schema("verify_refactor")["input_schema"]
    assert schema["required"] == ["baseline", "refactored"]
    assert set(schema["properties"]) == {
        "baseline", "refactored", "result_export", "signing_intent"}


def test_java_service_retains_both_check_and_esc_observations(tmp_path):
    baseline, candidate = _pair(tmp_path, ".java", JAVA_BASE, JAVA_REFACTORED)
    request = RefactorWorkflowRequest(str(baseline), str(candidate))
    result = run_refactor_verification(
        request, _context(request, tmp_path), execute_java=_java_success)
    assert result.payload["status"] == "VERIFIED"
    assert result.payload["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert result.payload["request_satisfied"] is True
    assert [stage["stage"] for stage in result.stages] == ["baseline", "refactored"]
    assert [len(stage["execution_stages"]) for stage in result.stages] == [2, 2]
    assert result.inputs["baseline"][0]["sha256"] != \
        result.inputs["refactored"][0]["sha256"]


def test_contract_change_is_rejected_before_any_execution(tmp_path):
    changed = JAVA_REFACTORED.replace("\\result == 1", "\\result == 2")
    baseline, candidate = _pair(tmp_path, ".java", JAVA_BASE, changed)
    request = RefactorWorkflowRequest(str(baseline), str(candidate))
    calls = []

    def execute(files, mode):
        calls.append((files, mode))
        return _java_success(files, mode)

    result = run_refactor_verification(
        request, _context(request, tmp_path), execute_java=execute)
    assert result.payload["code"] == "contract_surface_changed"
    assert result.payload["claim"] == "NO_PROOF"
    assert result.payload["request_satisfied"] is False
    assert calls == []


def test_candidate_failure_preserves_successful_baseline_stage(tmp_path):
    baseline, candidate = _pair(tmp_path, ".java", JAVA_BASE, JAVA_REFACTORED)
    request = RefactorWorkflowRequest(str(baseline), str(candidate))
    exits = iter((0, 0, 0, 6))

    def execute(_files, mode):
        exit_code = next(exits)
        return VerificationExecutionResult(
            exit_code, "postcondition failed" if exit_code else mode,
            _observation(mode, exit_code))

    result = run_refactor_verification(
        request, _context(request, tmp_path), execute_java=execute)
    assert result.payload["code"] == "refactored_not_verified"
    assert result.payload["claim"] == "NO_PROOF"
    assert result.stages[0]["status"] == "VERIFIED"
    assert result.stages[1]["status"] == "FAIL"
    assert result.stages[0]["execution_stages"]


def test_multifile_java_helper_extraction_uses_joint_candidate_stage(tmp_path):
    baseline, _candidate = _pair(tmp_path, ".java", JAVA_BASE, JAVA_REFACTORED)
    candidate_dir = tmp_path / "candidate-files"
    candidate_dir.mkdir()
    (candidate_dir / "Account.java").write_text(
        JAVA_BASE.replace("return 1;", "return Helper.value();"), encoding="utf-8")
    (candidate_dir / "Helper.java").write_text(
        "public class Helper { public static int value() { return 1; } }\n",
        encoding="utf-8")
    request = RefactorWorkflowRequest(str(baseline), str(candidate_dir))
    seen = []

    def execute(files, mode):
        seen.append((mode, tuple(path.name for path in files)))
        return _java_success(files, mode)

    result = run_refactor_verification(
        request, _context(request, tmp_path), execute_java=execute)
    assert result.payload["claim"] == "MULTIFILE_REFACTOR_CONTRACT_PRESERVED"
    assert seen[-1] == ("esc", ("Account.java", "Helper.java"))
    assert {item["name"] for item in result.inputs["refactored"]} == {
        "Account.java", "Helper.java"}


@pytest.mark.parametrize(
    ("suffix", "before", "after", "backend", "claim"),
    [
        (".rs", RUST_BASE, RUST_REFACTORED, "prusti",
         "REFACTOR_CONTRACT_PRESERVED"),
        (".c", C_BASE, C_REFACTORED, "frama-c",
         "REFACTOR_CONTRACT_PRESERVED"),
        (".cpp", CPP_BASE, CPP_REFACTORED, "esbmc",
         "BOUNDED_REFACTOR_CONTRACT_PRESERVED"),
    ],
)
def test_native_services_preserve_claim_ceiling(
        tmp_path, suffix, before, after, backend, claim):
    baseline, candidate = _pair(tmp_path, suffix, before, after, name="module")
    request = RefactorWorkflowRequest(str(baseline), str(candidate))
    calls = []

    def execute(path, **options):
        calls.append((path.name, options["backend"]))
        return IsolatedVerificationResult({
            "status": "VERIFIED", "exit_code": 0,
            "claim": "BOUNDED_CPP_PROOF" if suffix == ".cpp" else "DEDUCTIVE_PROOF",
            "output": "proved",
        })

    result = run_refactor_verification(
        request, _context(request, tmp_path), execute_native=execute)
    assert result.payload["status"] == "VERIFIED"
    assert result.payload["claim"] == claim
    assert [item[1] for item in calls] == [backend, backend]


def test_mcp_negative_export_and_receipt_bind_both_inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    baseline, candidate = _pair(tmp_path, ".java", JAVA_BASE, JAVA_REFACTORED)
    exits = iter((0, 0, 0, 6))

    def execute(_files, mode):
        exit_code = next(exits)
        return VerificationExecutionResult(
            exit_code, "candidate failed" if exit_code else mode,
            _observation(mode, exit_code))

    with patch("pipeline.workflow_services.verify_files_detailed", side_effect=execute):
        result = mcp_server.verify_refactor(
            str(baseline.relative_to(tmp_path)), str(candidate.relative_to(tmp_path)),
            result_export="refactor/failed.json")
    assert result["status"] == "FAIL"
    assert result["claim"] == "NO_PROOF"
    assert result["request_satisfied"] is False
    assert result["evidence"]["publication_status"] == "COMMITTED"
    assert result["result_export"]["status"] == "COMMITTED"
    exported = json.loads((
        tmp_path / ".formalspecgen/mcp-output/refactor/failed.json"
    ).read_text(encoding="utf-8"))
    assert exported["claim"] == "NO_PROOF"
    manifest_path = Path(result["evidence"]["manifest_path"])
    validation = RunLedger.validate(manifest_path.parent.parent)
    assert validation["valid"] is True
    terminal = validation["terminal"]
    assert terminal["inputs"]["baseline"][0]["sha256"] == \
        result["input_manifest"]["baseline"][0]["sha256"]
    assert terminal["inputs"]["refactored"][0]["sha256"] == \
        result["input_manifest"]["refactored"][0]["sha256"]
    assert [stage["stage"] for stage in terminal["execution_stages"]] == [
        "baseline", "refactored"]


def test_pre_execution_rejection_is_exported_with_compared_surface(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    changed = JAVA_REFACTORED.replace("\\result == 1", "\\result == 2")
    baseline, candidate = _pair(tmp_path, ".java", JAVA_BASE, changed)
    with patch("pipeline.workflow_services.verify_files_detailed") as execute:
        result = mcp_server.verify_refactor(
            str(baseline.relative_to(tmp_path)),
            str(candidate.relative_to(tmp_path)),
            result_export="refactor/surface-rejected.json")
    execute.assert_not_called()
    assert result["code"] == "contract_surface_changed"
    assert result["claim"] == "NO_PROOF"
    assert result["result_export"]["status"] == "COMMITTED"
    validation = RunLedger.validate(
        Path(result["evidence"]["manifest_path"]).parent.parent)
    terminal = validation["terminal"]
    assert terminal["execution_stages"] == []
    assert terminal["semantic_bindings"]["gate_evidence"]


def test_sandbox_failure_is_no_proof_and_can_be_exported(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    baseline, candidate = _pair(tmp_path, ".java", JAVA_BASE, JAVA_REFACTORED)

    def unavailable(_files, mode):
        observation = ExecutionObservation(
            status="SANDBOX_UNAVAILABLE", exit_code=125,
            output="sandbox setup failed",
            requested_policy={"network": "denied"}, enforced_policy={},
            policy_compliance="NOT_ENFORCED",
            snapshot_manifest_sha256=f"snapshot-{mode}", snapshot_files=(),
            tool="openjml", command=("openjml", f"-{mode}"),
        )
        return VerificationExecutionResult(125, observation.output, observation)

    with patch("pipeline.workflow_services.verify_files_detailed",
               side_effect=unavailable):
        result = mcp_server.verify_refactor(
            str(baseline.relative_to(tmp_path)),
            str(candidate.relative_to(tmp_path)),
            result_export="refactor/sandbox-failed.json")
    assert result["claim"] == "NO_PROOF"
    assert result["request_satisfied"] is False
    assert result["verification_stages"][0]["execution"][
        "policy_compliance"] == "NOT_ENFORCED"
    assert result["result_export"]["status"] == "COMMITTED"


def test_publication_failure_downgrades_success_to_no_proof(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    baseline, candidate = _pair(tmp_path, ".java", JAVA_BASE, JAVA_REFACTORED)
    with patch("pipeline.workflow_services.verify_files_detailed",
               side_effect=_java_success), \
            patch("mcp_server.publish_multistage_evidence",
                  side_effect=OSError("publisher unavailable")):
        result = mcp_server.verify_refactor(
            str(baseline.relative_to(tmp_path)), str(candidate.relative_to(tmp_path)),
            result_export="refactor/publication-failed.json")
    assert result["status"] == "EVIDENCE_PUBLICATION_FAILED"
    assert result["claim"] == "NO_PROOF"
    assert result["request_satisfied"] is False
    assert result["evidence"]["publication_status"] == "FAILED"
    assert result["result_export"]["status"] == "COMMITTED"


def test_signing_intent_requires_human_approval_before_dispatch(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("pipeline.workflow_services.run_refactor_verification") as service:
        result = mcp_server.verify_refactor(
            "baseline/Account.java", "candidate/Account.java",
            signing_intent=True)
    service.assert_not_called()
    assert result["status"] == "APPROVAL_REQUIRED"
    assert result["claim"] == "NO_PROOF"
    assert result["approval"]["signing_authority_available"] is False
    assert "signing_key" not in result["workflow_result"]["request"]


def test_cli_and_mcp_share_normalized_unsigned_request_and_result(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    baseline, candidate = _pair(tmp_path, ".java", JAVA_BASE, JAVA_REFACTORED)
    cli_export = "cli-result.json"
    args = SimpleNamespace(
        baseline=str(baseline), refactored=str(candidate),
        json=cli_export, signing_key=None)
    ui = SimpleNamespace(console=SimpleNamespace(print=lambda *_args, **_kwargs: None))
    with patch("pipeline.workflow_services.verify_files_detailed",
               side_effect=_java_success):
        assert cli.command_verify_refactor(args, ui) == 0
    cli_result = json.loads((tmp_path / cli_export).read_text(encoding="utf-8"))
    with patch("pipeline.workflow_services.verify_files_detailed",
               side_effect=_java_success):
        mcp_result = mcp_server.verify_refactor(
            str(baseline.relative_to(tmp_path)), str(candidate.relative_to(tmp_path)),
            result_export=cli_export)
    assert cli_result["workflow_result"]["request"] == \
        mcp_result["workflow_result"]["request"]
    for key in ("status", "claim", "request_satisfied", "language", "backend"):
        assert cli_result[key] == mcp_result[key]


def test_real_mcp_transport_exercises_refactor_matrix():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("real stdio MCP acceptance is required only in provisioned CI")
    observation = collect_transport_observation("verify-refactor")
    assert observation["transport"] == "mcp-stdio-subprocess"
    assert observation["result_status"] == "APPROVAL_REQUIRED"
    assert "verify_refactor" in observation["discovered_tools"]
    assert len(observation["variants"]) == 11
