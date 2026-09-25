# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Shared polyglot verification, isolation, and MCP admission regressions."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server
from pipeline.execution import ExecutionObservation
from pipeline.isolated_verification import (
    IsolatedVerificationResult,
    execute_isolated_verification,
)
from pipeline.kani import verified_property_count
from pipeline.mcp_policy import authorize_mcp_invocation
from pipeline.workflow_contracts import (
    VerificationWorkflowRequest,
    WorkflowContext,
    WorkflowInterface,
)
from pipeline.workflow_services import run_verification


def _observation(request, output: str, exit_code: int = 0) -> ExecutionObservation:
    return ExecutionObservation(
        status="COMPLETED", exit_code=exit_code, output=output,
        requested_policy={"network": "denied"},
        enforced_policy={"network": "denied"}, policy_compliance="ENFORCED",
        snapshot_manifest_sha256=request.snapshot.manifest_sha256,
        snapshot_files=request.snapshot.manifest,
        tool=request.tool, command=request.command,
        readonly_paths=tuple(str(item) for item in request.readonly_paths),
    )


class RecordingExecutor:
    def __init__(self, outputs: dict[str, str] | None = None,
                 exit_codes: dict[str, int] | None = None):
        self.requests = []
        self.outputs = outputs or {}
        self.exit_codes = exit_codes or {}

    def execute(self, request):
        self.requests.append(request)
        return _observation(
            request, self.outputs.get(request.tool, ""),
            self.exit_codes.get(request.tool, 0))


def _tool(tmp_path: Path, name: str) -> str:
    path = tmp_path / name
    path.write_text("fixture", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


@pytest.mark.parametrize(
    ("name", "mode", "backend", "tool", "output", "status", "claim"),
    [
        ("Probe.rs", "check", "prusti", "rustc", "", "RUST_CHECKED", "STATIC_CHECK"),
        ("Proof.rs", "esc", "prusti", "prusti", "", "VERIFIED", "DEDUCTIVE_PROOF"),
        ("Harness.rs", "esc", "kani", "kani", "Successfully verified 1 of 1 properties",
         "VERIFIED", "BOUNDED_EVIDENCE"),
        ("proof.c", "esc", "prusti", "frama-c", "Proved goals: 1 / 1",
         "VERIFIED", "DEDUCTIVE_PROOF"),
        ("proof.cpp", "esc", "prusti", "esbmc", "VERIFICATION SUCCESSFUL",
         "VERIFIED", "BOUNDED_CPP_PROOF"),
    ],
)
def test_polyglot_routes_use_strict_executor_and_shared_policy(
        tmp_path, monkeypatch, name, mode, backend, tool, output, status, claim):
    source = tmp_path / name
    if name.endswith(".rs"):
        text = ("use prusti_contracts::*;\n#[ensures(result == 1)]\n"
                "#[kani::proof]\nfn value() -> i32 { 1 }\n")
    elif name.endswith(".c"):
        text = ("/*@ assigns \\nothing; ensures \\result == 1; */\n"
                "int value(void) { return 1; }\n")
    else:
        text = "int main() { return 0; }\n"
    source.write_text(text, encoding="utf-8")
    monkeypatch.setattr("pipeline.isolated_verification.config.RUSTC_BIN",
                        _tool(tmp_path, "rustc"))
    monkeypatch.setattr("pipeline.isolated_verification.config.PRUSTI_BIN",
                        _tool(tmp_path, "prusti-rustc"))
    monkeypatch.setattr("pipeline.isolated_verification.config.KANI_BIN",
                        _tool(tmp_path, "kani-driver"))
    monkeypatch.setattr("pipeline.isolated_verification.config.CC_BIN",
                        _tool(tmp_path, "gcc"))
    monkeypatch.setattr("pipeline.isolated_verification.config.FRAMAC_BIN",
                        _tool(tmp_path, "frama-c"))
    monkeypatch.setattr(
        "pipeline.isolated_verification.shutil.which",
        lambda value: _tool(tmp_path, value)
        if value in {"esbmc", "z3"} else None)
    executor = RecordingExecutor({tool: output})
    request = VerificationWorkflowRequest(str(source), mode=mode, backend=backend)
    context = WorkflowContext.for_cli(
        request.required_effects(WorkflowInterface.CLI), workspace_root=tmp_path)
    result = run_verification(
        request, context,
        execute=lambda path, **options: execute_isolated_verification(
            path, executor=executor, **options)).payload
    assert result["status"] == status
    assert result["claim"] == claim
    assert result["request_satisfied"] is True
    assert executor.requests
    assert all(item.policy.network == "denied" for item in executor.requests)
    assert executor.requests[-1].tool == tool


@pytest.mark.parametrize("suffix,mode", [(".c", "check"), (".cpp", "parse")])
def test_unsupported_native_modes_stop_before_execution(tmp_path, suffix, mode):
    source = tmp_path / f"Probe{suffix}"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    request = VerificationWorkflowRequest(str(source), mode=mode)
    context = WorkflowContext.for_cli(
        request.required_effects(WorkflowInterface.CLI), workspace_root=tmp_path)
    execute = RecordingExecutor()
    result = run_verification(
        request, context,
        execute=lambda path, **options: execute_isolated_verification(
            path, executor=execute, **options)).payload
    assert result["status"] == "UNSUPPORTED_MODE"
    assert result["request_satisfied"] is False
    assert execute.requests == []


@pytest.mark.parametrize(
    ("name", "mode", "backend", "profile"),
    [
        ("Probe.java", "esc", "prusti", "java-openjml-verification"),
        ("Probe.rs", "check", "kani", "rust-compiler-verification"),
        ("Probe.rs", "esc", "prusti", "rust-prusti-verification"),
        ("Probe.rs", "esc", "kani", "rust-kani-verification"),
        ("Probe.c", "esc", "prusti", "c-framac-verification"),
        ("Probe.cpp", "esc", "prusti", "cpp-esbmc-verification"),
    ],
)
def test_every_supported_verify_route_has_an_invocation_profile(
        tmp_path, name, mode, backend, profile):
    request = VerificationWorkflowRequest(
        str(tmp_path / name), mode=mode, backend=backend)
    admission = authorize_mcp_invocation(
        "verify_code", mode=request.mode, language=request.language,
        backend=request.effective_backend,
        effects=request.required_effects(WorkflowInterface.MCP))
    assert admission.admitted is True
    assert admission.profile.name == profile


def test_mcp_native_result_preserves_execution_and_receipt(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = Path("Proof.cpp")
    source.write_text("int main() { return 0; }\n", encoding="utf-8")
    request_seen = None

    def execute(path, **_options):
        nonlocal request_seen
        fixture = tmp_path / "snapshot"
        fixture.mkdir()
        from pipeline.execution import ExecutionPolicy, SourceSnapshot
        snapshot = SourceSnapshot.create(fixture / "input", {path.name: path.read_bytes()})
        request_seen = type("Request", (), {
            "snapshot": snapshot, "tool": "esbmc", "command": ("esbmc", "/input/Proof.cpp"),
            "readonly_paths": (), "policy": ExecutionPolicy(),
        })()
        observation = _observation(request_seen, "VERIFICATION SUCCESSFUL")
        return IsolatedVerificationResult({
            "status": "VERIFIED", "exit_code": 0,
            "claim": "BOUNDED_CPP_PROOF", "output": observation.output,
        }, (observation,))

    monkeypatch.setattr(mcp_server, "execute_isolated_verification", execute)
    result = mcp_server.verify_code("Proof.cpp", backend="prusti")
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "BOUNDED_CPP_PROOF"
    assert result["execution"]["tool"] == "esbmc"
    assert result["evidence"]["publication_status"] == "COMMITTED"
    assert result["mcp_admission"]["profile"] == "cpp-esbmc-verification"


def test_kani_multiline_success_output_counts_checked_properties():
    output = """Check 1: proof.assertion.1
     - Status: SUCCESS
     - Description: assertion
"""
    assert verified_property_count(output) == 1


def test_verifier_initialization_failure_is_not_a_candidate_failure(
        tmp_path, monkeypatch):
    source = tmp_path / "Proof.rs"
    source.write_text(
        "use prusti_contracts::*;\n#[ensures(result == 1)]\n"
        "fn value() -> i32 { 1 }\n", encoding="utf-8")
    monkeypatch.setattr(
        "pipeline.isolated_verification.config.PRUSTI_BIN",
        _tool(tmp_path, "prusti-rustc"))
    executor = RecordingExecutor(
        {"prusti": "Failed to find Java home directory"}, {"prusti": 101})
    result = execute_isolated_verification(
        source, backend="prusti", executor=executor).payload
    assert result["status"] == "TOOL_INITIALIZATION_FAILED"
    assert result["claim"] == "NO_PROOF"
    assert result["request_satisfied"] is False
