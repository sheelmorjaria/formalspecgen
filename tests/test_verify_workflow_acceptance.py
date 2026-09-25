# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Acceptance contract for complete CLI-to-MCP ``verify`` parity."""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("mcp")

import mcp_server  # noqa: E402
from pipeline import cli  # noqa: E402
from pipeline.isolated_verification import IsolatedVerificationResult  # noqa: E402
from pipeline.mcp_policy import authorize_mcp_invocation  # noqa: E402
from pipeline.parity_inventory import handler_input_schema  # noqa: E402
from pipeline.verify import VerificationExecutionResult  # noqa: E402
from pipeline.workflow_contracts import (  # noqa: E402
    VerificationWorkflowRequest,
    WorkflowInterface,
)
from scripts.mcp_acceptance_adapters import (  # noqa: E402
    collect_tool_schema,
    collect_transport_observation,
)


CASES = (
    ("Probe.java", "parse", "prusti", None),
    ("Probe.java", "check", "prusti", "results/java.json"),
    ("Probe.java", "esc", "prusti", None),
    ("Probe.jml", "esc", "prusti", None),
    ("Probe.rs", "parse", "kani", None),
    ("Probe.rs", "check", "prusti", None),
    ("Probe.rs", "esc", "prusti", None),
    ("Probe.rs", "esc", "kani", None),
    ("Probe.c", "esc", "prusti", None),
    ("Probe.cpp", "esc", "prusti", None),
    ("Probe.c", "parse", "prusti", None),
    ("Probe.c", "check", "prusti", None),
    ("Probe.cpp", "parse", "prusti", None),
    ("Probe.cpp", "check", "prusti", None),
    ("Probe.c", "parse", "prusti", "results/c-parse.json"),
    ("Probe.c", "check", "prusti", "results/c-check.json"),
    ("Probe.cpp", "parse", "prusti", "results/cpp-parse.json"),
    ("Probe.cpp", "check", "prusti", "results/cpp-check.json"),
)


def _source(root: Path, name: str) -> Path:
    path = root / name
    value = {
        ".java": "public class Probe { public static int value() { return 1; } }\n",
        ".jml": "public class Probe { public static int value() { return 1; } }\n",
        ".rs": "pub fn value() -> i32 { 1 }\n",
        ".c": "int value(void) { return 1; }\n",
        ".cpp": "int main() { return 0; }\n",
    }[path.suffix]
    path.write_text(value, encoding="utf-8")
    return path


def _raw(request: VerificationWorkflowRequest) -> IsolatedVerificationResult:
    if request.language in {"c", "cpp"} and request.mode != "esc":
        return IsolatedVerificationResult({
            "status": "UNSUPPORTED_MODE", "exit_code": 2, "claim": "NO_PROOF"})
    if request.mode == "parse":
        status = "PARSED"
    elif request.mode == "check":
        status = "RUST_CHECKED" if request.language == "rust" else "VERIFIED"
    else:
        status = "VERIFIED"
    payload = {"status": status, "exit_code": 0, "output": "fixture"}
    if request.language == "c":
        payload.update({"proved_goals": 1, "total_goals": 1})
    if request.effective_backend == "kani":
        payload["claim"] = "BOUNDED_RUST_EVIDENCE"
    if request.effective_backend == "esbmc":
        payload["claim"] = "BOUNDED_CPP_PROOF"
    return IsolatedVerificationResult(payload)


def test_verify_cli_and_mcp_requests_normalize_equivalently(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name, mode, backend, export in CASES:
        source = _source(tmp_path, name)
        cli_request = VerificationWorkflowRequest(
            str(source), mode=mode, backend=backend, result_export=export)
        mcp_request = VerificationWorkflowRequest(
            str(source), mode=mode, backend=backend, result_export=export)
        assert cli_request == mcp_request
        assert cli_request.required_effects(WorkflowInterface.MCP) == tuple(
            sorted(set(cli_request.required_effects(WorkflowInterface.CLI))
                   | {"evidence_publication"}))


def test_verify_cli_parser_and_transport_schema_cover_all_inputs():
    parsed = cli.build_parser().parse_args([
        "verify", "Probe.rs", "--mode", "esc", "--backend", "kani",
        "--json", "results/probe.json",
    ])
    assert (parsed.source, parsed.mode, parsed.backend, parsed.json) == (
        "Probe.rs", "esc", "kani", "results/probe.json")
    static = handler_input_schema(mcp_server.verify_code)
    assert static["field_names"] == ["source", "mode", "backend", "result_export"]
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("real stdio MCP acceptance is required only in its provisioned CI job")
    schema = collect_tool_schema("verify_code")["input_schema"]
    assert schema["required"] == ["source"]
    assert set(schema["properties"]) == {
        "source", "mode", "backend", "result_export"}
    assert schema["properties"]["mode"]["default"] == "esc"
    assert schema["properties"]["backend"]["default"] == "prusti"


def test_verify_effects_exports_and_unsupported_modes_are_enforced(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = _source(tmp_path, "Probe.java")
    readonly = VerificationWorkflowRequest(str(source))
    exporting = VerificationWorkflowRequest(
        str(source), result_export="results/probe.json")
    base = authorize_mcp_invocation(
        "verify_code", mode=readonly.mode, language=readonly.language,
        backend=readonly.effective_backend,
        effects=readonly.required_effects(WorkflowInterface.MCP))
    export = authorize_mcp_invocation(
        "verify_code", mode=exporting.mode, language=exporting.language,
        backend=exporting.effective_backend,
        effects=exporting.required_effects(WorkflowInterface.MCP))
    incomplete = authorize_mcp_invocation(
        "verify_code", mode="esc", language="java", backend="openjml",
        effects=("workspace_read", "workspace_write_new"))
    assert base.admitted and not base.permits("workspace_write_new")
    assert export.admitted and export.permits("workspace_write_new")
    assert incomplete.admitted is False

    c_source = _source(tmp_path, "Probe.c")
    with patch("mcp_server.execute_isolated_verification") as backend:
        rejected = mcp_server.verify_code(str(c_source), mode="check")
    backend.assert_not_called()
    assert rejected["status"] == "UNSUPPORTED_MODE"
    assert rejected["request_satisfied"] is False

    outside = tmp_path.parent / "Outside.java"
    outside.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    assert mcp_server.verify_code(str(outside))["code"] == "path_outside_workspace"

    destination = tmp_path / ".formalspecgen/mcp-output/results/existing.json"
    destination.parent.mkdir(parents=True)
    destination.write_text("existing", encoding="utf-8")
    request = VerificationWorkflowRequest(str(source), result_export="results/existing.json")
    with patch("mcp_server.verify_detailed", return_value=VerificationExecutionResult(
            0, "fixture", None)):
        result = mcp_server.verify_code(
            str(source), result_export=request.result_export)
    assert result["status"] == "RESULT_EXPORT_FAILED"
    assert destination.read_text(encoding="utf-8") == "existing"
    assert result["evidence"]["publication_status"] == "COMMITTED"


@pytest.mark.parametrize("name", ["Probe.c", "Probe.cpp"])
@pytest.mark.parametrize("mode", ["parse", "check"])
@pytest.mark.parametrize("exporting", [False, True])
def test_unsupported_native_mode_results_publish_with_optional_export(
        tmp_path, monkeypatch, name, mode, exporting):
    monkeypatch.chdir(tmp_path)
    source = _source(tmp_path, name)
    relative_export = (
        f"unsupported/{source.suffix[1:]}-{mode}.json" if exporting else None)
    with patch("mcp_server.execute_isolated_verification") as backend:
        result = mcp_server.verify_code(
            source.name, mode=mode, result_export=relative_export)
    backend.assert_not_called()
    assert result["status"] == "UNSUPPORTED_MODE"
    assert result["claim"] == "NO_PROOF"
    assert result["request_satisfied"] is False
    assert result["evidence"]["publication_status"] == "COMMITTED"
    assert result["mcp_admission"]["granted_effects"] == sorted(
        {"workspace_read", "evidence_publication"}
        | ({"workspace_write_new"} if exporting else set()))
    if exporting:
        assert result["result_export"]["status"] == "COMMITTED"
        exported = (
            tmp_path / ".formalspecgen/mcp-output" / str(relative_export))
        payload = json.loads(exported.read_text(encoding="utf-8"))
        assert payload["status"] == "UNSUPPORTED_MODE"
        assert payload["claim"] == "NO_PROOF"
        assert payload["request_satisfied"] is False
    else:
        assert "result_export" not in result


def test_verify_cli_and_mcp_results_are_semantically_equivalent(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cases = (
        ("Probe.java", "check", "prusti"),
        ("Probe.rs", "check", "prusti"),
        ("Proof.rs", "esc", "prusti"),
        ("Harness.rs", "esc", "kani"),
        ("Proof.c", "esc", "prusti"),
        ("Proof.cpp", "esc", "prusti"),
        ("Unsupported.c", "check", "prusti"),
    )
    for index, (name, mode, backend) in enumerate(cases):
        source = _source(tmp_path, name)
        request = VerificationWorkflowRequest(str(source), mode=mode, backend=backend)
        raw = _raw(request)
        cli_export = f"cli/{index}.json"
        arguments = [
            "verify", str(source), "--mode", mode, "--backend", backend,
            "--json", cli_export,
        ]
        with patch.object(cli, "execute_isolated_verification", return_value=raw):
            cli.main(arguments)
        cli_result = json.loads((tmp_path / cli_export).read_text(encoding="utf-8"))
        if request.language in {"java", "jml"}:
            backend_patch = patch(
                "mcp_server.verify_detailed",
                return_value=VerificationExecutionResult(
                    raw.exit_code, raw.output, None))
        else:
            backend_patch = patch(
                "mcp_server.execute_isolated_verification", return_value=raw)
        with backend_patch:
            mcp_result = mcp_server.verify_code(
                str(source), mode=mode, backend=backend)
        for field in ("status", "claim", "request_satisfied", "language", "mode"):
            assert cli_result.get(field) == mcp_result.get(field)
        assert cli_result["workflow_result"]["verification"] == \
            mcp_result["workflow_result"]["verification"]


def test_real_mcp_transport_discovers_and_calls_verify_variants():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("real stdio MCP acceptance is required only in its provisioned CI job")
    observation = collect_transport_observation("verify")
    assert observation["transport"] == "mcp-stdio-subprocess"
    assert observation["result_status"] == "VERIFY_FAILED"
    assert "verify_code" in observation["discovered_tools"]
    assert len(observation["variants"]) == 26
