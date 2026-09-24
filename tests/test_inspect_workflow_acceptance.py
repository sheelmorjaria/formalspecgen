# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""End-to-end acceptance cases for the complete inspection workflow."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

pytest.importorskip("mcp")
import anyio  # noqa: E402
from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import (  # noqa: E402
    StdioServerParameters,
    stdio_client,
)

import mcp_server  # noqa: E402
from pipeline import cli  # noqa: E402
from pipeline.mcp_policy import authorize_mcp_invocation  # noqa: E402
from pipeline.workflow_contracts import (  # noqa: E402
    InspectionWorkflowRequest,
    WorkflowInterface,
)


JAVA = "public class Probe { public int value() { return 1; } }\n"
JML = "public class Probe { //@ ensures \\result == 1;\n" \
      "public int value() { return 1; } }\n"
SEMANTIC_FIELDS = (
    "status", "claim", "scope", "parser_mode", "source_sha256", "class",
    "metrics", "findings", "automated_refactor_applied",
    "formal_defect_proved", "behavior_equivalence_proved",
)


def _sources(root: Path) -> list[Path]:
    java = root / "Probe.java"
    jml = root / "Probe.jml"
    java.write_text(JAVA, encoding="utf-8")
    jml.write_text(JML, encoding="utf-8")
    return [java, jml]


async def _transport_calls(calls: list[dict]) -> tuple[dict, list[dict]]:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(mcp_server.__file__).resolve())],
        cwd=str(Path.cwd()), env=dict(os.environ))
    with anyio.fail_after(30):
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                schema = next(
                    tool.inputSchema for tool in tools.tools
                    if tool.name == "inspect_code")
                results = []
                for arguments in calls:
                    response = await session.call_tool(
                        "inspect_code", arguments=arguments)
                    assert response.isError is False
                    assert isinstance(response.structuredContent, dict)
                    results.append(response.structuredContent)
    return schema, results


def _run_transport(calls: list[dict]) -> tuple[dict, list[dict]]:
    return anyio.run(_transport_calls, calls)


def test_cli_and_mcp_requests_normalize_equivalently(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", raising=False)
    for source in _sources(tmp_path):
        for export in (None, f"exports/{source.suffix[1:]}.json"):
            expected = InspectionWorkflowRequest(str(source), result_export=export)
            result = mcp_server.inspect_code(str(source), export)
            assert result["workflow_result"]["request"] == expected.as_dict()
            assert expected.required_effects(WorkflowInterface.MCP) == (
                ("workspace_read",) if export is None
                else ("workspace_read", "workspace_write_new"))


def test_cli_parser_and_mcp_discovery_expose_complete_inputs(
        tmp_path, monkeypatch):
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("real stdio MCP acceptance is required only in its provisioned CI job")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", raising=False)
    parsed = cli.build_parser().parse_args([
        "inspect", "Probe.java", "--json", "exports/result.json"])
    assert parsed.source == "Probe.java"
    assert parsed.json == "exports/result.json"

    schema, _results = _run_transport([])
    assert schema["required"] == ["source"]
    assert set(schema["properties"]) == {"source", "result_export"}
    assert schema["properties"]["source"]["type"] == "string"
    assert schema["properties"]["result_export"]["default"] is None


def test_inspection_read_and_export_effects_are_enforced(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", raising=False)
    source = _sources(tmp_path)[0]
    readonly = authorize_mcp_invocation(
        "inspect_code", mode="inspect", language="java",
        backend="builtin-java-inspector", effects=("workspace_read",))
    exporting = authorize_mcp_invocation(
        "inspect_code", mode="inspect", language="java",
        backend="builtin-java-inspector",
        effects=("workspace_read", "workspace_write_new"))
    assert readonly.granted_effects == ("workspace_read",)
    assert readonly.permits("workspace_write_new") is False
    assert exporting.granted_effects == ("workspace_read", "workspace_write_new")

    outside = tmp_path.parent / "Outside.java"
    outside.write_text(JAVA, encoding="utf-8")
    assert mcp_server.inspect_code(str(outside))["code"] == "path_outside_workspace"
    assert mcp_server.inspect_code(
        str(source), "../escape.json")["code"] == "OUTPUT_SCOPE_VIOLATION"
    destination = tmp_path / ".formalspecgen/mcp-output/exports/existing.json"
    destination.parent.mkdir(parents=True)
    destination.write_text("existing", encoding="utf-8")
    assert mcp_server.inspect_code(
        str(source), "exports/existing.json")["code"] == "OUTPUT_ALREADY_EXISTS"
    assert destination.read_text(encoding="utf-8") == "existing"

    oversized = tmp_path / "Oversized.java"
    oversized.write_bytes(b" " * (mcp_server.MCP_INSPECT_MAX_INPUT_BYTES + 1))
    assert mcp_server.inspect_code(str(oversized))["code"] == "INPUT_LIMIT_EXCEEDED"


def test_cli_and_mcp_results_are_semantically_equivalent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", raising=False)
    for source in _sources(tmp_path):
        export = f"results/{source.suffix[1:]}.json"
        with patch("pipeline.cli.SessionStore"):
            assert cli.main(["inspect", str(source), "--json", export]) == 0
        cli_result = json.loads((tmp_path / export).read_text(encoding="utf-8"))
        mcp_result = mcp_server.inspect_code(str(source), export)
        assert {key: cli_result[key] for key in SEMANTIC_FIELDS} == {
            key: mcp_result[key] for key in SEMANTIC_FIELDS}
        assert cli_result["workflow_result"]["request"] == \
            mcp_result["workflow_result"]["request"]
        assert cli_result["workflow_result"]["verification"] == \
            mcp_result["workflow_result"]["verification"]
        assert mcp_result["publication"]["status"] == "COMMITTED"


def test_real_mcp_transport_discovers_and_calls_every_inspection_variant(
        tmp_path, monkeypatch):
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("real stdio MCP acceptance is required only in its provisioned CI job")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", raising=False)
    sources = _sources(tmp_path)
    calls = []
    for source in sources:
        calls.append({"source": source.name})
        calls.append({
            "source": source.name,
            "result_export": f"transport/{source.suffix[1:]}.json",
        })
    schema, results = _run_transport(calls)
    assert set(schema["properties"]) == {"source", "result_export"}
    assert [result["status"] for result in results] == ["INSPECTED"] * 4
    assert [result["workflow_result"]["request"]["language"]
            for result in results] == ["java", "java", "jml", "jml"]
    assert results[0]["workflow_result"]["publication"] is None
    assert results[1]["workflow_result"]["publication"]["status"] == "COMMITTED"
    assert results[2]["workflow_result"]["publication"] is None
    assert results[3]["workflow_result"]["publication"]["status"] == "COMMITTED"
