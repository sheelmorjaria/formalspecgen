# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Shared-service and strict-interface acceptance for codebase analysis."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server
from pipeline import cli
from pipeline.mcp_policy import authorize_mcp_invocation
from pipeline.workflow_contracts import (
    CodebaseAnalysisWorkflowRequest,
    WorkflowContext,
    WorkflowInterface,
)
from pipeline.workflow_services import run_codebase_analysis


JAVA = (
    "public class Counter { private int value; "
    "public void inc() { if (value < 3) value = value + 1; } }\n")
WARNING_JAVA = (
    "import java.util.List;\n"
    "public class Basket { private List<Integer> items; }\n")


def _request(root: Path, **overrides: object) -> CodebaseAnalysisWorkflowRequest:
    values = {
        "target_dir": str(root / "src"),
        "out_dir": str(root / "extracted"),
        "project_root": str(root / "project"),
        "result_export": None,
    }
    values.update(overrides)
    return CodebaseAnalysisWorkflowRequest(**values)


def _context(
        request: CodebaseAnalysisWorkflowRequest, root: Path,
        **budgets: int) -> WorkflowContext:
    defaults = {
        "max_input_bytes": 4096,
        "max_input_files": 16,
        "max_traversal_entries": 64,
        "max_traversal_depth": 8,
        "max_result_bytes": 64 * 1024,
    }
    defaults.update(budgets)
    return WorkflowContext.for_cli(
        request.required_effects(WorkflowInterface.CLI),
        workspace_root=root, resource_budget=defaults)


def test_request_effects_admission_and_cli_arguments_cover_complete_surface(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cli_request = CodebaseAnalysisWorkflowRequest(
        "src", "artifacts", "project", result_export="result.json")
    mcp_request = CodebaseAnalysisWorkflowRequest(
        "src", "artifacts", "project", result_export="result.json")
    assert cli_request == mcp_request
    assert cli_request.as_dict()["workflow"] == "analyze-codebase"
    assert cli_request.required_effects(WorkflowInterface.MCP) == (
        "workspace_read", "workspace_write_new")
    admission = authorize_mcp_invocation(
        "analyze_codebase", mode="analyze", language="polyglot",
        backend="builtin-codebase-analysis",
        effects=cli_request.required_effects(WorkflowInterface.MCP))
    assert admission.admitted
    assert admission.permits("external_execution") is False
    assert admission.permits("provider_access") is False
    parsed = cli.build_parser().parse_args([
        "analyze-codebase", "src", "--out-dir", "artifacts",
        "--project-root", "project", "--json", "result.json"])
    assert (parsed.target_dir, parsed.out_dir, parsed.project_root, parsed.json) == (
        "src", "artifacts", "project", "result.json")


def test_shared_service_captures_polyglot_inputs_and_prepares_unreviewed_artifacts(
        tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "Counter.java").write_text(JAVA, encoding="utf-8")
    (source / "Meter.c").write_text(
        "struct Meter { int value; };\n", encoding="utf-8")
    (source / "ignored.py").write_text("print('ignored')\n", encoding="utf-8")
    request = _request(tmp_path)
    result = run_codebase_analysis(request, _context(request, tmp_path))
    assert result.payload["status"] == "EXTRACTED"
    assert result.payload["claim"] == "UNREVIEWED_EXTRACTION_CANDIDATE"
    assert result.payload["request_satisfied"] is True
    assert result.payload["review_status"] == "unreviewed"
    assert result.payload["input_snapshot"]["file_count"] == 2
    assert {item["path"] for item in result.payload["input_snapshot"]["files"]} == {
        "Counter.java", "Meter.c"}
    assert "extracted_architecture.json" in result.extraction_artifacts
    assert "counter.v2.yaml" in result.candidate_artifacts
    assert "meter.v2.yaml" in result.candidate_artifacts
    assert not Path(request.out_dir).exists()
    assert not Path(request.project_root).exists()
    architecture = json.loads(
        result.extraction_artifacts["extracted_architecture.json"])
    assert architecture["review_status"] == "unreviewed"


def test_shared_service_normalizes_embedded_diagnostics_before_hashing(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    warning_source = source / "Basket.java"
    warning_source.write_text(WARNING_JAVA, encoding="utf-8")
    request = _request(tmp_path)
    result = run_codebase_analysis(request, _context(request, tmp_path))
    architecture = json.loads(
        result.extraction_artifacts["extracted_architecture.json"])
    assert result.payload["warnings"]
    assert architecture["warnings"] == result.payload["warnings"]
    assert {item["file"] for item in architecture["warnings"]} == {
        str(warning_source)}
    assert "formalspecgen-analysis-" not in json.dumps(architecture)
    assert result.payload["architecture"] is None
    assert result.payload["domains"] == []
    assert result.architecture_artifact == (
        "extraction", "extracted_architecture.json")


@pytest.mark.parametrize(("budget", "value", "expected"), [
    ("max_input_bytes", 1, "INPUT_LIMIT_EXCEEDED"),
    ("max_input_files", 0, "INPUT_FILE_LIMIT_EXCEEDED"),
    ("max_traversal_entries", 0, "INPUT_TRAVERSAL_LIMIT_EXCEEDED"),
    ("max_traversal_depth", 0, "INPUT_TRAVERSAL_LIMIT_EXCEEDED"),
])
def test_input_limits_stop_before_extractor_dispatch(
        tmp_path, budget, value, expected):
    source = tmp_path / "src" / "nested"
    source.mkdir(parents=True)
    (source / "Counter.java").write_text(JAVA, encoding="utf-8")
    request = _request(tmp_path)
    with patch("pipeline.codebase_analysis.analyze_codebase") as extractor:
        with pytest.raises(ValueError, match=expected):
            run_codebase_analysis(
                request, _context(request, tmp_path, **{budget: value}))
    extractor.assert_not_called()


def test_symlinked_source_entry_is_rejected_before_extraction(tmp_path):
    source = tmp_path / "src"
    outside = tmp_path / "outside"
    source.mkdir()
    outside.mkdir()
    (outside / "Counter.java").write_text(JAVA, encoding="utf-8")
    (source / "linked").symlink_to(outside, target_is_directory=True)
    request = _request(tmp_path)
    with patch("pipeline.codebase_analysis.analyze_codebase") as extractor:
        with pytest.raises(ValueError, match="INPUT_SYMLINK_REJECTED"):
            run_codebase_analysis(request, _context(request, tmp_path))
    extractor.assert_not_called()


def test_mcp_enforces_roots_no_replace_and_hidden_effect_boundaries(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "src"
    source.mkdir()
    (source / "Counter.java").write_text(JAVA, encoding="utf-8")
    (source / "Basket.java").write_text(WARNING_JAVA, encoding="utf-8")
    with patch("subprocess.run") as process, \
            patch("pipeline.llm._chat_fn") as provider:
        result = mcp_server.analyze_codebase(
            "src", "analysis", "project", "results/analysis.json")
    assert result["status"] == "EXTRACTED"
    assert result["claim"] == "UNREVIEWED_EXTRACTION_CANDIDATE"
    assert result["publication"]["status"] == "COMMITTED"
    assert result["result_export"]["status"] == "COMMITTED"
    assert result["mcp_admission"]["profile"] == \
        "bounded-polyglot-codebase-analysis"
    process.assert_not_called()
    provider.assert_not_called()
    output = tmp_path / ".formalspecgen" / "mcp-output"
    assert (output / "analysis/extracted_architecture.json").is_file()
    assert (output / "project/domains/candidates/counter.v2.yaml").is_file()
    assert (output / "results/analysis.json").is_file()
    architecture = Path(result["architecture"])
    domains = [Path(value) for value in result["domains"]]
    published_by_path = {
        Path(metadata["path"]): metadata
        for metadata in result["publication"]["artifacts"].values()
    }
    assert architecture == output / "analysis/extracted_architecture.json"
    assert architecture in published_by_path
    assert domains and all(path in published_by_path for path in domains)
    embedded = json.loads(architecture.read_text(encoding="utf-8"))
    assert embedded["warnings"] == result["warnings"]
    assert "formalspecgen-analysis-" not in json.dumps(embedded)
    exported = json.loads(
        (output / "results/analysis.json").read_text(encoding="utf-8"))
    assert exported["architecture"] == result["architecture"]
    assert exported["domains"] == result["domains"]
    existing = output / "results/existing.json"
    existing.write_text("existing", encoding="utf-8")
    export_collision = mcp_server.analyze_codebase(
        "src", "analysis-export-collision", "project-export-collision",
        "results/existing.json")
    assert export_collision["status"] == "FAIL"
    assert export_collision["claim"] == "NO_PROOF"
    assert export_collision["publication"]["status"] == "COMMITTED"
    assert export_collision["result_export"]["status"] == "FAILED"
    assert existing.read_text(encoding="utf-8") == "existing"
    repeated = mcp_server.analyze_codebase("src", "analysis", "project")
    assert repeated["status"] == "FAIL"
    assert repeated["code"] == "OUTPUT_ALREADY_EXISTS"
    missing = mcp_server.analyze_codebase(
        "missing", "unused", "unused-project", "results/missing.json")
    assert missing["status"] == "FAIL"
    assert missing["result_export"]["status"] == "COMMITTED"
    assert (output / "results/missing.json").is_file()
    assert mcp_server.analyze_codebase("../outside")["code"] == \
        "path_outside_workspace"
    assert mcp_server.analyze_codebase("src", "../escape")["code"] == \
        "OUTPUT_SCOPE_VIOLATION"


def test_cli_uses_shared_service_and_no_replace_publication(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "src"
    source.mkdir()
    (source / "Counter.java").write_text(JAVA, encoding="utf-8")
    arguments = [
        "analyze-codebase", "src", "--out-dir", "analysis",
        "--project-root", "project", "--json", "results/analysis.json"]
    assert cli.main(arguments) == 0
    exported = json.loads((tmp_path / "results/analysis.json").read_text())
    assert exported["status"] == "EXTRACTED"
    assert Path(exported["architecture"]) == \
        tmp_path / "analysis/extracted_architecture.json"
    assert Path(exported["architecture"]).is_file()
    assert exported["domains"]
    assert all(Path(value).is_file() for value in exported["domains"])
    assert exported["workflow_result"]["request"] == \
        CodebaseAnalysisWorkflowRequest(
            "src", "analysis", "project",
            result_export="results/analysis.json").as_dict()
    architecture = tmp_path / "analysis/extracted_architecture.json"
    before = architecture.read_bytes()
    assert cli.main(arguments) == 1
    assert architecture.read_bytes() == before


def test_mcp_references_follow_configured_output_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORMALSPECGEN_MCP_OUTPUT_ROOT", "controlled-output")
    source = tmp_path / "src"
    source.mkdir()
    (source / "Counter.java").write_text(JAVA, encoding="utf-8")
    result = mcp_server.analyze_codebase(
        "src", "analysis", "models", "results/analysis.json")
    output = tmp_path / "controlled-output"
    assert Path(result["architecture"]) == \
        output / "analysis/extracted_architecture.json"
    assert all(output in Path(value).parents for value in result["domains"])
    exported = json.loads(
        (output / "results/analysis.json").read_text(encoding="utf-8"))
    assert exported["architecture"] == result["architecture"]
    assert exported["domains"] == result["domains"]


def test_cli_and_mcp_semantic_results_are_equivalent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "src"
    source.mkdir()
    (source / "Counter.java").write_text(JAVA, encoding="utf-8")
    assert cli.main([
        "analyze-codebase", "src", "--out-dir", "cli-analysis",
        "--project-root", "cli-project", "--json", "cli-result.json"]) == 0
    cli_result = json.loads((tmp_path / "cli-result.json").read_text())
    mcp_result = mcp_server.analyze_codebase(
        "src", "mcp-analysis", "mcp-project", "mcp-result.json")
    semantic_fields = (
        "status", "claim", "request_satisfied", "components", "warnings",
        "os_pattern_evidence", "validation", "review_status", "limitations",
        "input_snapshot",
    )
    assert {field: cli_result.get(field) for field in semantic_fields} == {
        field: mcp_result.get(field) for field in semantic_fields}
    assert cli_result["workflow_result"]["request"]["workflow"] == \
        mcp_result["workflow_result"]["request"]["workflow"] == \
        "analyze-codebase"


def test_real_mcp_transport_discovers_and_calls_analysis_variants():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("real stdio MCP acceptance is required only in its CI job")
    pytest.importorskip("mcp")
    from scripts.mcp_acceptance_adapters import collect_transport_observation

    observation = collect_transport_observation("analyze-codebase")
    assert observation["transport"] == "mcp-stdio-subprocess"
    assert observation["variants"] == [
        "polyglot-success-export", "unsupported-input", "missing-input",
        "denied-path", "publication-collision", "negative-result-export"]
    schema = observation["input_schema"]
    assert schema["required"] == ["target_dir"]
    assert set(schema["properties"]) == {
        "target_dir", "out_dir", "project_root", "result_export"}
