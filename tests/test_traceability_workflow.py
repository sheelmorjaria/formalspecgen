# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Bounded traceability, publication identity, and CLI/MCP parity."""
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server
from pipeline import cli
from pipeline.mcp_policy import authorize_mcp_invocation
from pipeline.traceability_workflow import TRACEABILITY_BUDGET, run_traceability_workflow
from pipeline.workflow_contracts import (
    TraceabilityWorkflowRequest, WorkflowContext, WorkflowInterface,
)
from pipeline.workflow_services import run_traceability_generation
from test_traceability import DOMAIN_YAML, REQUIREMENTS, SOURCE


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", "1")
    monkeypatch.delenv("FORMALSPECGEN_MCP_OUTPUT_ROOT", raising=False)
    (tmp_path / "domain.yaml").write_text(DOMAIN_YAML)
    (tmp_path / "requirements.req").write_text(REQUIREMENTS)
    for directory, content in (("a", SOURCE), ("b", "int pending = 100;\n")):
        folder = tmp_path / "src" / directory
        folder.mkdir(parents=True)
        (folder / "Counter.java").write_text(content)
    return tmp_path


def request(**kwargs):
    return TraceabilityWorkflowRequest(
        "domain.yaml", "src", "requirements.req", **kwargs)


def context(root, **budgets):
    return WorkflowContext.for_cli(
        ("workspace_read", "workspace_write_new"), workspace_root=root,
        resource_budget={**TRACEABILITY_BUDGET, **budgets})


def call(**kwargs):
    return mcp_server.generate_traceability_matrix(
        "domain.yaml", "src", "requirements.req", **kwargs)


def test_request_and_argument_equivalence(inputs):
    args = cli.build_parser().parse_args([
        "generate-traceability-matrix", "domain.yaml", "src",
        "--reqs", "requirements.req", "--out", "reports/m.md",
        "--json", "results/m.json"])
    normalized = TraceabilityWorkflowRequest(
        args.domain, args.source, args.requirements,
        out=args.out, result_export=args.json_out)
    assert normalized == request(out="reports/m.md", result_export="results/m.json")
    assert normalized.required_effects(WorkflowInterface.MCP) == (
        "workspace_read", "workspace_write_new")
    admitted = authorize_mcp_invocation(
        "generate_traceability_matrix", mode="generate", language="mixed",
        backend="builtin-traceability", effects=normalized.required_effects(WorkflowInterface.MCP))
    assert admitted.admitted
    assert not admitted.permits("external_execution")
    assert not admitted.permits("provider_access")


def test_capture_identity_duplicate_names_and_unmapped_rows(inputs):
    result = run_traceability_generation(request(), context(inputs))
    payload = result.payload
    assert payload["matrix_file"] is None
    assert payload["claim"] == "NO_PROOF"
    rows = {row["req"]: row for row in payload["rows"]}
    assert rows["REQ-001"]["source"] == "a/Counter.java"
    assert rows["REQ-003"]["source"] == "b/Counter.java"
    assert rows["REQ-004"]["status"] == "UNMAPPED"
    for row in rows.values():
        if row["source"]:
            assert row["source_sha256"] == hashlib.sha256(
                (inputs / "src" / row["source"]).read_bytes()).hexdigest()
    manifest = payload["input_snapshot"]["files"]
    assert len(manifest) == 4
    assert payload["input_snapshot"]["manifest_sha256"] == hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert "formalspecgen-traceability-" not in json.dumps(payload)


def test_capture_once_before_matching(inputs):
    from pipeline.traceability import generate_traceability_matrix
    original = (inputs / "src/a/Counter.java").read_bytes()
    def mutate_then_match(*args, **kwargs):
        (inputs / "src/a/Counter.java").write_text("changed after capture")
        return generate_traceability_matrix(*args, **kwargs)
    with patch("pipeline.traceability.generate_traceability_matrix", side_effect=mutate_then_match):
        result = run_traceability_generation(request(), context(inputs))
    assert result.payload["rows"][0]["source_sha256"] == hashlib.sha256(original).hexdigest()


def test_capture_reads_only_aggregate_allowance_plus_overflow_probe(inputs, monkeypatch):
    import pipeline.workflow_services as services
    original = services.os.fdopen
    requests = []
    class Reader:
        def __init__(self, descriptor, mode):
            self.handle = original(descriptor, mode)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.handle.close()
        def fileno(self):
            return self.handle.fileno()
        def read(self, amount):
            requests.append(amount)
            return self.handle.read(amount)
    monkeypatch.setattr(services.os, "fdopen", Reader)
    allowance = (inputs / "domain.yaml").stat().st_size + 2
    with pytest.raises(ValueError, match="INPUT_LIMIT_EXCEEDED"):
        run_traceability_generation(request(), context(inputs, max_input_bytes=allowance))
    assert requests == [allowance + 1, 3]


@pytest.mark.parametrize("malformed", [{}, {"m.md": {}}, {"m.md": {"path": ""}}])
def test_missing_publication_reference_is_not_guessed(inputs, malformed):
    from pipeline.workflow_services import bind_traceability_publication
    prepared = run_traceability_generation(request(), context(inputs))
    with pytest.raises(ValueError):
        bind_traceability_publication(prepared, malformed, "m.md")


def test_output_limits_and_symlink_destinations(inputs, monkeypatch):
    monkeypatch.setattr(mcp_server, "MCP_TRACEABILITY_MAX_RESULT_BYTES", 1)
    result = call()
    assert result["request_satisfied"] is False
    assert result["code"] == "RESULT_LIMIT_EXCEEDED"
    monkeypatch.setattr(mcp_server, "MCP_TRACEABILITY_MAX_RESULT_BYTES", 8*1024*1024)
    output = inputs / ".formalspecgen/mcp-output"
    output.mkdir(parents=True, exist_ok=True)
    (output / "link").symlink_to(inputs, target_is_directory=True)
    result = call(out="link/m.md", result_export="failure.json")
    assert result["request_satisfied"] is False
    assert result["code"] == "OUTPUT_SYMLINK_REJECTED"
    assert result["result_export"]["status"] == "COMMITTED"
    assert not (inputs / "m.md").exists()


@pytest.mark.parametrize("budget,value,code", [
    ("max_input_bytes", 0, "INPUT_LIMIT_EXCEEDED"),
    ("max_input_bytes", 1600, "INPUT_LIMIT_EXCEEDED"),
    ("max_input_files", 2, "INPUT_FILE_LIMIT_EXCEEDED"),
    ("max_traversal_entries", 1, "INPUT_TRAVERSAL_LIMIT_EXCEEDED"),
    ("max_traversal_depth", 0, "INPUT_TRAVERSAL_LIMIT_EXCEEDED"),
])
def test_capture_limits_precede_matching(inputs, budget, value, code):
    with patch("pipeline.traceability.generate_traceability_matrix") as generate:
        with pytest.raises(ValueError, match=code):
            run_traceability_generation(request(), context(inputs, **{budget: value}))
    generate.assert_not_called()


def test_exact_aggregate_limit_and_matching_limit(inputs):
    size = sum(path.stat().st_size for path in inputs.rglob("*") if path.is_file())
    assert run_traceability_generation(
        request(), context(inputs, max_input_bytes=size)).payload["request_satisfied"]
    with pytest.raises(ValueError, match="INPUT_LIMIT_EXCEEDED"):
        run_traceability_generation(request(), context(inputs, max_input_bytes=size-1))
    with pytest.raises(ValueError, match="MATCHING_LIMIT_EXCEEDED"):
        run_traceability_generation(request(), context(inputs, max_matching_steps=1))


@pytest.mark.parametrize("missing", ["workspace_read", "workspace_write_new"])
def test_effect_denial(inputs, missing):
    ctx = WorkflowContext.for_cli(
        tuple(effect for effect in ("workspace_read", "workspace_write_new") if effect != missing),
        workspace_root=inputs, resource_budget=TRACEABILITY_BUDGET)
    result = run_traceability_workflow(
        request(), ctx, output_root=inputs / "out", matrix_key="m.md", export_key="m.json")
    assert result["request_satisfied"] is False
    assert not (inputs / "out/m.md").exists()
    assert not (inputs / "out/m.json").exists()


@pytest.mark.parametrize("custom", [False, True])
def test_publication_references_exports_and_hidden_effects(inputs, monkeypatch, custom):
    output = inputs / ("custom" if custom else ".formalspecgen/mcp-output")
    if custom:
        monkeypatch.setenv("FORMALSPECGEN_MCP_OUTPUT_ROOT", str(output))
    with patch("subprocess.run", side_effect=AssertionError("unexpected execution")), \
            patch("pipeline.llm._chat_fn", side_effect=AssertionError("unexpected provider")):
        result = call()
    assert result["request_satisfied"], result
    assert result["claim"] == "NO_PROOF"
    assert Path(result["matrix_file"]) == output / "traceability-matrix.md"
    exported = json.loads((output / "traceability-matrix.json").read_text())
    assert exported["matrix_file"] == result["matrix_file"]
    assert exported["rows"] == result["rows"]
    for stage in ("publication", "result_export"):
        for item in result[stage]["artifacts"].values():
            assert hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest() == item["sha256"]


def test_cli_mcp_semantic_result_equivalence(inputs):
    assert cli.main([
        "generate-traceability-matrix", "domain.yaml", "src", "--reqs", "requirements.req",
        "--out", "matrix.md", "--json", "result.json"]) == 0
    terminal = json.loads((inputs / "result.json").read_text())
    remote = call(out="matrix.md", result_export="result.json")
    for key in ("status", "claim", "request_satisfied", "rows", "coverage", "input_snapshot", "limitations"):
        assert terminal[key] == remote[key]
    assert terminal["workflow_result"]["request"] == remote["workflow_result"]["request"]


def test_cli_and_mcp_preserve_custom_output_extensions(inputs):
    assert cli.main([
        "generate-traceability-matrix", "domain.yaml", "src", "--reqs", "requirements.req",
        "--out", "report.txt", "--json", "report.data"]) == 0
    result = call(out="report.txt", result_export="report.data")
    assert result["request_satisfied"]
    assert Path(result["matrix_file"]).suffix == ".txt"
    assert json.loads((inputs / "report.data").read_text())["rows"] == result["rows"]


@pytest.mark.parametrize("problem", [
    "domain", "requirements", "encoding", "symlink", "missing", "denied",
    "matrix-collision", "export-collision",
])
def test_negative_outcomes_and_exports(inputs, problem):
    if problem == "domain":
        (inputs / "domain.yaml").write_text("{}")
    elif problem == "requirements":
        (inputs / "requirements.req").write_text("No requirement identifiers")
    elif problem == "encoding":
        (inputs / "src/a/Counter.java").write_bytes(b"\xff")
    elif problem == "symlink":
        (inputs / "src/link.java").symlink_to(inputs / "domain.yaml")
    elif problem == "missing":
        (inputs / "domain.yaml").unlink()
    elif problem == "denied":
        (inputs / "domain.yaml").unlink()
        (inputs / "domain.yaml").symlink_to(inputs.parent / "outside.yaml")
    output = inputs / ".formalspecgen/mcp-output"
    if problem.endswith("collision"):
        output.mkdir(parents=True)
        (output / ("m.md" if problem == "matrix-collision" else "m.json")).write_text("retain")
    result = call(out="m.md", result_export="m.json")
    assert result["request_satisfied"] is False, result
    assert result["claim"] == "NO_PROOF"
    if problem == "export-collision":
        assert (output / "m.json").read_text() == "retain"
        assert result["result_export"]["status"] == "FAILED"
        assert (output / "m.md").exists()
    else:
        assert result["result_export"]["status"] == "COMMITTED"
        exported = json.loads((output / "m.json").read_text())
        assert exported["request_satisfied"] is False
        if problem == "matrix-collision":
            assert (output / "m.md").read_text() == "retain"


@pytest.mark.parametrize("target", ["domain.yaml", "requirements.req", "src/a/Counter.java", "m.md"])
def test_cli_export_cannot_replace_inputs_or_matrix(inputs, target):
    before = {str(path): path.read_bytes() for path in inputs.rglob("*") if path.is_file()}
    with patch("pipeline.traceability_workflow.run_traceability_generation") as generate:
        assert cli.main([
            "generate-traceability-matrix", "domain.yaml", "src", "--reqs", "requirements.req",
            "--out", "m.md", "--json", target]) == 2
    generate.assert_not_called()
    assert all(Path(path).read_bytes() == data for path, data in before.items())


def test_real_mcp_transport_traceability():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("provisioned stdio transport acceptance")
    pytest.importorskip("mcp")
    from scripts.mcp_acceptance_adapters import collect_transport_observation
    observation = collect_transport_observation("generate-traceability-matrix")
    assert observation["transport"] == "mcp-stdio-subprocess"
    assert set(observation["input_schema"]["properties"]) == {
        "domain", "source", "requirements", "out", "result_export"}
    assert observation["input_schema"]["required"] == ["domain", "source", "requirements"]
    assert len(observation["semantic_results"]) >= 10
