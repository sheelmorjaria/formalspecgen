# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import mcp_server
from pipeline import cli, security_poc
from pipeline.security_template_workflow import SECURITY_TEMPLATE_BUDGET, run_security_template_workflow
from pipeline.workflow_contracts import SecurityTemplateWorkflowRequest, WorkflowContext


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "Target.java").write_text("public class Target { public int get(int[] a, int i) { return a[i]; } }")
    (tmp_path / "report.json").write_text('{"findings":[{"cwe":"CWE-125"}]}')
    monkeypatch.setenv("FORMALSPECGEN_MCP_OUTPUT_ROOT", str(tmp_path / "custom-output"))
    return tmp_path


def request(**values):
    return SecurityTemplateWorkflowRequest("report.json", "Target.java", **values)


def test_request_defaults_and_publication_references(inputs, capsys):
    assert request().effective_export == "security-pocs/poc-verdict.json"
    assert request(result_export="-").effective_export is None
    remote = mcp_server.security_exploit("report.json", "Target.java")
    assert remote["request_satisfied"] and remote["claim"] == "NO_PROOF" and not remote["exploit_proven"]
    assert cli.dispatch(cli.build_parser().parse_args(["security-exploit", "report.json", "Target.java"]),
        cli.TerminalUI(), None, {}) == 0
    local = json.JSONDecoder().raw_decode(capsys.readouterr().out)[0]
    assert local["workflow_result"]["request"] == remote["workflow_result"]["request"]
    assert local["input_manifest"] == remote["input_manifest"]
    for result in (local, remote):
        generated = result["generated"][0]
        published = result["publication"]["artifacts"][generated["publication_key"]]
        assert generated["file"] == published["path"]
        assert generated["sha256"] == hashlib.sha256(Path(generated["file"]).read_bytes()).hexdigest()
        export = next(iter(result["result_export"]["artifacts"].values()))
        assert json.loads(Path(export["path"]).read_text())["generated"] == result["generated"]
        assert not generated["executed"] and generated["review_status"] == "unreviewed"


@pytest.mark.parametrize("cwe", ["125", "89", "22", "502", "190", "476", "78", "798", "79", "326", "732"])
def test_supported_java_templates_never_execute(inputs, cwe):
    (inputs / "report.json").write_text(json.dumps([{"cwe": "CWE-" + cwe}]))
    with patch("subprocess.run", side_effect=AssertionError("no execution")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no provider")):
        result = mcp_server.security_exploit("report.json", "Target.java", result_export="-")
    assert result["request_satisfied"] and len(result["generated"]) == 1
    assert "result_export" not in result and result["claim"] == "NO_PROOF"


@pytest.mark.parametrize("suffix", [".rs", ".c", ".h", ".cpp", ".cc"])
def test_native_bounds_templates_are_review_only(inputs, suffix):
    target = inputs / ("Target" + suffix)
    target.write_text("/* Synthetic source identity fixture, never compiled. */")
    (inputs / "report.json").write_text('[{"cwe":"CWE-125"},{"cwe":"CWE-89"}]')
    result = mcp_server.security_exploit("report.json", target.name)
    assert result["request_satisfied"] and len(result["generated"]) == 1
    assert result["unsupported_findings"][0]["index"] == 2
    assert not result["executed"] and result["claim"] == "NO_PROOF"


@pytest.mark.parametrize("body", ["not json", "{}", "[1]", '{"findings":{}}',
    '[{"cwe":1}]', '{"findings":[],"findings":[]}', '[{"score":NaN}]', '[]', '[{"cwe":"CWE-999"}]'])
def test_negative_report_export(inputs, body):
    (inputs / "report.json").write_text(body)
    result = mcp_server.security_exploit("report.json", "Target.java", result_export="negative.json")
    assert not result["request_satisfied"] and result["claim"] == "NO_PROOF" and result["generated"] == []
    saved = json.loads((inputs / "custom-output/negative.json").read_text())
    assert saved["status"] == result["status"] and not saved["request_satisfied"]


@pytest.mark.parametrize("kind", ["bytes", "files", "depth", "findings", "matching", "symlink", "fifo", "missing", "denied"])
def test_capture_limits_stop_before_generation(inputs, kind):
    limits = dict(SECURITY_TEMPLATE_BUDGET)
    if kind in {"bytes", "files", "depth", "findings", "matching"}:
        key = {"bytes": "max_input_bytes", "files": "max_input_files", "depth": "max_path_depth",
               "findings": "max_findings", "matching": "max_matching_bytes"}[kind]
        limits[key] = 0
    if kind in {"symlink", "fifo", "missing"}:
        (inputs / "Target.java").unlink()
        if kind == "symlink": (inputs / "Target.java").symlink_to(inputs / "report.json")
        if kind == "fifo": os.mkfifo(inputs / "Target.java")
    req = request(result_export="negative.json") if kind != "denied" else SecurityTemplateWorkflowRequest(
        "../outside.json", "Target.java", result_export="negative.json")
    context = WorkflowContext.for_cli(req.required_effects(), resource_budget=limits)
    with patch("pipeline.security_template_workflow._poc_for") as generator:
        result = run_security_template_workflow(req, context, output_root=inputs / "out",
            artifact_dir="pocs", export_key="negative.json")
    generator.assert_not_called()
    assert not result["request_satisfied"] and result["result_export"]["status"] == "COMMITTED"


@pytest.mark.parametrize("effects", [(), ("workspace_read",)])
def test_effect_denial_precedes_capture(inputs, effects):
    context = WorkflowContext.for_cli(effects, resource_budget=SECURITY_TEMPLATE_BUDGET)
    with patch("pipeline.security_template_workflow.capture") as capture, \
         patch("pipeline.security_template_workflow.publish_new_artifacts") as publish:
        result = run_security_template_workflow(request(), context, output_root=inputs,
            artifact_dir="pocs", export_key="result.json")
    capture.assert_not_called()
    publish.assert_not_called()
    assert not result["request_satisfied"]


@pytest.mark.parametrize("export", ["Target.java", "report.json", "pocs/OutOfBoundsPoC1.java"])
def test_cli_export_aliases_do_not_replace_inputs_or_templates(inputs, export, capsys):
    before = {p.name: p.read_bytes() for p in inputs.iterdir()}
    assert cli.dispatch(cli.build_parser().parse_args(["security-exploit", "report.json", "Target.java",
        "--out-dir", "pocs", "--json", export]), cli.TerminalUI(), None, {}) == 1
    capsys.readouterr()
    assert before == {p.name: p.read_bytes() for p in inputs.iterdir()}


def test_no_replace_publication_and_export_failure(inputs):
    result = mcp_server.security_exploit("report.json", "Target.java")
    template = Path(result["generated"][0]["file"])
    original = template.read_bytes()
    failed = mcp_server.security_exploit("report.json", "Target.java", result_export="collision.json")
    assert not failed["request_satisfied"] and failed["result_export"]["status"] == "COMMITTED"
    assert template.read_bytes() == original
    (inputs / "custom-output/existing.json").write_text("preserve")
    failed = mcp_server.security_exploit("report.json", "Target.java", "other", "existing.json")
    assert failed["status"] == "RESULT_EXPORT_FAILED" and failed["publication"]["status"] == "COMMITTED"
    assert (inputs / "custom-output/existing.json").read_text() == "preserve"
    assert Path(failed["generated"][0]["file"]).is_file()


def test_source_is_captured_once_and_lexical_matching_is_bounded(inputs):
    original = (inputs / "Target.java").read_bytes()
    generator = security_poc._poc_for
    def changed(finding, target, index, **kwargs):
        (inputs / "Target.java").write_text("changed")
        assert kwargs["source_text"] == original.decode()
        return generator(finding, target, index, **kwargs)
    with patch("pipeline.security_template_workflow._poc_for", side_effect=changed):
        result = mcp_server.security_exploit("report.json", "Target.java")
    assert result["input_manifest"][1]["sha256"] == hashlib.sha256(original).hexdigest()
    assert "Target service" in Path(result["generated"][0]["file"]).read_text()
    assert security_poc._template_method("public " + " " * 100000 + ";") == "get"
    assert security_poc._template_method("public Target() {} protected int read(int n) {}") == "read"


def test_real_security_template_transport():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("requires real MCP stdio")
    import anyio
    from scripts.mcp_acceptance_adapters import _security_template_observation
    observation = anyio.run(_security_template_observation)
    assert len(observation["semantic_results"]) == 29
    assert len(observation["cli_comparisons"]) == 27
    assert len(observation["artifact_validations"]) == 44
