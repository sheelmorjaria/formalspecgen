"""Assessment unit tests use synthetic judge observations, not formal proofs."""
from dataclasses import asdict
import os
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pipeline.execution import ExecutionObservation
from pipeline.lifecycle import RunLedger
from pipeline.security_workflow import SECURITY_BUDGET, SecurityAssessmentWorkflowRequest, run_security_assessment
from pipeline.workflow_contracts import WorkflowContext


@pytest.fixture
def setup(tmp_path, monkeypatch):
    source = tmp_path / "S.java"
    source.write_text("class S { //@ ensures \\result == 1;\n public int one() { return 1; } }\n")
    monkeypatch.setattr("pipeline.verify._resolved_openjml", lambda: Path("/usr/bin/openjml"))
    monkeypatch.setattr("pipeline.isolated_semgrep.shutil.which", lambda _: "/usr/bin/semgrep")
    return source


def judge(request, *, formal_exit=0, findings=False, **changes):
    output = "" if request.tool == "openjml" else json.dumps({
        "version": "fixture", "paths": {"scanned": ["/input/source/S.java"]}, "errors": [], "skipped_rules": [],
        "results": [{"check_id": "CWE-327-WEAK-CRYPTO", "path": "/input/source/S.java", "start": {"line": 1},
                     "extra": {"severity": "WARNING", "message": "weak crypto"}}] if findings else []})
    return ExecutionObservation(**(dict(status="COMPLETED", exit_code=formal_exit if request.tool == "openjml" else 0,
        output=output, requested_policy=asdict(request.policy), enforced_policy=asdict(request.policy),
        policy_compliance="ENFORCED", snapshot_manifest_sha256=request.snapshot.manifest_sha256,
        snapshot_files=request.snapshot.manifest, command=request.command, tool=request.tool) | changes))


def run(source, *, sast=True, export="result.json", executor=None, limits=None, effects=None):
    request = SecurityAssessmentWorkflowRequest(str(source), sast, export)
    context = WorkflowContext.for_cli(effects or request.required_effects(), workspace_root=source.parent,
        output_root=source.parent / "out", resource_budget=SECURITY_BUDGET | (limits or {}))
    return run_security_assessment(request, context, executor=executor or Mock(execute=judge))


@pytest.mark.parametrize("sast,findings,formal_exit,status,satisfied", [
    (True, False, 0, "CHECKS_PASSED", True),
    (False, False, 0, "FORMALLY_VERIFIED_SAST_SKIPPED", True),
    (True, True, 0, "SECURITY_FINDINGS", False),
    (True, False, 1, "FORMAL_VERIFICATION_FAILED", False),
    (True, False, 6, "FORMAL_VERIFICATION_FAILED", False),
])
def test_stages_evidence_and_negative_exports(setup, sast, findings, formal_exit, status, satisfied):
    result = run(setup, sast=sast, executor=Mock(execute=lambda request: judge(request,
        findings=findings, formal_exit=formal_exit)))
    assert result["status"] == status, result
    assert result["claim"] == "NO_PROOF" and result["request_satisfied"] is satisfied
    assert len(result["execution_observations"]) == (2 if sast else 1)
    assert result["sast"]["source"] == setup.name
    receipt = result["publication"]["receipt"]
    path = Path(receipt["manifest_path"])
    assert hashlib.sha256(path.read_bytes()).hexdigest() == receipt["manifest_sha256"]
    manifest = json.loads(path.read_text())
    assert not RunLedger._validate_artifacts(path.parent, manifest["artifacts"])
    assert manifest["terminal"]["request_satisfied"] is satisfied
    assert manifest["terminal"]["claim"] == "NO_PROOF"
    assert manifest["terminal"]["inputs"]["sources"] == result["inputs"]
    assert json.loads((setup.parent / "out/result.json").read_text())["status"] == status
    for item in result["publication"]["artifacts"].values():
        assert hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest() == item["sha256"]


@pytest.mark.parametrize("change", ["inplace", "replace"])
def test_both_judges_use_one_capture(setup, change):
    original = setup.read_bytes()
    calls = []
    def execute(request):
        calls.append(request.tool)
        if change == "replace":
            setup.unlink()
        setup.write_text("class Changed {}")
        key = "S.java" if request.tool == "openjml" else "source/S.java"
        assert (request.snapshot.root / key).read_bytes() == original
        return judge(request)
    result = run(setup, executor=Mock(execute=execute))
    assert result["request_satisfied"] and calls == ["openjml", "semgrep"]
    assert result["inputs"][0]["sha256"] == hashlib.sha256(original).hexdigest()


@pytest.mark.parametrize("changes", [{"policy_compliance": "NOT_ENFORCED"}, {"timed_out": True},
    {"output_truncated": True}, {"status": "MEMORY_LIMIT_EXCEEDED"}, {"output": "not json"},
    {"snapshot_files": ()}])
def test_sast_failure_retains_formal_evidence(setup, changes):
    result = run(setup, executor=Mock(execute=lambda request: judge(request,
        **(changes if request.tool == "semgrep" else {}))))
    assert result["status"] == "SECURITY_ASSESSMENT_INCOMPLETE"
    assert result["formal_verification"]["request_satisfied"]
    assert not result["request_satisfied"] and result["claim"] == "NO_PROOF"
    assert len(result["execution_observations"]) == 2
    assert result["result_export"]["status"] == "COMMITTED"


@pytest.mark.parametrize("kind", ["missing", "unsupported", "oversized", "symlink", "denied"])
def test_capture_stops_before_execution_with_negative_export(setup, kind):
    limits = {}
    if kind == "missing":
        setup.unlink()
    if kind == "unsupported":
        setup = setup.with_suffix(".rs")
        setup.write_text("fn main() {}")
    if kind == "oversized":
        limits = {"max_input_bytes": 1}
    if kind == "symlink":
        real = setup.with_suffix(".real")
        setup.rename(real)
        setup.symlink_to(real)
    if kind == "denied":
        setup = setup.parent / ".." / setup.parent.name / setup.name
    executor = Mock(execute=Mock(side_effect=judge))
    result = run(setup, executor=executor, limits=limits)
    assert not result["request_satisfied"]
    executor.execute.assert_not_called()
    assert result["result_export"]["status"] == "COMMITTED"


@pytest.mark.parametrize("effect", ["workspace_read", "external_execution", "workspace_write_new", "evidence_publication"])
def test_missing_effect_stops_dispatch(setup, effect):
    executor = Mock(execute=Mock(side_effect=judge))
    effects = tuple(item for item in SecurityAssessmentWorkflowRequest(str(setup)).required_effects() if item != effect)
    result = run(setup, executor=executor, effects=effects)
    assert not result["request_satisfied"]
    executor.execute.assert_not_called()


def test_export_collision_preserves_existing_bytes(setup):
    out = setup.parent / "out"
    out.mkdir()
    (out / "result.json").write_text("existing")
    result = run(setup)
    assert result["status"] == "RESULT_EXPORT_FAILED" and not result["request_satisfied"]
    assert (out / "result.json").read_text() == "existing"
    assert result["publication"]["status"] == "COMMITTED"


def test_evidence_failure_is_not_success_and_exports(setup, monkeypatch):
    monkeypatch.setattr("pipeline.security_workflow.publish_multistage_evidence", Mock(side_effect=OSError("unavailable")))
    result = run(setup)
    assert result["status"] == "EVIDENCE_PUBLICATION_FAILED" and result["claim"] == "NO_PROOF"
    assert not result["request_satisfied"] and result["formal_verification"]["request_satisfied"]
    assert result["result_export"]["status"] == "COMMITTED"


def test_late_stage_exception_keeps_observations(setup, monkeypatch):
    monkeypatch.setattr("pipeline.security_workflow.run_isolated_semgrep", Mock(side_effect=RuntimeError("failed")))
    result = run(setup)
    assert not result["request_satisfied"] and len(result["execution_observations"]) == 1
    assert result["formal_verification"]["request_satisfied"]


def test_export_alias_rejected_before_execution(setup):
    request = SecurityAssessmentWorkflowRequest(str(setup), True, setup.name)
    context = WorkflowContext.for_cli(request.required_effects(), workspace_root=setup.parent, output_root=setup.parent)
    executor = Mock(execute=Mock(side_effect=judge))
    before = setup.read_bytes()
    result = run_security_assessment(request, context, executor=executor)
    assert result["code"] == "OUTPUT_SCOPE_VIOLATION" and setup.read_bytes() == before
    executor.execute.assert_not_called()


def test_aggregate_execution_caps(setup):
    allowances = []
    def execute(request):
        allowances.append(request.policy)
        assert request.policy.max_memory_bytes == 1024
        return judge(request)
    result = run(setup, executor=Mock(execute=execute), limits={"max_memory_bytes": 1024, "max_execution_seconds": 10})
    assert result["request_satisfied"]
    assert 0 < allowances[1].timeout_s <= allowances[0].timeout_s <= 10


def test_unavailable_formal_tool_is_incomplete_not_security_finding(setup, monkeypatch):
    monkeypatch.setattr("pipeline.verify._resolved_openjml", lambda: None)
    result = run(setup)
    assert result["status"] == "SECURITY_ASSESSMENT_INCOMPLETE"
    assert result["formal_verification"]["status"] == "TOOL_MISSING"
    assert not result["request_satisfied"] and result["result_export"]["status"] == "COMMITTED"


def test_unavailable_sast_retains_formal_claim_and_negative_export(setup, monkeypatch):
    monkeypatch.setattr("pipeline.isolated_semgrep.shutil.which", lambda _: None)
    result = run(setup)
    assert result["status"] == "SECURITY_ASSESSMENT_INCOMPLETE" and result["sast"]["status"] == "TOOL_MISSING"
    assert result["formal_verification"]["claim"] == "DEDUCTIVE_PROOF"
    assert result["claim"] == "NO_PROOF" and result["result_export"]["status"] == "COMMITTED"


@pytest.mark.parametrize("limits", [{"max_execution_seconds": 0}, {"max_input_bytes": 0}, {"max_result_bytes": 1}])
def test_resource_budget_exhaustion_fails_closed(setup, limits):
    result = run(setup, limits=limits)
    assert not result["request_satisfied"] and result["claim"] == "NO_PROOF"


def test_output_budget_is_consumed_not_reset_per_stage(setup):
    calls = []
    def execute(request):
        calls.append(request)
        return judge(request, output=" " * 50) if request.tool == "openjml" else judge(request)
    run(setup, executor=Mock(execute=execute), limits={"max_output_bytes": 50})
    assert [item.tool for item in calls] == ["openjml"]


def test_captured_input_change_fails_before_second_stage(setup):
    # A faulty trusted adapter mutates only this run's private captured input.
    from unittest.mock import patch
    from pipeline.security_workflow import run_verification as actual
    def mutate(request, context, **kwargs):
        result = actual(request, context, **kwargs)
        path = Path(request.source)
        path.chmod(0o600)
        path.write_text("changed")
        return result
    executor = Mock(execute=Mock(side_effect=judge))
    with patch("pipeline.security_workflow.run_verification", side_effect=mutate):
        result = run(setup, executor=executor)
    assert not result["request_satisfied"] and executor.execute.call_count == 1
    assert result["formal_verification"]["request_satisfied"]


@pytest.mark.parametrize("kwargs", [{"source": ""}, {"source": "S.java", "run_sast": "false"},
    {"source": "S.java", "result_export": ""}])
def test_request_validation(kwargs):
    with pytest.raises(ValueError):
        SecurityAssessmentWorkflowRequest(**kwargs)


def test_real_security_assessment_transport():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("requires provisioned OpenJML, Semgrep and delegated sandbox")
    from scripts.mcp_acceptance_adapters import collect_transport_observation
    result = collect_transport_observation("assess-security")
    assert len(result["semantic_results"]) == 12
    assert len(result["cli_comparisons"]) == 11
    assert result["artifact_validations"]


@pytest.mark.parametrize("sast,export", [(True, "verdict.json"), (False, "verdict.json"),
    (True, "results/verdict.json"), (False, None)])
def test_cli_mcp_request_and_result_equivalence(setup, monkeypatch, sast, export):
    import io
    import mcp_server
    from rich.console import Console
    from pipeline import cli
    monkeypatch.chdir(setup.parent)
    monkeypatch.setenv("FORMALSPECGEN_MCP_OUTPUT_ROOT", str(setup.parent / "remote"))
    if export == "results/verdict.json":
        nested = setup.parent / "src"
        nested.mkdir()
        setup = setup.rename(nested / setup.name)
    monkeypatch.setattr("pipeline.security_workflow.StrictSandboxExecutor", lambda: Mock(execute=judge))
    remote = mcp_server.assess_security(str(setup), sast, export)
    rendered = []
    monkeypatch.setattr(cli, "_write_json", lambda value, *_: rendered.append(value))
    ui = cli.TerminalUI(Console(file=io.StringIO()), lambda _: "")
    assert cli.command_assess_security(SimpleNamespace(source=str(setup), no_sast=not sast,
        json=export or "-"), ui) == 0
    local = rendered[0]
    assert local["workflow_result"]["request"] == remote["workflow_result"]["request"]
    for field in ("status", "claim", "request_satisfied", "inputs", "claim_limits", "formal_findings"):
        assert local[field] == remote[field]
    assert local["sast"]["status"] == remote["sast"]["status"]


def test_real_fail_closed_transport():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("requires real MCP stdio")
    import anyio
    import tempfile
    from scripts.mcp_acceptance_adapters import _call_tool
    async def check():
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            calls = [{"source": "Missing.java", "result_export": "missing.json"},
                     {"source": "../denied.java", "result_export": "denied.json"}]
            _, tools, schema, results = await _call_tool(workspace, "assess_security", calls)
            assert "result_export" in schema["properties"] and "run_sast" in schema["properties"]
            assert "assess_security" in {tool.name for tool in tools.tools}
            for result in results:
                assert not result["request_satisfied"] and result["claim"] == "NO_PROOF"
                assert not result["execution_observations"]
                assert result["publication"]["status"] == "COMMITTED"
                assert result["result_export"]["status"] == "COMMITTED"
    anyio.run(check)
