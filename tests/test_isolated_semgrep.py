"""SAST adapter unit tests; real isolation coverage lives in sandbox acceptance."""
from dataclasses import asdict
import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from pipeline.execution import ExecutionObservation
from pipeline.isolated_semgrep import SemgrepScanRequest, _local_rules, run_isolated_semgrep
from pipeline.mcp_policy import MCPPolicyViolation
from pipeline.workflow_contracts import WorkflowContext


def context(root, effects=("workspace_read", "external_execution"), **limits):
    return WorkflowContext.for_cli(effects, workspace_root=root, resource_budget=limits)


def report(findings=False):
    return {"version": "1.138.0", "paths": {"scanned": ["/input/source/S.java"]}, "errors": [], "skipped_rules": [],
            "results": [{"check_id": "CWE-327-WEAK-CRYPTO", "path": "/input/source/S.java",
                         "start": {"line": 1}, "extra": {"severity": "WARNING", "message": "weak crypto"}}]
            if findings else []}


def observation(request, data=None, **changes):
    values = dict(status="COMPLETED", exit_code=0, output=json.dumps(report() if data is None else data),
                  requested_policy=asdict(request.policy), enforced_policy=asdict(request.policy),
                  policy_compliance="ENFORCED", snapshot_manifest_sha256=request.snapshot.manifest_sha256,
                  snapshot_files=request.snapshot.manifest, command=request.command, tool=request.tool)
    return ExecutionObservation(**(values | changes))


@pytest.fixture
def setup(tmp_path, monkeypatch):
    source, rules = tmp_path / "S.java", tmp_path / "rules.yml"
    source.write_text("class S {}\n")
    rules.write_text("rules: []\n")
    monkeypatch.setattr("pipeline.isolated_semgrep.shutil.which", lambda _: "/usr/bin/semgrep")
    return source, rules


@pytest.mark.parametrize("findings,exit_code", [(False, 0), (True, 0), (True, 1)])
def test_captured_inputs_output_binding_and_distinct_outcomes(setup, tmp_path, findings, exit_code):
    source, rules = setup
    source_bytes, rule_bytes = source.read_bytes(), rules.read_bytes()
    calls = []
    def execute(request):
        calls.append(request)
        source.write_text("changed workspace source")
        rules.write_text("changed configured rules")
        assert (request.snapshot.root / "source/S.java").read_bytes() == source_bytes
        assert (request.snapshot.root / "rules/rules.yml").read_bytes() == rule_bytes
        assert str(source) not in request.command and str(rules) not in request.command
        assert "--metrics=off" in request.command and "--disable-version-check" in request.command
        assert "--disable-nosem" in request.command and "--no-git-ignore" in request.command
        assert not request.environment
        assert request.policy.network == "denied"
        assert all(str(path) not in {"/etc", "/etc/ssl", "/etc/ssl/private"}
                   for path in request.readonly_paths)
        return observation(request, report(findings), exit_code=exit_code,
                           status="TOOL_FAILED" if exit_code else "COMPLETED")
    result = run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path),
                                  rules_path=rules, executor=Mock(execute=execute))
    assert result["status"] == ("SAST_FINDINGS" if findings else "SAST_CLEAN")
    assert result["request_satisfied"] and result["scan_complete"]
    assert result["claim"] == "NO_PROOF"
    assert result["source"] == "S.java"
    assert result["snapshot_manifest"][0]["sha256"] == hashlib.sha256(rule_bytes).hexdigest()
    assert result["snapshot_manifest"][1]["sha256"] == hashlib.sha256(source_bytes).hexdigest()
    assert len(result["execution_observations"]) == 1
    assert not calls[0].snapshot.root.exists()
    if findings:
        assert result["findings"][0]["source"] == "S.java"
        assert result["findings"][0]["cwe"] == "CWE-327"


@pytest.mark.parametrize("changes", [
    {"status": "TIMEOUT"}, {"policy_compliance": "NOT_ENFORCED"},
    {"timed_out": True}, {"output_truncated": True}, {"status": "MEMORY_LIMIT_EXCEEDED"},
])
def test_execution_failures_cannot_be_clean(setup, tmp_path, changes):
    source, rules = setup
    result = run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path), rules_path=rules,
        executor=Mock(execute=lambda request: observation(request, **changes)))
    assert result["status"] == "SAST_EXECUTION_FAILED"
    assert not result["request_satisfied"] and not result["scan_complete"]
    assert len(result["execution_observations"]) == 1


@pytest.mark.parametrize("data,exit_code", [
    (report() | {"errors": [{"type": "ParseError"}]}, 0),
    (report() | {"skipped_rules": [{"rule_id": "unsupported-rule"}]}, 0),
    (report() | {"paths": {"scanned": []}}, 0),
    (report() | {"paths": {"scanned": ["/other.java"]}}, 0),
    (report() | {"paths": {"scanned": ["/input/source/S.java"], "skipped": [{}]}}, 0),
    (report(), 1), (report(), 2), (report(True), 2),
])
def test_errors_skips_unscanned_and_error_exits_are_incomplete(setup, tmp_path, data, exit_code):
    result = run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path), rules_path=setup[1],
        executor=Mock(execute=lambda request: observation(request, data, exit_code=exit_code)))
    assert result["status"] == "SAST_INCOMPLETE"
    assert not result["request_satisfied"] and not result["scan_complete"]
    assert len(result["findings"]) == len(data["results"])


@pytest.mark.parametrize("output", [
    "not JSON", "[]", '{}', '{"results":[],"results":[]}', '{"version":NaN}',
    json.dumps(report() | {"results": [None]}), json.dumps(report() | {"errors": "error"}),
    json.dumps(report() | {"paths": []}), json.dumps(report() | {"version": ""}),
    json.dumps(report() | {"skipped_rules": None}),
    json.dumps(report() | {"paths": {"scanned": None}}),
    json.dumps(report() | {"results": [{"path": "/wrong.java"}]}),
    json.dumps(report() | {"results": [{"path": "/input/source/S.java", "check_id": "x", "start": {"line": True}, "extra": {}}]}),
])
def test_malformed_output_retains_observation(setup, tmp_path, output):
    result = run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path), rules_path=setup[1],
        executor=Mock(execute=lambda request: observation(request, output=output)))
    assert result["status"] == "SAST_INVALID_OUTPUT"
    assert not result["request_satisfied"]
    assert result["execution_observations"][0]["output"] == output


@pytest.mark.parametrize("effects", [(), ("workspace_read",), ("external_execution",)])
def test_denied_effects_stop_before_capture(setup, tmp_path, monkeypatch, effects):
    capture = Mock(side_effect=AssertionError("must not read"))
    monkeypatch.setattr("pipeline.isolated_semgrep.capture", capture)
    with pytest.raises(MCPPolicyViolation):
        run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path, effects), rules_path=setup[1])
    capture.assert_not_called()


@pytest.mark.parametrize("limits", [
    {"max_input_bytes": 1}, {"max_input_bytes": 15}, {"max_rule_bytes": 1},
    {"max_input_files": 1}, {"max_output_bytes": 0}, {"max_memory_bytes": True},
])
def test_input_and_execution_limits_stop_dispatch(setup, tmp_path, limits):
    executor = Mock()
    result = run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path, **limits),
                                  rules_path=setup[1], executor=executor)
    assert not result["request_satisfied"]
    executor.execute.assert_not_called()


@pytest.mark.parametrize("source", ["../S.java", "/etc/passwd", "missing.java", "alias.java"])
def test_out_of_scope_missing_and_symlink_sources(setup, tmp_path, source):
    (tmp_path / "alias.java").symlink_to(setup[0])
    executor = Mock()
    result = run_isolated_semgrep(SemgrepScanRequest(source), context(tmp_path), rules_path=setup[1], executor=executor)
    assert not result["request_satisfied"]
    executor.execute.assert_not_called()


@pytest.mark.parametrize("kind", ["missing", "symlink", "fifo", "directory", "oversized"])
def test_only_bounded_local_regular_rules(tmp_path, kind):
    path = tmp_path / "rules"
    if kind == "symlink":
        path.symlink_to(tmp_path / "target")
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    elif kind == "oversized":
        path.write_bytes(b"too long")
    with pytest.raises((ValueError, OSError)):
        _local_rules(path, 2)


def test_no_registry_fallback_for_missing_local_rules(setup, tmp_path):
    executor = Mock()
    result = run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path),
                                  rules_path=tmp_path / "p/java", executor=executor)
    assert not result["request_satisfied"]
    executor.execute.assert_not_called()


def test_missing_executable_and_unsupported_source_are_distinct(setup, tmp_path, monkeypatch):
    monkeypatch.setattr("pipeline.isolated_semgrep.shutil.which", lambda _: None)
    assert run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path), rules_path=setup[1])["status"] == "TOOL_MISSING"
    assert run_isolated_semgrep(SemgrepScanRequest("S.txt"), context(tmp_path))["status"] == "SAST_UNSUPPORTED"


@pytest.mark.parametrize("source,timeout", [(None, 1), ("", 1), ("x\0", 1), ("x", True), ("x", 0)])
def test_invalid_typed_requests(source, timeout):
    with pytest.raises(ValueError):
        SemgrepScanRequest(source, timeout)


def test_unknown_rules_remain_explicit_and_findings_are_bounded(setup, tmp_path):
    data = report(True)
    data["results"][0]["check_id"] = "operator-custom-rule"
    executor = Mock(execute=lambda request: observation(request, data))
    result = run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path), rules_path=setup[1], executor=executor)
    assert result["findings"][0]["unmapped_rule_id"] and result["findings"][0]["cwe"] is None
    data["results"] *= 2
    result = run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path, max_findings=1),
                                  rules_path=setup[1], executor=executor)
    assert result["status"] == "SAST_INVALID_OUTPUT"
    assert not result["request_satisfied"]


def test_default_config_is_local_and_limits_only_attenuate(setup, tmp_path, monkeypatch):
    monkeypatch.setattr("pipeline.isolated_semgrep.config.resource_path", lambda *parts: setup[1])
    calls = []
    def execute(request):
        calls.append(request)
        return observation(request)
    result = run_isolated_semgrep(SemgrepScanRequest("S.java", timeout_s=9999),
        context(tmp_path, max_memory_bytes=100 * 1024**3, max_processes=2, max_execution_seconds=5),
        executor=Mock(execute=execute))
    assert result["request_satisfied"]
    assert calls[0].policy.max_memory_bytes == 2 * 1024**3
    assert calls[0].policy.max_processes == 2 and calls[0].policy.timeout_s == 5


def test_cleanup_failure_retains_observation_but_revokes_success(setup, tmp_path, monkeypatch):
    class CleanupFailure(tempfile.TemporaryDirectory):
        def __exit__(self, *args):
            super().__exit__(*args)
            raise OSError("snapshot cleanup failed")
    monkeypatch.setattr("pipeline.isolated_semgrep.tempfile.TemporaryDirectory", CleanupFailure)
    result = run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path), rules_path=setup[1],
                                  executor=Mock(execute=observation))
    assert result["status"] == "SAST_PREPARATION_OR_EXECUTION_FAILED"
    assert not result["request_satisfied"] and not result["scan_complete"]
    assert len(result["execution_observations"]) == 1


def test_production_executor_has_no_unrestricted_fallback(setup, tmp_path, monkeypatch):
    from pipeline.execution import StrictSandboxExecutor
    executor = StrictSandboxExecutor(sandbox_binary="/missing/bwrap", prlimit_binary="/missing/prlimit")
    monkeypatch.setattr("pipeline.isolated_semgrep.StrictSandboxExecutor", lambda: executor)
    result = run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path), rules_path=setup[1])
    assert result["status"] == "SAST_EXECUTION_FAILED"
    assert not result["request_satisfied"]
    assert result["execution_observations"][0]["policy_compliance"] == "NOT_ENFORCED"


@pytest.mark.parametrize("available", [True, False])
def test_only_public_ca_bundle_is_added_to_runtime_mounts(setup, tmp_path, monkeypatch, available):
    bundle = Path("/etc/ssl/certs/ca-certificates.crt")
    original = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda path: available if path == bundle else original(path))
    calls = []
    def execute(request):
        calls.append(request)
        return observation(request)
    result = run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path),
                                  rules_path=setup[1], executor=Mock(execute=execute))
    assert result["request_satisfied"]
    assert calls[0].readonly_paths == ((Path("/usr"), bundle) if available else (Path("/usr"),))
    assert calls[0].policy.network == "denied"


@pytest.mark.parametrize("location", ["bin/semgrep", "semgrep"])
def test_operator_runtime_cannot_mount_the_workspace(setup, tmp_path, monkeypatch, location):
    monkeypatch.setattr("pipeline.isolated_semgrep.shutil.which", lambda _: str(tmp_path / location))
    executor = Mock()
    result = run_isolated_semgrep(SemgrepScanRequest("S.java"), context(tmp_path),
                                  rules_path=setup[1], executor=executor)
    assert not result["request_satisfied"]
    assert "runtime mount" in result["message"]
    executor.execute.assert_not_called()


def test_ci_requires_real_scans_and_retains_observations():
    import yaml

    workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/tests.yml").read_text())
    job = workflow["jobs"]["sandbox-acceptance"]
    assert all("runner." not in str(value) for value in job.get("env", {}).values())
    steps = job["steps"]
    install = next(step for step in steps if step.get("name") == "Install isolated Semgrep acceptance toolchain")
    assert '/usr/bin/python3 -m venv "$RUNNER_TEMP/formalspecgen-semgrep"' in install["run"]
    assert '"semgrep==1.138.0"' in install["run"]
    assert any('SEMGREP_BIN=$RUNNER_TEMP/formalspecgen-semgrep/bin/semgrep' in step.get("run", "")
               for step in steps)
    scan = next(step for step in steps if step.get("name") == "Run mandatory real sandbox acceptance")
    assert scan["env"]["FORMALSPECGEN_REQUIRE_SANDBOX_ACCEPTANCE"] == "1"
    assert scan["env"]["FORMALSPECGEN_SEMGREP_ACCEPTANCE_DIR"] == "${{ runner.temp }}/semgrep-acceptance"
    assert "tests/test_sandbox_acceptance.py" in scan["run"]
    assert not scan.get("continue-on-error", False)
    upload = next(step for step in steps if step.get("name") == "Upload actual Semgrep execution observations")
    assert upload["if"] == "always()"
    assert upload["with"]["name"] == "semgrep-execution-${{ github.sha }}"
    assert upload["with"]["path"] == "${{ runner.temp }}/semgrep-acceptance/*.json"
    assert upload["with"]["if-no-files-found"] == "error"
    assert steps.index(install) < steps.index(scan) < steps.index(upload)
