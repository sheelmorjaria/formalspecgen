"""Strict TLC infrastructure tests; mock observations are not backend evidence."""
from dataclasses import asdict, replace
import hashlib
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from pipeline.execution import ExecutionObservation
from pipeline.isolated_tlc import TlcModelRequest, _capture_jar, run_isolated_tlc
from pipeline.mcp_policy import MCPPolicyViolation
from pipeline.workflow_contracts import WorkflowContext


TLA = """---- MODULE Counter ----
EXTENDS Naturals
VARIABLE x
Init == x = 0
Next == x' = IF x = 0 THEN 1 ELSE 0
TypeOK == x \\in 0..1
Spec == Init /\\ [][Next]_x
====
"""
CFG = "SPECIFICATION Spec\nINVARIANT TypeOK\n"
SUCCESS = "Model checking completed. No error has been found.\n"


def context(tmp_path, **budget):
    return WorkflowContext.for_cli(("external_execution",), workspace_root=tmp_path,
                                   resource_budget=budget)


def observed(request, *, output="TLC2 Version 2.19\n", exit_code=0, **changes):
    value = ExecutionObservation(
        status="COMPLETED" if exit_code == 0 else "TOOL_FAILED", exit_code=exit_code,
        output=output, requested_policy=asdict(request.policy),
        enforced_policy=asdict(request.policy), policy_compliance="ENFORCED",
        snapshot_manifest_sha256=request.snapshot.manifest_sha256,
        snapshot_files=request.snapshot.manifest, command=request.command,
        tool=request.tool)
    return replace(value, **changes)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    jar = tmp_path / "tlc.jar"
    jar.write_bytes(b"approved jar bytes")
    monkeypatch.setattr("pipeline.isolated_tlc.shutil.which", lambda _: "/usr/bin/java")
    monkeypatch.setattr("pipeline.isolated_tlc._java_configuration_paths", lambda _: ())
    return jar, TlcModelRequest("Counter", TLA, CFG)


def test_same_snapshot_binds_tool_model_config_and_both_observations(setup, tmp_path):
    jar, request = setup
    calls = []

    def execute(execution):
        calls.append(execution)
        assert execution.snapshot.validate()
        assert (execution.snapshot.root / "tool/tla2tools.jar").read_bytes() == b"approved jar bytes"
        assert (execution.snapshot.root / "Counter.tla").read_text() == TLA
        assert (execution.snapshot.root / "Counter.cfg").read_text() == CFG
        assert str(jar) not in execution.command
        jar.write_bytes(b"changed after capture")
        return observed(execution, output="TLC2 Version 2.19\n" if len(calls) == 1 else SUCCESS,
                        exit_code=1 if len(calls) == 1 else 0)

    result = run_isolated_tlc(request, context(tmp_path), tlc_jar=str(jar),
                              executor=Mock(execute=execute))
    assert result["status"] == "TLC_MODEL_CHECK_PASSED"
    assert result["model_check_passed"] and result["request_satisfied"]
    assert result["claim"] == "NO_PROOF"
    assert len(result["execution_observations"]) == 2
    assert result["version"] == "2.19"
    assert calls[0].snapshot == calls[1].snapshot
    assert calls[1].policy.max_output_bytes < calls[0].policy.max_output_bytes
    assert calls[1].policy.timeout_s < request.timeout_s
    assert not calls[0].snapshot.root.exists()
    manifests = {item["path"]: item for item in result["snapshot_manifest"]}
    assert manifests["Counter.cfg"]["sha256"] == hashlib.sha256(CFG.encode()).hexdigest()
    assert manifests["tool/tla2tools.jar"]["sha256"] == hashlib.sha256(b"approved jar bytes").hexdigest()


@pytest.mark.parametrize("stage,changes", [
    (0, {"exit_code": 2}), (0, {"output": "no version"}),
    (0, {"output": "TLC2 Version    \n"}),
    (0, {"policy_compliance": "NOT_ENFORCED"}),
    (0, {"status": "SANDBOX_UNAVAILABLE"}),
    (0, {"output_truncated": True}), (0, {"timed_out": True}),
    (1, {"output": "silent zero exit"}), (1, {"exit_code": 12}),
    (1, {"status": "MEMORY_LIMIT_EXCEEDED"}),
    (1, {"policy_compliance": "NOT_ENFORCED"}),
    (1, {"output_truncated": True}), (1, {"timed_out": True}),
])
def test_failure_never_erases_prior_observations(setup, tmp_path, stage, changes):
    jar, request = setup
    calls = []

    def execute(execution):
        index = len(calls)
        calls.append(execution)
        observation = observed(execution, output="TLC2 Version 2.19\n" if index == 0 else SUCCESS)
        return replace(observation, **changes) if index == stage else observation

    result = run_isolated_tlc(request, context(tmp_path), tlc_jar=str(jar),
                              executor=Mock(execute=execute))
    assert not result["model_check_passed"] and not result["request_satisfied"]
    assert result["claim"] == "NO_PROOF"
    assert len(result["execution_observations"]) == stage + 1
    if stage:
        assert result["execution_observations"][0]["status"] == "COMPLETED"


def test_permission_denied_before_tool_capture(setup, tmp_path, monkeypatch):
    jar, request = setup
    capture = Mock(side_effect=AssertionError("must not read tools"))
    monkeypatch.setattr("pipeline.isolated_tlc._capture_jar", capture)
    with pytest.raises(MCPPolicyViolation):
        run_isolated_tlc(request, WorkflowContext.for_cli((), workspace_root=tmp_path))
    capture.assert_not_called()


@pytest.mark.parametrize("budget", [
    {"max_input_bytes": 0}, {"max_input_bytes": len(TLA) + len(CFG) - 1},
    {"max_tool_bytes": 2}, {"max_execution_seconds": 0},
    {"max_output_bytes": 0}, {"max_memory_bytes": 0}, {"max_processes": 0},
    {"max_workspace_bytes": 0}, {"max_input_bytes": True},
])
def test_limits_stop_before_execution(setup, tmp_path, budget):
    jar, request = setup
    executor = Mock()
    result = run_isolated_tlc(request, context(tmp_path, **budget), tlc_jar=str(jar), executor=executor)
    assert not result["request_satisfied"]
    executor.execute.assert_not_called()


def test_utf8_byte_limit_not_character_count(setup, tmp_path):
    jar, request = setup
    executor = Mock()
    result = run_isolated_tlc(replace(request, tla="é", cfg="é"),
                              context(tmp_path, max_input_bytes=3),
                              tlc_jar=str(jar), executor=executor)
    assert not result["request_satisfied"]
    executor.execute.assert_not_called()


@pytest.mark.parametrize("kind", ["missing", "symlink", "fifo", "directory"])
def test_jar_must_be_bounded_regular_file(tmp_path, kind):
    path = tmp_path / "jar"
    if kind == "symlink":
        target = tmp_path / "target"
        target.write_bytes(b"jar")
        path.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    with pytest.raises((OSError, ValueError)):
        _capture_jar(path, 10)


def test_jar_exact_limit_and_overflow_probe(tmp_path, monkeypatch):
    jar = tmp_path / "jar"
    jar.write_bytes(b"1234")
    assert _capture_jar(jar, 4) == b"1234"
    original = os.fdopen
    requested = []

    class Recording:
        def __init__(self, fd, mode, **kwargs):
            assert kwargs == {"buffering": 0}
            self.stream = original(fd, mode, **kwargs)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.stream.close()
        def fileno(self):
            return self.stream.fileno()
        def read(self, size):
            requested.append(size)
            return self.stream.read(size)

    monkeypatch.setattr("pipeline.isolated_tlc.os.fdopen", Recording)
    with pytest.raises(ValueError, match="max_tool_bytes"):
        _capture_jar(jar, 2)
    assert requested == [3]


@pytest.mark.parametrize("values", [
    {"module_name": "../bad"}, {"module_name": "A" * 129}, {"module_name": None},
    {"timeout_s": 0}, {"timeout_s": True}, {"tla": b"text"},
])
def test_invalid_requests(values):
    with pytest.raises(ValueError):
        TlcModelRequest(**({"module_name": "Counter", "tla": TLA, "cfg": CFG} | values))


def test_missing_java_is_explicit(setup, tmp_path, monkeypatch):
    monkeypatch.setattr("pipeline.isolated_tlc.shutil.which", lambda _: None)
    result = run_isolated_tlc(setup[1], context(tmp_path))
    assert result["status"] == "TOOL_MISSING"
    assert not result["execution_observations"]


def test_late_executor_error_retains_probe(setup, tmp_path):
    jar, request = setup
    executor = Mock()
    count = 0

    def execute(execution):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("sandbox unavailable")
        return observed(execution)

    executor.execute.side_effect = execute
    result = run_isolated_tlc(request, context(tmp_path), tlc_jar=str(jar), executor=executor)
    assert not result["request_satisfied"]
    assert len(result["execution_observations"]) == 1


def test_cumulative_deadline_stops_second_stage(setup, tmp_path, monkeypatch):
    jar, request = setup
    monkeypatch.setattr("pipeline.isolated_tlc.time.monotonic", Mock(side_effect=[0, 1, 121]))
    executor = Mock(execute=lambda execution: observed(execution))
    result = run_isolated_tlc(request, context(tmp_path), tlc_jar=str(jar), executor=executor)
    assert result["status"] == "RESOURCE_BUDGET_EXHAUSTED"
    assert len(result["execution_observations"]) == 1


def test_cumulative_output_stops_second_stage(setup, tmp_path):
    jar, request = setup
    banner = "TLC2 Version 2.19\n"
    result = run_isolated_tlc(request, context(tmp_path, max_output_bytes=len(banner)),
                              tlc_jar=str(jar), executor=Mock(execute=observed))
    assert result["status"] == "RESOURCE_BUDGET_EXHAUSTED"
    assert len(result["execution_observations"]) == 1


def test_default_executor_fails_closed_without_sandbox(setup, tmp_path, monkeypatch):
    from pipeline.execution import StrictSandboxExecutor

    jar, request = setup
    executor = StrictSandboxExecutor(sandbox_binary="/missing/bwrap", prlimit_binary="/missing/prlimit")
    monkeypatch.setattr("pipeline.isolated_tlc.StrictSandboxExecutor", lambda: executor)
    result = run_isolated_tlc(request, context(tmp_path), tlc_jar=str(jar))
    assert result["status"] == "TLC_EXECUTION_FAILED"
    assert len(result["execution_observations"]) == 1
    assert result["execution_observations"][0]["policy_compliance"] == "NOT_ENFORCED"
    assert not result["request_satisfied"]


def test_resource_ceilings_and_lower_grants(setup, tmp_path):
    jar, request = setup
    calls = []

    def execute(execution):
        calls.append(execution)
        return observed(execution, output="TLC2 Version 2.19\n" if len(calls) == 1 else SUCCESS)

    result = run_isolated_tlc(request, context(
        tmp_path, max_memory_bytes=100 * 1024**3, max_processes=12,
        max_execution_seconds=20, max_workspace_bytes=4096),
        tlc_jar=str(jar), executor=Mock(execute=execute))
    assert result["request_satisfied"]
    for call in calls:
        assert call.policy.max_memory_bytes == 2 * 1024**3
        assert call.policy.max_processes == 12
        assert call.policy.timeout_s <= 20
        assert call.policy.max_workspace_bytes == 4096


def test_cleanup_failure_cannot_return_satisfied_success(setup, tmp_path, monkeypatch):
    jar, request = setup

    class CleanupFailure(tempfile.TemporaryDirectory):
        def __exit__(self, *args):
            super().__exit__(*args)
            raise OSError("private snapshot cleanup failed")

    monkeypatch.setattr("pipeline.isolated_tlc.tempfile.TemporaryDirectory", CleanupFailure)
    executor = Mock(execute=lambda execution: observed(
        execution, output="TLC2 Version 2.19\n" if execution.tool == "tlc-provenance" else SUCCESS))
    result = run_isolated_tlc(request, context(tmp_path), tlc_jar=str(jar), executor=executor)
    assert result["status"] == "TLC_PREPARATION_OR_EXECUTION_FAILED"
    assert not result["request_satisfied"] and not result["model_check_passed"]
    assert len(result["execution_observations"]) == 2
