"""Strict execution policy, snapshot integrity, and bounded process collection."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from pipeline.execution import (
    ExecutionPolicy, ExecutionRequest, SourceSnapshot, StrictSandboxExecutor,
)


def _request(tmp_path, *, policy=None, environment=None):
    snapshot = SourceSnapshot.create(tmp_path / "snapshot", {"main.c": "int main(void){}\n"})
    return ExecutionRequest(
        tool="cc", command=("/usr/bin/cc", "/input/main.c", "-o", "/work/main"),
        snapshot=snapshot, workspace=tmp_path / "workspace",
        policy=policy or ExecutionPolicy(), environment=environment or {})


def test_sandbox_unavailable_never_falls_back_to_process_execution(tmp_path):
    popen = Mock()
    observation = StrictSandboxExecutor(
        sandbox_binary="", prlimit_binary="", popen_factory=popen).execute(
            _request(tmp_path))
    assert observation.status == "SANDBOX_UNAVAILABLE"
    assert observation.policy_compliance == "NOT_ENFORCED"
    popen.assert_not_called()


def test_environment_is_allowlisted_and_secret_keys_are_rejected(tmp_path):
    observation = StrictSandboxExecutor(
        sandbox_binary="", prlimit_binary="").execute(
            _request(tmp_path, environment={"AWS_SECRET_ACCESS_KEY": "sentinel"}))
    assert observation.status == "POLICY_INVALID"
    assert "AWS_SECRET_ACCESS_KEY" in observation.message
    assert "sentinel" not in observation.message


def test_sandbox_command_denies_network_and_exposes_only_snapshot_and_workspace(tmp_path):
    request = _request(tmp_path, environment={"SOURCE_DATE_EPOCH": "0"})
    request = ExecutionRequest(**{
        **request.__dict__, "readonly_paths": (tmp_path.resolve(),)})
    executor = StrictSandboxExecutor(sandbox_binary="/usr/bin/bwrap",
                                     prlimit_binary="/usr/bin/prlimit")
    command = executor._sandbox_command(request, request.command)
    assert "--unshare-all" in command and "--clearenv" in command
    assert [str(request.snapshot.root), "/input"] == command[
        command.index(str(request.snapshot.root)):command.index(str(request.snapshot.root)) + 2]
    assert [str(request.workspace), "/work"] == command[
        command.index(str(request.workspace)):command.index(str(request.workspace)) + 2]
    assert os.environ.get("SSH_AUTH_SOCK", "not-present") not in command
    assert [str(tmp_path.resolve()), str(tmp_path.resolve())] == command[
        command.index(str(tmp_path.resolve())):command.index(str(tmp_path.resolve())) + 2]


def test_snapshot_mutation_is_detected_before_sandbox_probe(tmp_path):
    request = _request(tmp_path)
    source = request.snapshot.root / "main.c"
    source.chmod(0o644)
    source.write_text("int main(void){return 1;}\n", encoding="utf-8")
    probe = Mock()
    observation = StrictSandboxExecutor(
        sandbox_binary="/usr/bin/bwrap", prlimit_binary="/usr/bin/prlimit",
        probe_runner=probe).execute(request)
    assert observation.status == "SNAPSHOT_INTEGRITY_FAILED"
    probe.assert_not_called()


def test_snapshot_rejects_escaping_paths_and_missing_files(tmp_path):
    with pytest.raises(ValueError, match="relative and contained"):
        SourceSnapshot.create(tmp_path / "bad", {"../secret": "x"})
    snapshot = SourceSnapshot.create(tmp_path / "good", {"nested/main.c": b"x"})
    (snapshot.root / "nested/main.c").unlink()
    assert not snapshot.validate()


@pytest.mark.parametrize(("request_change", "message"), [
    ({"policy": ExecutionPolicy(network="allowed")}, "network=denied"),
    ({"policy": ExecutionPolicy(profile="unknown")}, "unsupported execution profile"),
    ({"command": ()}, "command is empty"),
    ({"policy": ExecutionPolicy(timeout_s=0)}, "limits must be positive"),
    ({"workspace": Path("/")}, "sibling disposable directory"),
    ({"readonly_paths": (Path("relative"),)}, "existing absolute path"),
    ({"readonly_paths": (Path.home().resolve(),)}, "too broad"),
])
def test_invalid_execution_profiles_fail_closed(tmp_path, request_change, message):
    request = _request(tmp_path)
    values = {**request.__dict__, **request_change}
    observation = StrictSandboxExecutor(
        sandbox_binary="bwrap", prlimit_binary="prlimit").execute(
            ExecutionRequest(**values))
    assert observation.status == "POLICY_INVALID"
    assert message in observation.message


def test_probe_failures_and_success_dispatch(tmp_path):
    request = _request(tmp_path)
    for outcome, expected in [
        (OSError("denied"), "denied"),
        (SimpleNamespace(returncode=1, stdout="", stderr="profile denied"),
         "profile denied"),
    ]:
        probe = Mock(side_effect=outcome) if isinstance(outcome, BaseException) else Mock(
            return_value=outcome)
        observation = StrictSandboxExecutor(
            sandbox_binary="bwrap", prlimit_binary="prlimit",
            probe_runner=probe).execute(request)
        assert observation.status == "SANDBOX_UNAVAILABLE"
        assert expected in observation.message

    executor = StrictSandboxExecutor(
        sandbox_binary="bwrap", prlimit_binary="prlimit",
        probe_runner=Mock(return_value=SimpleNamespace(
            returncode=0, stdout="", stderr="")))
    completed = SimpleNamespace(status="COMPLETED")
    executor._run_bounded = Mock(return_value=completed)
    assert executor.execute(request) is completed
    executor._run_bounded.assert_called_once()


def test_bounded_runner_reports_normal_failure_and_spawn_error(tmp_path):
    request = _request(tmp_path / "normal")
    executor = StrictSandboxExecutor(sandbox_binary="unused", prlimit_binary="unused")
    completed = executor._run_bounded(
        [sys.executable, "-c", "print('ok')"], request)
    assert completed.status == "COMPLETED" and completed.output.strip() == "ok"
    failed = executor._run_bounded(
        [sys.executable, "-c", "raise SystemExit(7)"], request)
    assert failed.status == "TOOL_FAILED" and failed.exit_code == 7

    broken = StrictSandboxExecutor(
        sandbox_binary="unused", prlimit_binary="unused",
        popen_factory=Mock(side_effect=OSError("cannot spawn")))
    observation = broken._run_bounded(["tool"], request)
    assert observation.status == "TOOL_ERROR" and "cannot spawn" in observation.message


def test_process_termination_falls_back_to_direct_kill():
    process = Mock(pid=123)
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(os, "killpg", Mock(side_effect=OSError("gone")))
        StrictSandboxExecutor._terminate_unit(process)
    process.kill.assert_called_once()

    process.kill.side_effect = OSError("gone")
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(os, "killpg", Mock(side_effect=OSError("gone")))
        StrictSandboxExecutor._terminate_unit(process)


def test_workspace_accounting_tolerates_disappearing_files(tmp_path):
    (tmp_path / "file").write_text("data", encoding="utf-8")
    with patch("pipeline.execution.Path.lstat", side_effect=OSError("gone")):
        assert StrictSandboxExecutor._workspace_size(tmp_path) == 0
    with patch("pipeline.execution.os.walk", side_effect=OSError("unavailable")):
        assert StrictSandboxExecutor._workspace_size(tmp_path) == 0


def test_output_and_process_tree_are_bounded(tmp_path):
    output_request = _request(
        tmp_path / "output",
        policy=ExecutionPolicy(timeout_s=5, max_output_bytes=1024))
    executor = StrictSandboxExecutor(sandbox_binary="unused", prlimit_binary="unused")
    output = executor._run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"],
        output_request)
    assert output.status == "OUTPUT_LIMIT_EXCEEDED"
    assert output.output_truncated and len(output.output.encode()) <= 1024

    timeout_request = _request(
        tmp_path / "timeout",
        policy=ExecutionPolicy(timeout_s=0.2, max_output_bytes=1024))
    timeout = executor._run_bounded(
        [sys.executable, "-c",
         "import subprocess,time; subprocess.Popen(['sleep','30']); time.sleep(30)"],
        timeout_request)
    assert timeout.status == "TIMEOUT"
    assert timeout.timed_out and timeout.exit_code == 124

    storage_request = _request(
        tmp_path / "storage",
        policy=ExecutionPolicy(timeout_s=5, max_workspace_bytes=1024))
    storage_request.workspace.mkdir()
    target = storage_request.workspace / "large.bin"
    storage = executor._run_bounded(
        [sys.executable, "-c",
         f"import time; open({str(target)!r}, 'wb').write(b'x' * 4096); time.sleep(2)"],
        storage_request)
    assert storage.status == "WORKSPACE_LIMIT_EXCEEDED"
