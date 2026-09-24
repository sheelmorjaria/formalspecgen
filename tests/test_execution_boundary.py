"""Strict execution policy, snapshot integrity, and bounded process collection."""
from __future__ import annotations

import os
import selectors
import signal
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from pipeline.execution import (
    CgroupV2Handle, ExecutionPolicy, ExecutionRequest, SourceSnapshot,
    StrictSandboxExecutor,
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
    assert str(request.workspace) not in command
    assert ["--size", str(request.policy.max_temporary_bytes), "--tmpfs", "/tmp"] == command[
        command.index(str(request.policy.max_temporary_bytes)) - 1:
        command.index(str(request.policy.max_temporary_bytes)) + 3]
    assert ["--size", str(request.policy.max_workspace_bytes), "--tmpfs", "/work"] == command[
        command.index(str(request.policy.max_workspace_bytes)) - 1:
        command.index(str(request.policy.max_workspace_bytes)) + 3]
    assert not any(item.startswith("--as=") for item in command)
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
    ({"policy": ExecutionPolicy(filesystem="unknown")}, "unsupported filesystem policy"),
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
    cgroup = Mock()
    cgroup.attach_command.side_effect = lambda command: command
    executor._create_cgroup = Mock(return_value=cgroup)
    assert executor.execute(request) is completed
    executor._run_bounded.assert_called_once()

    executor = StrictSandboxExecutor(
        sandbox_binary="bwrap", prlimit_binary="prlimit",
        probe_runner=Mock(return_value=SimpleNamespace(
            returncode=0, stdout="", stderr="")))
    executor._create_cgroup = Mock(side_effect=OSError("delegation denied"))
    unavailable = executor.execute(request)
    assert unavailable.status == "RESOURCE_CONTROL_UNAVAILABLE"
    assert unavailable.policy_compliance == "NOT_ENFORCED"
    assert "delegation denied" in unavailable.message


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


def test_cgroup_event_collection_and_attach_wrapper(tmp_path):
    (tmp_path / "memory.events").write_text("oom 1\noom_kill 2\n", encoding="ascii")
    (tmp_path / "pids.events").write_text("max 3\n", encoding="ascii")
    handle = CgroupV2Handle(tmp_path)
    assert handle.events() == {"oom": 1, "oom_kill": 2, "pids_max": 3}
    command = handle.attach_command(["/bin/true"])
    assert command[-1] == "/bin/true"
    assert "cgroup.procs" in command[2]


def test_cgroup_creation_writes_memory_process_and_swap_limits(tmp_path):
    (tmp_path / "cgroup.controllers").write_text("memory pids", encoding="ascii")
    target = tmp_path / f"formalspecgen-{os.getpid()}-fixed"
    target.mkdir()
    for name in ("memory.max", "pids.max", "memory.swap.max"):
        (target / name).write_text("max", encoding="ascii")
    original_mkdir = Path.mkdir

    def mkdir(path, *args, **kwargs):
        if path == target:
            return None
        return original_mkdir(path, *args, **kwargs)

    policy = ExecutionPolicy(max_memory_bytes=1234, max_processes=7)
    executor = StrictSandboxExecutor(
        sandbox_binary="unused", prlimit_binary="unused", cgroup_root=tmp_path)
    with patch("pipeline.execution.uuid.uuid4", return_value=SimpleNamespace(hex="fixed")), \
         patch.object(Path, "mkdir", mkdir):
        handle = executor._create_cgroup(policy)
    assert handle.path == target
    assert (target / "memory.max").read_text(encoding="ascii") == "1234"
    assert (target / "pids.max").read_text(encoding="ascii") == "7"
    assert (target / "memory.swap.max").read_text(encoding="ascii") == "0"


def test_current_cgroup_resolution_and_missing_membership():
    with patch.object(Path, "read_text", return_value="0::/runner/scope\n"):
        assert StrictSandboxExecutor._current_cgroup_root() == \
            Path("/sys/fs/cgroup/runner/scope")
    with patch.object(Path, "read_text", return_value="1:name:/legacy\n"), \
         pytest.raises(OSError, match="membership is unavailable"):
        StrictSandboxExecutor._current_cgroup_root()


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

    storage_request = _request(tmp_path / "storage")
    storage = executor._run_bounded(
        [sys.executable, "-c", "import sys; print('No space left on device'); sys.exit(1)"],
        storage_request)
    assert storage.status == "WRITABLE_STORAGE_LIMIT_EXCEEDED"


class _EventCgroup:
    def __init__(self, events):
        self._events = events
        self.killed = False
        self.closed = False

    def events(self):
        return dict(self._events)

    def kill(self):
        self.killed = True

    def close(self):
        self.closed = True
        return True


@pytest.mark.parametrize(("events", "status"), [
    ({"oom_kill": 1}, "MEMORY_LIMIT_EXCEEDED"),
    ({"max": 1}, "MEMORY_LIMIT_EXCEEDED"),
    ({"pids_max": 1}, "PROCESS_LIMIT_EXCEEDED"),
])
def test_cgroup_events_determine_resource_failure(tmp_path, events, status):
    request = _request(tmp_path / status)
    cgroup = _EventCgroup(events)
    observation = StrictSandboxExecutor(
        sandbox_binary="unused", prlimit_binary="unused")._run_bounded(
            [sys.executable, "-c", "raise SystemExit(1)"], request, cgroup)
    assert observation.status == status
    assert observation.exit_code == 126
    assert observation.resource_events == events
    assert observation.policy_compliance == "ENFORCED"
    assert cgroup.closed


@pytest.mark.parametrize(("signal_number", "status"), [
    (signal.SIGXCPU, "CPU_LIMIT_EXCEEDED"),
    (signal.SIGXFSZ, "FILE_SIZE_LIMIT_EXCEEDED"),
])
def test_resource_limit_signals_are_not_tool_failures(
        tmp_path, signal_number, status):
    request = _request(tmp_path / status)
    cgroup = _EventCgroup({})
    process = Mock(pid=123, stdout=Mock())
    process.stdout.fileno.return_value = 0
    process.poll.return_value = 128 + signal_number
    process.wait.return_value = 128 + signal_number
    executor = StrictSandboxExecutor(
        sandbox_binary="unused", prlimit_binary="unused",
        popen_factory=Mock(return_value=process))
    with patch.object(selectors.DefaultSelector, "register"), \
         patch.object(selectors.DefaultSelector, "get_map", return_value={}):
        observation = executor._run_bounded(["tool"], request, cgroup)
    assert observation.status == status
    assert observation.exit_code == 126


def test_cgroup_attach_failure_is_not_reported_as_tool_failure(tmp_path):
    request = _request(tmp_path)
    cgroup = _EventCgroup({})
    observation = StrictSandboxExecutor(
        sandbox_binary="unused", prlimit_binary="unused")._run_bounded(
            [sys.executable, "-c",
             "print('FORMALSPECGEN_CGROUP_ATTACH_FAILED'); raise SystemExit(125)"],
            request, cgroup)
    assert observation.status == "RESOURCE_CONTROL_UNAVAILABLE"
    assert observation.policy_compliance == "NOT_ENFORCED"
    assert observation.enforced_policy is None


def test_cgroup_cleanup_failure_invalidates_policy_compliance(tmp_path):
    request = _request(tmp_path)
    cgroup = _EventCgroup({})
    cgroup.close = Mock(return_value=False)
    observation = StrictSandboxExecutor(
        sandbox_binary="unused", prlimit_binary="unused")._run_bounded(
            [sys.executable, "-c", "pass"], request, cgroup)
    assert observation.status == "RESOURCE_CLEANUP_FAILED"
    assert observation.policy_compliance == "NOT_ENFORCED"
    assert "cleanup" in observation.message
