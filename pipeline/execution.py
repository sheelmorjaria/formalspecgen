# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed source snapshots and bounded Linux sandbox execution."""
from __future__ import annotations

import hashlib
import json
import math
import os
import selectors
import shutil
import signal
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping


_ALLOWED_ENVIRONMENT = {"LANG", "LC_ALL", "PATH", "SOURCE_DATE_EPOCH", "TZ"}
_SYSTEM_MOUNTS = ("/usr", "/bin", "/lib", "/lib64")
_SYSTEM_FILES = ("/etc/ld.so.cache",)


@dataclass(frozen=True)
class ExecutionPolicy:
    """Resource and isolation requirements for one execution unit."""

    timeout_s: float = 60.0
    max_memory_bytes: int = 512 * 1024 * 1024
    max_processes: int = 32
    max_output_bytes: int = 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    max_workspace_bytes: int = 128 * 1024 * 1024
    network: str = "denied"
    filesystem: str = "readonly-input-disposable-workspace"
    profile: str = "linux-bwrap-v1"


@dataclass(frozen=True)
class SourceSnapshot:
    """An immutable-by-convention directory and its byte-level manifest."""

    root: Path
    manifest: tuple[dict, ...]
    manifest_sha256: str

    @classmethod
    def create(cls, root: Path, files: Mapping[str, str | bytes]) -> "SourceSnapshot":
        root.mkdir(parents=True, exist_ok=False)
        records = []
        for name in sorted(files):
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                raise ValueError(f"snapshot path must be relative and contained: {name!r}")
            target = root.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            value = files[name]
            content = value.encode("utf-8") if isinstance(value, str) else bytes(value)
            with target.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(target, 0o444)
            records.append({"path": relative.as_posix(), "size": len(content),
                            "sha256": hashlib.sha256(content).hexdigest()})
        manifest_json = json.dumps(records, sort_keys=True, separators=(",", ":"))
        manifest_path = root / "snapshot-manifest.json"
        with manifest_path.open("x", encoding="utf-8") as handle:
            handle.write(manifest_json)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(manifest_path, 0o444)
        return cls(root=root, manifest=tuple(records),
                   manifest_sha256=hashlib.sha256(manifest_json.encode("utf-8")).hexdigest())

    def validate(self) -> bool:
        for record in self.manifest:
            path = self.root.joinpath(*PurePosixPath(record["path"]).parts)
            try:
                content = path.read_bytes()
            except OSError:
                return False
            if len(content) != record["size"] or \
                    hashlib.sha256(content).hexdigest() != record["sha256"]:
                return False
        expected = json.dumps(list(self.manifest), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(expected.encode("utf-8")).hexdigest() == self.manifest_sha256


@dataclass(frozen=True)
class ExecutionRequest:
    """Exact command, snapshot, environment, and policy requested by an adapter."""

    tool: str
    command: tuple[str, ...]
    snapshot: SourceSnapshot
    workspace: Path
    policy: ExecutionPolicy = field(default_factory=ExecutionPolicy)
    environment: Mapping[str, str] = field(default_factory=dict)
    readonly_paths: tuple[Path, ...] = ()


@dataclass(frozen=True)
class ExecutionObservation:
    """Process observation kept separate from verification and publication status."""

    status: str
    exit_code: int
    output: str
    requested_policy: dict
    enforced_policy: dict | None
    policy_compliance: str
    snapshot_manifest_sha256: str
    timed_out: bool = False
    output_truncated: bool = False
    message: str = ""
    tool: str = ""
    command: tuple[str, ...] = ()
    readonly_paths: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return asdict(self)


class StrictSandboxExecutor:
    """Execute only when a networkless bubblewrap profile can be enforced."""

    def __init__(self, *, sandbox_binary: str | None = None,
                 prlimit_binary: str | None = None,
                 probe_runner: Callable = subprocess.run,
                 popen_factory: Callable = subprocess.Popen):
        self.sandbox_binary = shutil.which("bwrap") if sandbox_binary is None else sandbox_binary
        self.prlimit_binary = shutil.which("prlimit") if prlimit_binary is None else prlimit_binary
        self.probe_runner = probe_runner
        self.popen_factory = popen_factory

    def execute(self, request: ExecutionRequest) -> ExecutionObservation:
        requested = asdict(request.policy)
        invalid = self._validate_request(request)
        if invalid:
            return self._failure("POLICY_INVALID", requested, request, invalid)
        if not request.snapshot.validate():
            return self._failure(
                "SNAPSHOT_INTEGRITY_FAILED", requested, request,
                "source snapshot bytes no longer match their manifest")
        if not self.sandbox_binary or not self.prlimit_binary:
            return self._failure(
                "SANDBOX_UNAVAILABLE", requested, request,
                "bubblewrap and prlimit are required; unrestricted fallback is forbidden")
        request.workspace.mkdir(parents=True, exist_ok=True)
        probe = self._sandbox_command(request, ("/bin/true",))
        try:
            checked = self.probe_runner(
                probe, capture_output=True, text=True, timeout=5,
                env=self._host_environment(request.environment))
        except (OSError, subprocess.TimeoutExpired) as exc:
            return self._failure("SANDBOX_UNAVAILABLE", requested, request, str(exc))
        if checked.returncode != 0:
            output = ((checked.stdout or "") + (checked.stderr or "")).strip()
            return self._failure(
                "SANDBOX_UNAVAILABLE", requested, request,
                output[-2000:] or "sandbox profile probe failed")
        command = self._sandbox_command(request, request.command)
        return self._run_bounded(command, request)

    def _validate_request(self, request: ExecutionRequest) -> str:
        if request.policy.network != "denied":
            return "the strict profile requires network=denied"
        if request.policy.profile != "linux-bwrap-v1":
            return "unsupported execution profile"
        if not request.command:
            return "execution command is empty"
        rejected = sorted(set(request.environment) - _ALLOWED_ENVIRONMENT)
        if rejected:
            return "environment keys are not allowlisted: " + ", ".join(rejected)
        if request.policy.timeout_s <= 0 or request.policy.max_output_bytes <= 0 or \
                request.policy.max_workspace_bytes <= 0:
            return "time and output limits must be positive"
        snapshot_root = request.snapshot.root.resolve()
        workspace = request.workspace.resolve()
        if request.workspace.is_symlink() or workspace == Path("/") or \
                workspace.parent != snapshot_root.parent or workspace == snapshot_root:
            return "workspace must be a sibling disposable directory beside the source snapshot"
        forbidden_mounts = {Path("/"), Path.home().resolve()}
        for path in request.readonly_paths:
            if not path.is_absolute() or not path.exists():
                return f"read-only tool path must be an existing absolute path: {path}"
            if path.resolve() in forbidden_mounts:
                return f"read-only tool path is too broad for the strict profile: {path}"
        return ""

    def _sandbox_command(self, request: ExecutionRequest,
                         command: tuple[str, ...]) -> list[str]:
        policy = request.policy
        result = [
            str(self.prlimit_binary), f"--as={policy.max_memory_bytes}",
            f"--nproc={policy.max_processes}", f"--fsize={policy.max_file_bytes}",
            f"--cpu={max(1, math.ceil(policy.timeout_s))}", "--",
            str(self.sandbox_binary), "--die-with-parent", "--unshare-all",
            "--new-session", "--proc", "/proc", "--dev", "/dev",
            "--tmpfs", "/tmp", "--ro-bind", str(request.snapshot.root), "/input",
            "--bind", str(request.workspace), "/work", "--chdir", "/work",
            "--clearenv",
        ]
        for path in (*_SYSTEM_MOUNTS, *_SYSTEM_FILES):
            if Path(path).exists():
                result.extend(["--ro-bind", path, path])
        for path in request.readonly_paths:
            result.extend(["--ro-bind", str(path), str(path)])
        for name, value in sorted(self._sandbox_environment(request.environment).items()):
            result.extend(["--setenv", name, value])
        result.extend(["--", *command])
        return result

    @staticmethod
    def _sandbox_environment(requested: Mapping[str, str]) -> dict[str, str]:
        environment = {"HOME": "/work", "LANG": "C.UTF-8",
                       "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin",
                       "TMPDIR": "/tmp", "TZ": "UTC"}
        environment.update({key: str(value) for key, value in requested.items()})
        return environment

    @staticmethod
    def _host_environment(requested: Mapping[str, str]) -> dict[str, str]:
        environment = StrictSandboxExecutor._sandbox_environment(requested)
        return {"PATH": environment["PATH"], "LANG": environment["LANG"],
                "LC_ALL": environment["LC_ALL"], "TZ": environment["TZ"]}

    def _run_bounded(self, command: list[str], request: ExecutionRequest) -> ExecutionObservation:
        policy = request.policy
        try:
            process = self.popen_factory(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, start_new_session=True,
                env=self._host_environment(request.environment))
        except OSError as exc:
            return self._failure("TOOL_ERROR", asdict(policy), request, str(exc))
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        chunks = bytearray()
        started = time.monotonic()
        timed_out = truncated = storage_exceeded = False
        last_storage_check = 0.0
        try:
            while selector.get_map():
                now = time.monotonic()
                remaining = policy.timeout_s - (now - started)
                if remaining <= 0:
                    timed_out = True
                    self._terminate_unit(process)
                    break
                if now - last_storage_check >= 0.1:
                    last_storage_check = now
                    if self._workspace_size(request.workspace) > policy.max_workspace_bytes:
                        storage_exceeded = True
                        self._terminate_unit(process)
                        break
                events = selector.select(min(remaining, 0.1))
                if not events and process.poll() is not None:
                    tail = process.stdout.read() or b""
                    chunks.extend(tail[:max(0, policy.max_output_bytes - len(chunks))])
                    break
                for key, _mask in events:
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    room = policy.max_output_bytes - len(chunks)
                    chunks.extend(data[:max(0, room)])
                    if len(data) > room:
                        truncated = True
                        self._terminate_unit(process)
                        break
                if truncated:
                    break
        finally:
            selector.close()
        try:
            exit_code = process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._terminate_unit(process)
            exit_code = process.wait(timeout=2)
        storage_exceeded = storage_exceeded or \
            self._workspace_size(request.workspace) > policy.max_workspace_bytes
        status = "TIMEOUT" if timed_out else \
            "WORKSPACE_LIMIT_EXCEEDED" if storage_exceeded else \
            "OUTPUT_LIMIT_EXCEEDED" if truncated else \
            "COMPLETED" if exit_code == 0 else "TOOL_FAILED"
        return ExecutionObservation(
            status=status, exit_code=124 if timed_out else 126 if (
                truncated or storage_exceeded) else exit_code,
            output=bytes(chunks).decode("utf-8", errors="replace"),
            requested_policy=asdict(policy), enforced_policy=asdict(policy),
            policy_compliance="ENFORCED", snapshot_manifest_sha256=request.snapshot.manifest_sha256,
            timed_out=timed_out, output_truncated=truncated,
            tool=request.tool, command=request.command,
            readonly_paths=tuple(str(path) for path in request.readonly_paths))

    @staticmethod
    def _workspace_size(root: Path) -> int:
        total = 0
        try:
            for directory, _subdirectories, files in os.walk(root, followlinks=False):
                for name in files:
                    try:
                        total += (Path(directory) / name).lstat().st_size
                    except OSError:
                        continue
        except OSError:
            return 0
        return total

    @staticmethod
    def _terminate_unit(process) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass

    @staticmethod
    def _failure(status: str, requested: dict, request: ExecutionRequest,
                 message: str) -> ExecutionObservation:
        return ExecutionObservation(
            status=status, exit_code=125, output="", requested_policy=requested,
            enforced_policy=None, policy_compliance="NOT_ENFORCED",
            snapshot_manifest_sha256=request.snapshot.manifest_sha256,
            message=message, tool=request.tool, command=request.command,
            readonly_paths=tuple(str(path) for path in request.readonly_paths))
