# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Run OpenJML against immutable inputs in the strict execution boundary.

Generalized from formalspecDD's `-esc`-only wrapper: this project primarily uses
`-check` (fast, no SMT solver needed); `-esc` is available for an optional deep check.
"""
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import config
from .execution import (ExecutionObservation, ExecutionPolicy, ExecutionRequest,
                        SourceSnapshot, StrictSandboxExecutor)

TIMEOUT_EXIT = 124
TOOL_ERROR_EXIT = 125
_MODES = {"parse", "check", "esc"}
_DROPPED_VC_MARKERS = ("Not yet supported feature", "Not implemented for static checking")
_TOOL_CONFIGURATION_MARKERS = (
    "Could not find the internal system specifications",
    "Could not locate the internal specifications files",
)


@dataclass(frozen=True)
class VerificationExecutionResult:
    """Backend interpretation retaining the authoritative executor observation."""

    exit_code: int
    output: str
    observation: ExecutionObservation | None

    def legacy_tuple(self) -> tuple[int, str]:
        return self.exit_code, self.output

    def as_dict(self) -> dict:
        return {
            "exit_code": self.exit_code,
            "output": self.output,
            "execution": self.observation.as_dict() if self.observation else None,
        }


def _command(mode, java_files):
    command = [config.OPENJML, f"-{mode}"]
    specs = getattr(config, "OPENJML_SPECS", "")
    if specs and Path(specs).exists():
        command.extend(["--specs-path", specs])
    command.extend(map(str, java_files))
    return command


def _tool_result(returncode, text):
    if any(marker in text for marker in _TOOL_CONFIGURATION_MARKERS):
        return TOOL_ERROR_EXIT, text
    return returncode, text


def has_dropped_vc(text: str) -> bool:
    """True when ESC reports that an unsupported construct was omitted from SMT."""
    return any(marker in text for marker in _DROPPED_VC_MARKERS)


def _resolved_openjml() -> Path | None:
    configured = Path(config.OPENJML)
    if configured.is_absolute():
        return configured.resolve() if configured.is_file() else None
    resolved = shutil.which(config.OPENJML)
    return Path(resolved).resolve() if resolved else None


def _sandbox_verify_detailed(java_files, mode, timeout, executor=None):
    sources = [Path(path) for path in java_files]
    missing = [str(path) for path in sources if not path.is_file()]
    if missing:
        return VerificationExecutionResult(
            TOOL_ERROR_EXIT, "<source file unavailable: " + ", ".join(missing) + ">", None)
    names = [(path.with_suffix(".java").name
              if path.suffix.lower() == ".jml" else path.name)
             for path in sources]
    if len(names) != len(set(names)):
        return VerificationExecutionResult(
            TOOL_ERROR_EXIT, "<duplicate Java source basenames cannot share a snapshot>", None)
    openjml = _resolved_openjml()
    if openjml is None:
        return VerificationExecutionResult(
            127, f"<openjml binary not found at {config.OPENJML}>", None)
    specs_value = getattr(config, "OPENJML_SPECS", "")
    specs = Path(specs_value).resolve() if specs_value and Path(specs_value).exists() else None
    with tempfile.TemporaryDirectory(prefix="formalspecgen-openjml-") as temporary:
        root = Path(temporary)
        snapshot_files = {}
        for path, active_name in zip(sources, names):
            content = path.read_bytes()
            if path.suffix.lower() == ".jml":
                snapshot_files[f"reviewed/{path.name}"] = content
            snapshot_files[active_name] = content
        snapshot = SourceSnapshot.create(root / "snapshot", snapshot_files)
        command = [str(openjml), f"-{mode}"]
        readonly_paths = []
        if specs is not None:
            command.extend(["--specs-path", str(specs)])
            readonly_paths.append(specs)
        command.extend(f"/input/{name}" for name in names)
        # OpenJML distributions commonly keep jars next to their launcher.
        readonly_paths.append(openjml.resolve().parent)
        observation = (executor or StrictSandboxExecutor()).execute(ExecutionRequest(
            tool="openjml", command=tuple(command), snapshot=snapshot,
            workspace=root / "workspace",
            policy=ExecutionPolicy(
                timeout_s=float(timeout), max_memory_bytes=2 * 1024 * 1024 * 1024,
                # The JVM creates GC/compiler workers from the visible host CPU
                # count.  Keep the execution unit bounded without preventing
                # OpenJML from starting on high-core-count acceptance runners.
                max_processes=128),
            readonly_paths=tuple(dict.fromkeys(readonly_paths))))
    if observation.status == "TIMEOUT":
        return VerificationExecutionResult(
            TIMEOUT_EXIT, f"<openjml -{mode} timed out after {timeout}s>", observation)
    if observation.policy_compliance != "ENFORCED":
        detail = observation.message or observation.status
        return VerificationExecutionResult(
            TOOL_ERROR_EXIT, f"<openjml sandbox policy not enforced: {detail}>", observation)
    if observation.status in {
            "OUTPUT_LIMIT_EXCEEDED", "MEMORY_LIMIT_EXCEEDED",
            "PROCESS_LIMIT_EXCEEDED", "WRITABLE_STORAGE_LIMIT_EXCEEDED",
            "CPU_LIMIT_EXCEEDED", "FILE_SIZE_LIMIT_EXCEEDED"}:
        return VerificationExecutionResult(
            TOOL_ERROR_EXIT,
            observation.output + f"\n<openjml resource failure: {observation.status}>",
            observation)
    exit_code, output = _tool_result(observation.exit_code, observation.output)
    return VerificationExecutionResult(exit_code, output, observation)


def verify_detailed(java_file, mode="check", timeout=None, *, executor=None):
    """Run OpenJML and retain the exact execution observation."""
    if mode not in _MODES:
        raise ValueError(f"mode must be one of {_MODES}, got {mode!r}")
    if timeout is None:
        timeout = config.ESC_TIMEOUT if mode == "esc" else config.CHECK_TIMEOUT
    return _sandbox_verify_detailed([java_file], mode, timeout, executor)


def verify(java_file, mode="check", timeout=None, *, executor=None):
    """Compatibility wrapper returning ``(exit_code, output)``."""
    return verify_detailed(java_file, mode, timeout, executor=executor).legacy_tuple()


def verify_files_detailed(java_files, mode="check", timeout=None, *, executor=None):
    """Run OpenJML over a source set and retain the execution observation."""
    if mode not in _MODES:
        raise ValueError(f"mode must be one of {_MODES}, got {mode!r}")
    timeout = timeout or (config.ESC_TIMEOUT if mode == "esc" else config.CHECK_TIMEOUT)
    return _sandbox_verify_detailed(java_files, mode, timeout, executor)


def verify_files(java_files, mode="check", timeout=None, *, executor=None):
    """Compatibility wrapper returning ``(exit_code, output)``."""
    return verify_files_detailed(
        java_files, mode, timeout, executor=executor).legacy_tuple()


def classify(exit_code: int) -> str:
    if exit_code == 0:
        return "VERIFIED"
    if exit_code == 6:
        return "VERIFY_FAILED"   # -esc VC failures
    if exit_code == 1:
        return "COMPILE_FAILED"  # -check/-parse spec/type/config errors
    if exit_code == TIMEOUT_EXIT:
        return "TIMEOUT"
    if exit_code == TOOL_ERROR_EXIT:
        return "TOOL_ERROR"
    if exit_code == 127:
        return "TOOL_MISSING"
    return f"UNKNOWN_EXIT_{exit_code}"
