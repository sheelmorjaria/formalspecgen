# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Run OpenJML against immutable inputs in the strict execution boundary.

Generalized from formalspecDD's `-esc`-only wrapper: this project primarily uses
`-check` (fast, no SMT solver needed); `-esc` is available for an optional deep check.
"""
import shutil
import tempfile
from pathlib import Path

from . import config
from .execution import (ExecutionPolicy, ExecutionRequest, SourceSnapshot,
                        StrictSandboxExecutor)

TIMEOUT_EXIT = 124
TOOL_ERROR_EXIT = 125
_MODES = {"parse", "check", "esc"}
_DROPPED_VC_MARKERS = ("Not yet supported feature", "Not implemented for static checking")
_TOOL_CONFIGURATION_MARKERS = (
    "Could not find the internal system specifications",
    "Could not locate the internal specifications files",
)


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
        return configured if configured.is_file() else None
    resolved = shutil.which(config.OPENJML)
    return Path(resolved) if resolved else None


def _sandbox_verify(java_files, mode, timeout, executor=None):
    sources = [Path(path) for path in java_files]
    missing = [str(path) for path in sources if not path.is_file()]
    if missing:
        return TOOL_ERROR_EXIT, "<source file unavailable: " + ", ".join(missing) + ">"
    names = [path.name for path in sources]
    if len(names) != len(set(names)):
        return TOOL_ERROR_EXIT, "<duplicate Java source basenames cannot share a snapshot>"
    openjml = _resolved_openjml()
    if openjml is None:
        return 127, f"<openjml binary not found at {config.OPENJML}>"
    specs_value = getattr(config, "OPENJML_SPECS", "")
    specs = Path(specs_value).resolve() if specs_value and Path(specs_value).exists() else None
    with tempfile.TemporaryDirectory(prefix="formalspecgen-openjml-") as temporary:
        root = Path(temporary)
        snapshot = SourceSnapshot.create(
            root / "snapshot", {path.name: path.read_bytes() for path in sources})
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
                timeout_s=float(timeout), max_memory_bytes=2 * 1024 * 1024 * 1024),
            readonly_paths=tuple(dict.fromkeys(readonly_paths))))
    if observation.status == "TIMEOUT":
        return TIMEOUT_EXIT, f"<openjml -{mode} timed out after {timeout}s>"
    if observation.policy_compliance != "ENFORCED":
        detail = observation.message or observation.status
        return TOOL_ERROR_EXIT, f"<openjml sandbox policy not enforced: {detail}>"
    if observation.status == "OUTPUT_LIMIT_EXCEEDED":
        return TOOL_ERROR_EXIT, observation.output + "\n<openjml output limit exceeded>"
    return _tool_result(observation.exit_code, observation.output)


def verify(java_file, mode="check", timeout=None, *, executor=None):
    """Run `openjml -<mode> <java_file>`. Returns (exit_code, combined_text)."""
    if mode not in _MODES:
        raise ValueError(f"mode must be one of {_MODES}, got {mode!r}")
    if timeout is None:
        timeout = config.ESC_TIMEOUT if mode == "esc" else config.CHECK_TIMEOUT
    return _sandbox_verify([java_file], mode, timeout, executor)


def verify_files(java_files, mode="check", timeout=None, *, executor=None):
    """Run OpenJML once over a mutually dependent set of Java sources."""
    if mode not in _MODES:
        raise ValueError(f"mode must be one of {_MODES}, got {mode!r}")
    timeout = timeout or (config.ESC_TIMEOUT if mode == "esc" else config.CHECK_TIMEOUT)
    return _sandbox_verify(java_files, mode, timeout, executor)


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
