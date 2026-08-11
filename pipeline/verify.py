# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Wrap OpenJML in parse/check/esc modes. Returns (exit_code, combined_text).

Generalized from formalspecDD's `-esc`-only wrapper: this project primarily uses
`-check` (fast, no SMT solver needed); `-esc` is available for an optional deep check.
"""
import subprocess
from pathlib import Path
from . import config

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


def verify(java_file, mode="check", timeout=None):
    """Run `openjml -<mode> <java_file>`. Returns (exit_code, combined_text)."""
    if mode not in _MODES:
        raise ValueError(f"mode must be one of {_MODES}, got {mode!r}")
    if timeout is None:
        timeout = config.ESC_TIMEOUT if mode == "esc" else config.CHECK_TIMEOUT
    try:
        p = subprocess.run(
            _command(mode, [java_file]),
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return TIMEOUT_EXIT, f"<openjml -{mode} timed out after {timeout}s>"
    except FileNotFoundError:
        return 127, f"<openjml binary not found at {config.OPENJML}>"
    text = (p.stdout or "") + (p.stderr or "")
    return _tool_result(p.returncode, text)


def verify_files(java_files, mode="check", timeout=None):
    """Run OpenJML once over a mutually dependent set of Java sources."""
    if mode not in _MODES:
        raise ValueError(f"mode must be one of {_MODES}, got {mode!r}")
    timeout = timeout or (config.ESC_TIMEOUT if mode == "esc" else config.CHECK_TIMEOUT)
    try:
        process = subprocess.run(_command(mode, java_files),
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return TIMEOUT_EXIT, f"<openjml -{mode} timed out after {timeout}s>"
    except FileNotFoundError:
        return 127, f"<openjml binary not found at {config.OPENJML}>"
    text = (process.stdout or "") + (process.stderr or "")
    return _tool_result(process.returncode, text)


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
