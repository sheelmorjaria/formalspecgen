# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Strict TLC provenance and execution adapter for the isolated V2 lifecycle."""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Callable


class V2ToolProvenanceError(RuntimeError):
    pass


Runner = Callable[..., subprocess.CompletedProcess]


def get_tlc_provenance(tlc_jar: str, *, java: str = "java", timeout: int = 10,
                       runner: Runner = subprocess.run) -> dict:
    # TLC 2.19 has no -version option. Its supported help command prints the version banner but
    # exits 1 after displaying help, so a parsed banner—not the help exit status—is authoritative.
    command = [java, "-jar", tlc_jar, "-help"]
    try:
        result = runner(command, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"version": None, "command": command, "status": "TOOL_EXECUTION_FAILED",
                "exit_status": None, "diagnostic": type(exc).__name__}
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    match = re.search(r"(?:\bTLC2\s+Version\s+|\bTLC\b[^\r\n]*?\bVersion\s+)([^\r\n]+)", output)
    if not match:
        return {"version": None, "command": command,
                "status": "TOOL_VERSION_UNAVAILABLE", "exit_status": result.returncode,
                "output": output[-2000:]}
    return {"version": match.group(1).strip(), "command": command, "status": "OK",
            "exit_status": result.returncode}


def require_tlc_provenance(value: dict) -> dict:
    if value.get("status") != "OK" or not value.get("version"):
        raise V2ToolProvenanceError(
            f"TLC provenance is unavailable: {value.get('status', 'UNKNOWN')}")
    return value


def run_tlc_artifacts(tla: str, cfg: str, *, module_name: str, tlc_jar: str,
                      java: str = "java", timeout: int = 120,
                      runner: Runner = subprocess.run) -> dict:
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", module_name):
        raise ValueError("unsafe TLA+ module name")
    with tempfile.TemporaryDirectory(prefix="formalspecgen-v2-tlc-") as directory:
        root = Path(directory)
        tla_path, cfg_path = root / f"{module_name}.tla", root / f"{module_name}.cfg"
        tla_path.write_text(tla, encoding="utf-8")
        cfg_path.write_text(cfg, encoding="utf-8")
        command = [java, "-jar", tlc_jar, "-config", cfg_path.name, tla_path.name]
        try:
            result = runner(command, cwd=str(root), capture_output=True, text=True,
                            timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            return {"status": "TOOL_EXECUTION_FAILED", "exit_status": None,
                    "command": command, "diagnostic": type(exc).__name__}
        output = ((result.stdout or "") + (result.stderr or "")).strip()
        return {"status": "VERIFIED" if result.returncode == 0 else "TLC_FAILED",
                "exit_status": result.returncode, "command": command,
                "output": output[-4000:]}
