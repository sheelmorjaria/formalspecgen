# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""ESBMC adapter with explicitly bounded C++ evidence."""
from __future__ import annotations

import subprocess
from pathlib import Path


def verify_cpp(file_path: str | Path, timeout: int = 180, unwind: int = 5) -> dict:
    path = Path(file_path)
    command = ["esbmc", str(path), "--unwind", str(unwind),
               "--memory-leak-check", "--force-malloc-success", "--z3"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {"status": "TOOL_MISSING", "claim": "NO_PROOF", "language": "cpp",
                "exit_code": 127, "message": "ESBMC binary not found"}
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "claim": "NO_PROOF", "language": "cpp",
                "exit_code": 124, "message": f"ESBMC timed out after {timeout}s"}
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    success = result.returncode == 0 and "verification successful" in output.lower()
    return {"status": "VERIFIED" if success else "VERIFY_FAILED",
            "claim": "BOUNDED_CPP_PROOF" if success else "NO_PROOF",
            "language": "cpp", "exit_code": result.returncode,
            "unbounded_loop_proved": False, "unwind": unwind, "output": output[-12000:]}
