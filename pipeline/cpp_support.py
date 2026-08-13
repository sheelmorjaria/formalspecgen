# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Native C++17 syntax gate used before bounded ESBMC evidence."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


def check_cpp_syntax(code: str, timeout: int = 60) -> dict:
    compiler = shutil.which("g++")
    if not compiler:
        return {"status": "TOOL_MISSING", "exit_code": 127, "language": "cpp"}
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "contract.cpp"
        source.write_text(code, encoding="utf-8")
        try:
            result = subprocess.run([compiler, "-std=c++17", "-fsyntax-only", str(source)],
                                    capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "exit_code": 124, "language": "cpp"}
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    return {"status": "CPP_CHECKED" if result.returncode == 0 else "CPP_CHECK_FAILED",
            "exit_code": result.returncode, "language": "cpp", "output": output[-8000:]}
