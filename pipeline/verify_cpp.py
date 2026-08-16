# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""ESBMC adapter with explicitly bounded C++ evidence."""
from __future__ import annotations

import subprocess
import re
import tempfile
from pathlib import Path


def verify_cpp(file_path: str | Path, timeout: int = 180, unwind: int = 5) -> dict:
    path = Path(file_path)
    if not path.exists():
        return _run_esbmc(
            ["esbmc", str(path), "--unwind", str(unwind),
             "--memory-leak-check", "--force-malloc-success", "--z3"],
            timeout, language="cpp", unwind=unwind)
    source = path.read_text(encoding="utf-8")
    class_match = re.search(r"\bclass\s+([A-Za-z_]\w*)\s*\{", source)
    if class_match is None:
        # Preserve generic C++ verification for translation units that already
        # provide their own main entry point.
        return _run_esbmc(
            ["esbmc", str(path), "--unwind", str(unwind),
             "--memory-leak-check", "--force-malloc-success", "--z3"],
            timeout, language="cpp", unwind=unwind)
    class_name = class_match.group(1)
    # ESBMC is entry-point based.  Keep the generated class untouched and create
    # a small deterministic harness that exercises each public no-argument method
    # once, allowing constructor/method assertions to be checked.
    methods = re.findall(
        r"\b(?:void|bool|int|long|float|double|[A-Za-z_]\w*)\s+"
        r"([A-Za-z_]\w*)\s*\(\s*\)\s*\{", source)
    methods = [name for name in methods if name != "check_invariants"]
    try:
        with tempfile.TemporaryDirectory(prefix="formalspecgen-esbmc-") as directory:
            harness = Path(directory) / f"{class_name}_harness.cpp"
            calls = "\n".join(f"    object.{name}();" for name in methods)
            harness.write_text(
                f'#include "{path.resolve()}"\n\n'
                f"int main() {{\n    {class_name} object;\n{calls}\n    return 0;\n}}\n",
                encoding="utf-8",
            )
            command = ["esbmc", str(harness), "--unwind", str(unwind),
               "--memory-leak-check", "--force-malloc-success", "--z3"]
            return _run_esbmc(command, timeout, language="cpp", unwind=unwind)
    except OSError as exc:
        return {"status": "VERIFY_FAILED", "claim": "NO_PROOF", "language": "cpp",
                "exit_code": 2, "message": str(exc)}


def _run_esbmc(command: list[str], timeout: int, *, language: str, unwind: int = 5) -> dict:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {"status": "TOOL_MISSING", "claim": "NO_PROOF", "language": language,
                "exit_code": 127, "message": "ESBMC binary not found"}
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "claim": "NO_PROOF", "language": language,
                "exit_code": 124, "message": f"ESBMC timed out after {timeout}s"}
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    success = result.returncode == 0 and "verification successful" in output.lower()
    from .parse_esbmc import parse_esbmc_vcs
    vcs = [] if success else [vc.__dict__ for vc in parse_esbmc_vcs(output)]
    return {"status": "VERIFIED" if success else "VERIFY_FAILED",
            "claim": "BOUNDED_CPP_PROOF" if success else "NO_PROOF",
            "language": language, "exit_code": result.returncode,
            "vcs": vcs,
            "unbounded_loop_proved": False, "unwind": unwind, "output": output[-12000:]}
