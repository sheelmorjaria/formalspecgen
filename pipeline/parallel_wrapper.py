# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic immutable Rayon wrapper and scoped partition evidence."""
from __future__ import annotations

import hashlib
import json
import re
import os
import subprocess
import tempfile
from pathlib import Path


_SAFE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def render_rayon_wrapper(kernel_code: str, kernel_name: str) -> str:
    """Append one immutable element-wise Rayon map without altering the kernel."""
    if not _SAFE_NAME.fullmatch(kernel_name):
        raise ValueError("parallel kernel name must be a safe identifier")
    signature = re.compile(
        rf"(?m)^pub fn {re.escape(kernel_name)}\(value: i32\) -> i32\s*\{{")
    if len(signature.findall(kernel_code)) != 1:
        raise ValueError(
            "Rayon partition profile requires exactly one pub fn kernel(value: i32) -> i32")
    if re.search(r"(?m)^\s*(?:pub\s+)?static\s+(?:mut\s+)?", kernel_code):
        raise ValueError("parallel kernel profile forbids static state")
    prefix = "" if "use rayon::prelude::*;" in kernel_code else "use rayon::prelude::*;\n\n"
    wrapper = (
        "/// Applies the verified scalar kernel to an immutable partitioned input.\n"
        "pub fn process_parallel(data: &[i32]) -> Vec<i32> {\n"
        f"    data.par_iter().map(|value| {kernel_name}(*value)).collect()\n"
        "}\n")
    return prefix + kernel_code.rstrip() + "\n\n" + wrapper


def check_rayon_syntax(wrapped_code: str, timeout: int = 60) -> dict:
    """Compile the wrapper with cached Rayon after erasing Prusti-only syntax."""
    erased = re.sub(r"(?m)^\s*use\s+prusti_contracts::\*;\s*$", "", wrapped_code)
    erased = re.sub(r"(?m)^\s*#\[(?:requires|ensures|pure)\([^\n]*\)\]\s*$", "", erased)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text(
            '[package]\nname="formalspecgen-ci-rust-deps"\nversion="0.0.0"\n'
            'edition="2021"\n\n[dependencies]\nrayon="=1.11.0"\n'
            'tokio={version="=1.49.0",features=["sync"]}\n', encoding="utf-8")
        lockfile = Path(__file__).resolve().parents[1] / "ci" / "rust-deps" / "Cargo.lock"
        if lockfile.is_file():
            (root / "Cargo.lock").write_text(lockfile.read_text(encoding="utf-8"), encoding="utf-8")
        (root / "src" / "lib.rs").write_text(erased, encoding="utf-8")
        environment = dict(os.environ); environment["RUSTFLAGS"] = "-D warnings"
        try:
            process = subprocess.run(
                ["cargo", "check", "--locked", "--offline", "--quiet"], cwd=root,
                capture_output=True, text=True, timeout=timeout, env=environment)
        except FileNotFoundError:
            return {"status": "TOOL_MISSING", "exit_code": 127,
                    "message": "cargo is not installed"}
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "exit_code": 124,
                    "message": "offline Rayon check timed out"}
    output = ((process.stdout or "") + (process.stderr or "")).strip()
    return {"status": "RAYON_CHECKED" if process.returncode == 0 else "RAYON_CHECK_FAILED",
            "exit_code": process.returncode, "output": output[-8000:],
            "dependency": "rayon=1.11.0", "offline": True}


def parallel_partition_gate(kernel_code: str, wrapped_code: str, kernel_name: str, *,
                            kernel_deductive_proof: bool,
                            wrapper_compiled: bool) -> dict:
    """Bind an unchanged proved kernel to the one canonical immutable wrapper."""
    if not kernel_deductive_proof:
        return _fail("kernel_not_proved", "Sequential kernel lacks deductive proof evidence")
    if not wrapper_compiled:
        return _fail("wrapper_not_compiled", "Rayon wrapper lacks a successful native check")
    try:
        expected = render_rayon_wrapper(kernel_code, kernel_name)
    except ValueError as exc:
        return _fail("unsupported_kernel_boundary", str(exc))
    if wrapped_code != expected:
        return _fail("noncanonical_parallel_wrapper",
                     "Parallel source differs from deterministic Rayon lowering")
    body = {"scope": "immutable_elementwise_rayon_partition",
            "kernel_sha256": hashlib.sha256(kernel_code.encode()).hexdigest(),
            "wrapper_sha256": hashlib.sha256(wrapped_code.encode()).hexdigest(),
            "kernel": kernel_name,
            "obligations": [
                "input_is_shared_slice", "items_are_copied_i32",
                "output_is_fresh_collection", "kernel_source_unchanged"]}
    return {"status": "VERIFIED", "claim": "PARALLEL_PARTITION_VERIFIED",
            "scope": body["scope"], "partition_safety_proved": True,
            "kernel_deductive_proof": True, "parallel_scheduler_proved": False,
            "parallel_functional_equivalence_proved": False,
            "kernel_sha256": body["kernel_sha256"],
            "wrapper_sha256": body["wrapper_sha256"],
            "certificate_sha256": hashlib.sha256(json.dumps(
                body, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "obligations": [{"name": item, "status": "PROVED"}
                            for item in body["obligations"]]}


def _fail(code: str, message: str) -> dict:
    return {"status": "FAIL", "claim": "NO_PROOF", "code": code,
            "message": message, "partition_safety_proved": False,
            "parallel_scheduler_proved": False,
            "parallel_functional_equivalence_proved": False}
