# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Cheap Rust/C execution gates that produce samples or concrete failures, never proof."""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import config
from .llm import LLMError, _chat_fn
from .rust_support import _PRUSTI_ATTRIBUTE

_FENCE = {
    "rust": re.compile(r"```rust\s*\n(.*?)```", re.I | re.S),
    "c": re.compile(r"```c\s*\n(.*?)```", re.I | re.S),
}

_PROMPTS = {
    "rust": """Generate only a Rust #[cfg(test)] module for the public API below. Use deterministic
boundary examples satisfying #[requires]. Do not use unsafe, external crates, randomness, ignored
tests, or change production code. Print FORMALSPEC_INPUT: before each case. Return one rust fence.""",
    "c": """Generate only a bounded C11 test harness with int main(void) for the public API below.
Use deterministic boundary examples satisfying ACSL requires. Use assert, no dynamic allocation,
randomness, threads, or production-code changes. Print FORMALSPEC_INPUT: before each case. Return
one c fence.""",
}


def _generate_tests(code: str, language: str, provider: str) -> tuple[str, str]:
    raw, model, _usage = _chat_fn(provider)([
        {"role": "system", "content": _PROMPTS[language]},
        {"role": "user", "content": code},
    ], None, 0.0)
    match = _FENCE[language].search(raw)
    if not match:
        raise ValueError(f"test generator returned no {language} code fence")
    return match.group(1).strip() + "\n", model


def collect_polyglot_runtime_evidence(code: str, language: str, provider: str = "glm", *,
                                      test_code: str | None = None,
                                      runner=subprocess.run) -> dict:
    """Compile and execute generated tests under native safety instrumentation."""
    if language not in {"rust", "c"}:
        raise ValueError("runtime evidence language must be rust or c")
    model = "provided"
    if test_code is None:
        try:
            test_code, model = _generate_tests(code, language, provider)
        except (LLMError, ValueError) as exc:
            return _result("TESTGEN_FAILED", 2, str(exc), model="unavailable")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        if language == "rust":
            compiler = shutil.which(config.RUSTC_BIN)
            if not compiler:
                return _result("TOOL_MISSING", 127, f"Rust compiler not found: {config.RUSTC_BIN}", model)
            production = re.sub(r"(?m)^\s*use\s+prusti_contracts::\*;\s*$", "", code)
            production = _PRUSTI_ATTRIBUTE.sub("", production)
            source = root / "runtime_sample.rs"; executable = root / "runtime_sample"
            source.write_text(production + "\n" + test_code, encoding="utf-8")
            compile_command = [compiler, "--edition", "2021", "--test", "-C", "overflow-checks=yes",
                               str(source), "-o", str(executable)]
        else:
            compiler = shutil.which(config.CC_BIN)
            if not compiler:
                return _result("TOOL_MISSING", 127, f"C compiler not found: {config.CC_BIN}", model)
            source = root / "runtime_sample.c"; executable = root / "runtime_sample"
            source.write_text(code + "\n" + test_code, encoding="utf-8")
            compile_command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                               "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                               str(source), "-o", str(executable)]
        try:
            compiled = runner(compile_command, capture_output=True, text=True,
                              timeout=config.RAC_TIMEOUT)
            if compiled.returncode:
                return _result("TEST_COMPILE_FAILED", compiled.returncode,
                               _output(compiled), model, test_code)
            executed = runner([str(executable)], capture_output=True, text=True,
                              timeout=config.RAC_TIMEOUT)
        except subprocess.TimeoutExpired:
            return _result("TIMEOUT", 124, "runtime sample timed out", model, test_code)
        except OSError as exc:
            return _result("TOOL_ERROR", 127, str(exc), model, test_code)
    output = _output(executed)
    inputs = re.findall(r"FORMALSPEC_INPUT:\s*(.+)", output)
    failed = executed.returncode != 0 or bool(re.search(
        r"AddressSanitizer|runtime error:|panicked at|test result: FAILED|assertion failed", output, re.I))
    return {"status": "RUNTIME_FAILURES_FOUND" if failed else "NO_RUNTIME_FAILURE_FOUND",
            "exit_code": executed.returncode, "inputs": inputs, "log": output[-6000:],
            "test_code": test_code, "model": model,
            "claim": "COUNTEREXAMPLE_EVIDENCE" if failed else "RUNTIME_SAMPLE",
            "proof": False, "regeneration_recommended": failed,
            "instrumentation": ("rustc --test with overflow checks" if language == "rust" else
                                "ASan+UBSan"),
            "disclaimer": "Runtime samples can expose failures; passing samples are not proof."}


def _output(process) -> str:
    return ((process.stdout or "") + (process.stderr or "")).strip()


def _result(status: str, exit_code: int, log: str, model: str = "unavailable",
            test_code: str = "") -> dict:
    return {"status": status, "exit_code": exit_code, "inputs": [], "log": log[-6000:],
            "test_code": test_code, "model": model, "claim": "NO_PROOF", "proof": False,
            "regeneration_recommended": status == "RUNTIME_FAILURES_FOUND"}
