# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Cheap Rust/C execution gates that produce samples or concrete failures, never proof."""
from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path

from . import config
from .execution import ExecutionPolicy, ExecutionRequest, SourceSnapshot, StrictSandboxExecutor
from .llm import LLMError, _chat_fn
from .rust_support import _PRUSTI_ATTRIBUTE

_FENCE = {
    "rust": re.compile(r"```rust\s*\n(.*?)```", re.I | re.S),
    "c": re.compile(r"```c\s*\n(.*?)```", re.I | re.S),
    "cpp": re.compile(r"```cpp\s*\n(.*?)```", re.I | re.S),
}

_PROMPTS = {
    "rust": """Generate only a Rust #[cfg(test)] module for the public API below. Use deterministic
boundary examples satisfying #[requires]. Do not use unsafe, external crates, randomness, ignored
tests, or change production code. Print FORMALSPEC_INPUT: before each case. Return one rust fence.""",
    "c": """Generate only a bounded C11 test harness with int main(void) for the public API below.
Use deterministic boundary examples satisfying ACSL requires. Use assert, no dynamic allocation,
randomness, threads, or production-code changes. Print FORMALSPEC_INPUT: before each case. Return
one c fence.""",
    "cpp": """Generate only a bounded C++17 test harness with int main() for the public API below.
Use deterministic boundary examples satisfying the assertion guards. Use assert from <cassert>, no
dynamic allocation, no std::string, no exceptions with message strings, no randomness, threads, or
production-code changes — string operations burn the sanitizer budget and hide the boundary
obligations. Print FORMALSPEC_INPUT: before each case. Return one cpp fence.""",
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
                                      executor=None) -> dict:
    """Compile and execute generated tests under native safety instrumentation."""
    if language not in {"rust", "c", "cpp"}:
        raise ValueError("runtime evidence language must be rust, c, or cpp")
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
            filename = "runtime_sample.rs"
            assembled = production + "\n" + test_code
            sandbox_compile = [compiler, "--edition", "2021", "--test", "-C",
                               "overflow-checks=yes", f"/input/{filename}",
                               "-o", "/work/runtime_sample"]
        else:
            compiler = shutil.which("g++" if language == "cpp" else config.CC_BIN)
            if not compiler:
                return _result("TOOL_MISSING", 127,
                               f"{'C++' if language == 'cpp' else 'C'} compiler not found", model)
            suffix = ".cpp" if language == "cpp" else ".c"
            standard = "-std=c++17" if language == "cpp" else "-std=c11"
            filename = f"runtime_sample{suffix}"
            assembled = code + "\n" + test_code
            flags = [standard, "-Wall", "-Wextra", "-Werror",
                     "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
            sandbox_compile = [compiler, *flags, f"/input/{filename}",
                               "-o", "/work/runtime_sample"]
        snapshot = SourceSnapshot.create(root / "snapshot", {filename: assembled})
        workspace = root / "workspace"
        workspace.mkdir()
        policy = ExecutionPolicy(timeout_s=float(config.RAC_TIMEOUT))
        strict = executor or StrictSandboxExecutor()
        compiled = strict.execute(ExecutionRequest(
            tool=f"{language}-compiler", command=tuple(sandbox_compile),
            snapshot=snapshot, workspace=workspace, policy=policy,
            readonly_paths=(Path(compiler).resolve().parent,)))
        if compiled.status != "COMPLETED":
            compile_status = ("TEST_COMPILE_FAILED" if compiled.status == "TOOL_FAILED"
                              else compiled.status)
            return _result(compile_status, compiled.exit_code,
                           compiled.output or compiled.message, model, test_code,
                           snapshot=snapshot, compliance=compiled.policy_compliance,
                           execution=compiled.as_dict())
        executed = strict.execute(ExecutionRequest(
            tool=f"{language}-runtime-sample", command=("/work/runtime_sample",),
            snapshot=snapshot, workspace=workspace, policy=policy))
        if executed.status not in {"COMPLETED", "TOOL_FAILED"}:
            return _result(executed.status, executed.exit_code,
                           executed.output or executed.message, model, test_code,
                           snapshot=snapshot, compliance=executed.policy_compliance,
                           execution=executed.as_dict())
        output = executed.output
        executed_returncode = executed.exit_code
        execution_details = executed.as_dict()
    inputs = re.findall(r"FORMALSPEC_INPUT:\s*(.+)", output)
    failed = executed_returncode != 0 or bool(re.search(
        r"AddressSanitizer|runtime error:|panicked at|test result: FAILED|assertion failed", output, re.I))
    return {"status": "RUNTIME_FAILURES_FOUND" if failed else "NO_RUNTIME_FAILURE_FOUND",
            "exit_code": executed_returncode, "inputs": inputs, "log": output[-6000:],
            "test_code": test_code, "model": model,
            "claim": "COUNTEREXAMPLE_EVIDENCE" if failed else "RUNTIME_SAMPLE",
            "proof": False, "regeneration_recommended": failed,
            "source_snapshot": {"manifest_sha256": snapshot.manifest_sha256,
                                "files": list(snapshot.manifest)},
            "execution_policy_compliance": execution_details.get(
                "policy_compliance", "NOT_ENFORCED"),
            "execution": execution_details,
            "instrumentation": ("rustc --test with overflow checks" if language == "rust" else
                                "ASan+UBSan (g++)" if language == "cpp" else
                                "ASan+UBSan"),
            "disclaimer": "Runtime samples can expose failures; passing samples are not proof."}


def _result(status: str, exit_code: int, log: str, model: str = "unavailable",
            test_code: str = "", *, snapshot: SourceSnapshot | None = None,
            compliance: str = "NOT_ENFORCED", execution: dict | None = None) -> dict:
    return {"status": status, "exit_code": exit_code, "inputs": [], "log": log[-6000:],
            "test_code": test_code, "model": model, "claim": "NO_PROOF", "proof": False,
            "regeneration_recommended": status == "RUNTIME_FAILURES_FOUND",
            "source_snapshot": ({"manifest_sha256": snapshot.manifest_sha256,
                                 "files": list(snapshot.manifest)} if snapshot else None),
            "execution_policy_compliance": compliance,
            "execution": execution or {}}
