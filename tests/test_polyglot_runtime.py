# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pipeline import polyglot_runtime as runtime
from pipeline.llm import LLMError


RUST = "pub fn add(a: i32, b: i32) -> i32 { a + b }"
C = "int add(int a, int b) { return a + b; }"


def process(code=0, out="", err=""):
    return SimpleNamespace(returncode=code, stdout=out, stderr=err)


def test_rust_runtime_sample_compiles_tests_with_overflow_checks():
    seen = []
    def run(command, **_kwargs):
        seen.append(command)
        return process(0, "FORMALSPEC_INPUT: a=1,b=2\ntest result: ok")
    with patch.object(runtime.shutil, "which", return_value="/bin/rustc"):
        result = runtime.collect_polyglot_runtime_evidence(
            RUST, "rust", test_code="#[test] fn sample() { assert_eq!(add(1,2),3); }", runner=run)
    assert result["status"] == "NO_RUNTIME_FAILURE_FOUND"
    assert result["claim"] == "RUNTIME_SAMPLE" and not result["proof"]
    assert result["inputs"] == ["a=1,b=2"]
    assert "--test" in seen[0] and "overflow-checks=yes" in seen[0]


def test_c_runtime_failure_is_counterexample_evidence_under_sanitizers():
    calls = []
    def run(command, **_kwargs):
        calls.append(command)
        return process() if len(calls) == 1 else process(1, err="runtime error: signed overflow")
    with patch.object(runtime.shutil, "which", return_value="/bin/gcc"):
        result = runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="int main(void) { return add(1,2) != 3; }", runner=run)
    assert result["status"] == "RUNTIME_FAILURES_FOUND"
    assert result["claim"] == "COUNTEREXAMPLE_EVIDENCE"
    assert result["regeneration_recommended"]
    assert "-fsanitize=address,undefined" in calls[0]


def test_runtime_gate_reports_testgen_compile_tool_and_timeout_failures():
    with patch.object(runtime, "_chat_fn", return_value=lambda *_: ("no fence", "m", {})):
        assert runtime.collect_polyglot_runtime_evidence(RUST, "rust")["status"] == "TESTGEN_FAILED"
    with patch.object(runtime, "_chat_fn", return_value=lambda *_: (_ for _ in ()).throw(
            LLMError("API", "offline"))):
        assert runtime.collect_polyglot_runtime_evidence(C, "c")["status"] == "TESTGEN_FAILED"
    with patch.object(runtime.shutil, "which", return_value=None):
        assert runtime.collect_polyglot_runtime_evidence(
            RUST, "rust", test_code="x")["status"] == "TOOL_MISSING"
        assert runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="x")["status"] == "TOOL_MISSING"
    with patch.object(runtime.shutil, "which", return_value="cc"):
        assert runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="x", runner=lambda *_a, **_k: process(1, err="bad"))[
                "status"] == "TEST_COMPILE_FAILED"
    with patch.object(runtime.shutil, "which", return_value="cc"):
        assert runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="x", runner=lambda *_a, **_k: (_ for _ in ()).throw(
                subprocess.TimeoutExpired("cc", 1)))["status"] == "TIMEOUT"
    with patch.object(runtime.shutil, "which", return_value="cc"):
        assert runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="x", runner=lambda *_a, **_k: (_ for _ in ()).throw(
                OSError("cannot execute")))["status"] == "TOOL_ERROR"
    with pytest.raises(ValueError, match="rust, c, or cpp"):
        runtime.collect_polyglot_runtime_evidence("", "java", test_code="")


CPP = """class Adder {
public:
    int add(int a, int b) { return a + b; }
};
"""


def test_cpp_runtime_sample_compiles_under_sanitizers():
    seen = []
    def run(command, **_kwargs):
        seen.append(command)
        return process(0, "FORMALSPEC_INPUT: a=1,b=2\nall asserts passed")
    with patch.object(runtime.shutil, "which", return_value="/bin/g++"):
        result = runtime.collect_polyglot_runtime_evidence(
            CPP, "cpp",
            test_code="#include <cassert>\nint main() { Adder a; assert(a.add(1,2) == 3); }",
            runner=run)
    assert result["status"] == "NO_RUNTIME_FAILURE_FOUND"
    assert result["claim"] == "RUNTIME_SAMPLE" and not result["proof"]
    assert result["instrumentation"] == "ASan+UBSan (g++)"
    assert seen[0][0].endswith("g++") and "-std=c++17" in seen[0]
    assert "-fsanitize=address,undefined" in seen[0]


def test_cpp_runtime_failure_is_counterexample_evidence():
    calls = []
    def run(command, **_kwargs):
        calls.append(command)
        return process() if len(calls) == 1 else process(1, err="runtime error: signed integer overflow")
    with patch.object(runtime.shutil, "which", return_value="/bin/g++"):
        result = runtime.collect_polyglot_runtime_evidence(
            CPP, "cpp", test_code="int main() { return 0; }", runner=run)
    assert result["status"] == "RUNTIME_FAILURES_FOUND"
    assert result["claim"] == "COUNTEREXAMPLE_EVIDENCE"
    assert result["regeneration_recommended"]


def test_cpp_test_generation_accepts_exact_language_fence():
    with patch.object(runtime, "_chat_fn", return_value=lambda *_: (
            "```cpp\n#include <cassert>\nint main() {}\n```", "model", {})):
        code, model = runtime._generate_tests(CPP, "cpp", "ollama")
    assert code.startswith("#include <cassert>") and model == "model"


def test_runtime_test_generation_accepts_exact_language_fence():
    with patch.object(runtime, "_chat_fn", return_value=lambda *_: (
            "```rust\n#[test] fn sample() {}\n```", "model", {})):
        code, model = runtime._generate_tests(RUST, "rust", "ollama")
    assert code == "#[test] fn sample() {}\n" and model == "model"
