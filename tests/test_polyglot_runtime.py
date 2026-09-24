# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pipeline import polyglot_runtime as runtime
from pipeline.llm import LLMError
from pipeline.execution import ExecutionObservation


RUST = "pub fn add(a: i32, b: i32) -> i32 { a + b }"
C = "int add(int a, int b) { return a + b; }"


def observation(status="COMPLETED", exit_code=0, output="", compliance="ENFORCED"):
    return ExecutionObservation(
        status=status, exit_code=exit_code, output=output,
        requested_policy={"network": "denied"},
        enforced_policy={"network": "denied"} if compliance == "ENFORCED" else None,
        policy_compliance=compliance, snapshot_manifest_sha256="digest",
        timed_out=status == "TIMEOUT", message=output)


class SequenceExecutor:
    def __init__(self, *values):
        self.values = iter(values)
        self.calls = []

    def execute(self, request):
        self.calls.append(request)
        return next(self.values)


def test_rust_runtime_sample_compiles_tests_with_overflow_checks():
    executor = SequenceExecutor(observation(
        output="FORMALSPEC_PHASE:runtime\nFORMALSPEC_INPUT: a=1,b=2\ntest result: ok"))
    with patch.object(runtime.shutil, "which", return_value="/bin/rustc"):
        result = runtime.collect_polyglot_runtime_evidence(
            RUST, "rust", test_code="#[test] fn sample() { assert_eq!(add(1,2),3); }",
            executor=executor)
    assert result["status"] == "NO_RUNTIME_FAILURE_FOUND"
    assert result["claim"] == "RUNTIME_SAMPLE" and not result["proof"]
    assert result["inputs"] == ["a=1,b=2"]
    assert executor.calls[0].tool == "rust-runtime-pipeline"
    assert "--test" in executor.calls[0].command[2]
    assert "overflow-checks=yes" in executor.calls[0].command[2]


def test_c_runtime_failure_is_counterexample_evidence_under_sanitizers():
    executor = SequenceExecutor(observation(
        "TOOL_FAILED", 1, "FORMALSPECGEN_PHASE:runtime\nruntime error: signed overflow"))
    with patch.object(runtime.shutil, "which", return_value="/bin/gcc"):
        result = runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="int main(void) { return add(1,2) != 3; }",
            executor=executor)
    assert result["status"] == "RUNTIME_FAILURES_FOUND"
    assert result["claim"] == "COUNTEREXAMPLE_EVIDENCE"
    assert result["regeneration_recommended"]
    assert "-fsanitize=address,undefined" in executor.calls[0].command[2]


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
    with patch.object(runtime.shutil, "which", return_value="/usr/bin/cc"):
        assert runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="x", executor=SequenceExecutor(
                observation("TOOL_FAILED", 1,
                            "bad\nFORMALSPECGEN_PHASE:compile")))["status"] == \
            "TEST_COMPILE_FAILED"
    with patch.object(runtime.shutil, "which", return_value="/usr/bin/cc"):
        assert runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="x", executor=SequenceExecutor(
                observation("TIMEOUT", 124, "timed out")))["status"] == "TIMEOUT"
    with patch.object(runtime.shutil, "which", return_value="/usr/bin/cc"):
        assert runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="x", executor=SequenceExecutor(
                observation("TOOL_ERROR", 127, "cannot execute")))["status"] == "TOOL_ERROR"
    with pytest.raises(ValueError, match="rust, c, or cpp"):
        runtime.collect_polyglot_runtime_evidence("", "java", test_code="")


CPP = """class Adder {
public:
    int add(int a, int b) { return a + b; }
};
"""


def test_cpp_runtime_sample_compiles_under_sanitizers():
    executor = SequenceExecutor(observation(
        output="FORMALSPECGEN_PHASE:runtime\nFORMALSPEC_INPUT: a=1,b=2\nall asserts passed"))
    with patch.object(runtime.shutil, "which", return_value="/bin/g++"):
        result = runtime.collect_polyglot_runtime_evidence(
            CPP, "cpp",
            test_code="#include <cassert>\nint main() { Adder a; assert(a.add(1,2) == 3); }",
            executor=executor)
    assert result["status"] == "NO_RUNTIME_FAILURE_FOUND"
    assert result["claim"] == "RUNTIME_SAMPLE" and not result["proof"]
    assert result["instrumentation"] == "ASan+UBSan (g++)"
    assert executor.calls[0].command[:2] == ("/bin/sh", "-c")
    assert "g++" in executor.calls[0].command[2]
    assert "-std=c++17" in executor.calls[0].command[2]
    assert "-fsanitize=address,undefined" in executor.calls[0].command[2]


def test_cpp_runtime_failure_is_counterexample_evidence():
    executor = SequenceExecutor(observation(
        "TOOL_FAILED", 1,
        "FORMALSPECGEN_PHASE:runtime\nruntime error: signed integer overflow"))
    with patch.object(runtime.shutil, "which", return_value="/bin/g++"):
        result = runtime.collect_polyglot_runtime_evidence(
            CPP, "cpp", test_code="int main() { return 0; }", executor=executor)
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


def test_default_runtime_path_fails_closed_when_sandbox_is_unavailable():
    unavailable = ExecutionObservation(
        status="SANDBOX_UNAVAILABLE", exit_code=125, output="",
        requested_policy={}, enforced_policy=None, policy_compliance="NOT_ENFORCED",
        snapshot_manifest_sha256="digest", message="namespace denied")
    executor = SimpleNamespace(execute=lambda _request: unavailable)
    with patch.object(runtime.shutil, "which", return_value="/usr/bin/gcc"):
        result = runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="int main(void) { return 0; }", executor=executor)
    assert result["status"] == "SANDBOX_UNAVAILABLE"
    assert result["claim"] == "NO_PROOF"
    assert result["execution_policy_compliance"] == "NOT_ENFORCED"


def test_default_runtime_path_records_enforced_compile_and_execution():
    def observation(status="COMPLETED", exit_code=0, output=""):
        return ExecutionObservation(
            status=status, exit_code=exit_code, output=output,
            requested_policy={"network": "denied"},
            enforced_policy={"network": "denied"}, policy_compliance="ENFORCED",
            snapshot_manifest_sha256="digest")

    calls = []
    values = iter([observation(
        output="FORMALSPECGEN_PHASE:runtime\nFORMALSPEC_INPUT: x=1\nall assertions passed")])
    executor = SimpleNamespace(execute=lambda request: (calls.append(request), next(values))[1])
    with patch.object(runtime.shutil, "which", return_value="/usr/bin/gcc"):
        result = runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="int main(void) { return 0; }", executor=executor)
    assert result["status"] == "NO_RUNTIME_FAILURE_FOUND"
    assert result["execution_policy_compliance"] == "ENFORCED"
    assert len(calls) == 1 and calls[0].tool == "c-runtime-pipeline"
    assert calls[0].command[:2] == ("/bin/sh", "-c")
    assert "exec /work/runtime_sample" in calls[0].command[2]

    values = iter([observation("OUTPUT_LIMIT_EXCEEDED", 126, "partial")])
    executor = SimpleNamespace(execute=lambda _request: next(values))
    with patch.object(runtime.shutil, "which", return_value="/usr/bin/gcc"):
        limited = runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="int main(void) { return 0; }", executor=executor)
    assert limited["status"] == "OUTPUT_LIMIT_EXCEEDED"
    assert limited["claim"] == "NO_PROOF"


def test_sanitizer_initialization_failure_is_not_counterexample_evidence():
    executor = SequenceExecutor(observation(
        "TOOL_FAILED", 1,
        "FORMALSPECGEN_PHASE:runtime\nAddressSanitizer failed to allocate shadow memory"))
    with patch.object(runtime.shutil, "which", return_value="/usr/bin/gcc"):
        result = runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="int main(void) { return 0; }", executor=executor)
    assert result["status"] == "TOOL_INITIALIZATION_FAILED"
    assert result["claim"] == "NO_PROOF"
    assert result["regeneration_recommended"] is False


def test_actual_sanitizer_diagnostic_is_counterexample_evidence():
    executor = SequenceExecutor(observation(
        "TOOL_FAILED", 1,
        "FORMALSPECGEN_PHASE:runtime\nERROR: AddressSanitizer: heap-buffer-overflow"))
    with patch.object(runtime.shutil, "which", return_value="/usr/bin/gcc"):
        result = runtime.collect_polyglot_runtime_evidence(
            C, "c", test_code="int main(void) { return 0; }", executor=executor)
    assert result["status"] == "RUNTIME_FAILURES_FOUND"
    assert result["claim"] == "COUNTEREXAMPLE_EVIDENCE"
