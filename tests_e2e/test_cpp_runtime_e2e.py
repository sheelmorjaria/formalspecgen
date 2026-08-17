"""M19: real-g++ runtime samples for the C++ standard assurance profile.

The generated-test loop existed for Rust (rustc --test + overflow checks)
and C (ASan/UBSan); C++ crashed on an unsupported-language ValueError. This
e2e proves the closed loop end to end with a real compiler: the sanitized
binary executes, a passing sample mints RUNTIME_SAMPLE, and a real
sanitizer abort mints COUNTEREXAMPLE_EVIDENCE.
"""
from __future__ import annotations

import shutil

import pytest

from pipeline.polyglot_runtime import collect_polyglot_runtime_evidence


CPP_COUNTER = """#include <cassert>

class Counter {
public:
    int count;
    Counter() : count(0) {}
    void increment() {
        assert(count >= 0);
        count = count + 1;
    }
    int value() const { return count; }
};
"""

CPP_PASSING_HARNESS = """#include <cstdio>

int main() {
    Counter counter;
    std::printf("FORMALSPEC_INPUT: increments=3\\n");
    counter.increment();
    counter.increment();
    counter.increment();
    if (counter.value() != 3) { return 1; }
    return 0;
}
"""

# A genuine out-of-bounds read under the pointer the production API hands
# out: ASan aborts the sanitized binary, which the lane must classify as
# counterexample evidence, not as a passing sample.
CPP_FAILING_HARNESS = """int main() {
    Counter counter;
    int *held = &counter.count;
    int *past_end = held + 1;
    return *past_end;   // ASan: heap/stack-buffer-overflow read
}
"""


def _gpp_available() -> bool:
    return shutil.which("g++") is not None


def test_cpp_runtime_sample_with_real_gpp(tmp_path):
    if not _gpp_available():
        pytest.skip("g++ unavailable")
    result = collect_polyglot_runtime_evidence(
        CPP_COUNTER, "cpp", test_code=CPP_PASSING_HARNESS)
    assert result["status"] == "NO_RUNTIME_FAILURE_FOUND", result["log"][-800:]
    assert result["claim"] == "RUNTIME_SAMPLE" and not result["proof"]
    assert result["inputs"] == ["increments=3"]
    assert result["instrumentation"] == "ASan+UBSan (g++)"


def test_cpp_sanitizer_abort_is_counterexample_evidence(tmp_path):
    if not _gpp_available():
        pytest.skip("g++ unavailable")
    result = collect_polyglot_runtime_evidence(
        CPP_COUNTER, "cpp", test_code=CPP_FAILING_HARNESS)
    assert result["status"] == "RUNTIME_FAILURES_FOUND"
    assert result["claim"] == "COUNTEREXAMPLE_EVIDENCE"
    assert result["regeneration_recommended"]
    assert "AddressSanitizer" in result["log"]
