"""Polyglot verify-refactor gate: rust/c/cpp contract preservation."""
from __future__ import annotations

from unittest.mock import patch

from pipeline.refactor_gate import verify_contract_preserving_refactor

RUST_BASE = """#[requires(value >= 0)]
#[ensures(result >= 0)]
pub fn process(value: i32) -> i32 {
    let mut acc = value;
    acc = acc + 1;
    acc
}
"""

RUST_REFACTORED = """#[requires(value >= 0)]
#[ensures(result >= 0)]
pub fn process(value: i32) -> i32 {
    value + 1
}
"""

C_BASE = """/*@ requires 0 <= index < 10; */
/*@ ensures \\result >= 0; */
int get(int *arr, int index) {
    int v = arr[index];
    return v;
}
"""

C_REFACTORED = """/*@ requires 0 <= index < 10; */
/*@ ensures \\result >= 0; */
int get(int *arr, int index) {
    return arr[index];
}
"""

CPP_BASE = """class Counter {
public:
    Counter() : count_(0) {}
    void increment() {
        if (count_ < 5) { count_ = count_ + 1; }
        assert(count_ >= 0 && count_ <= 5);
    }
private:
    int count_;
};
"""

CPP_REFACTORED = """class Counter {
public:
    Counter() : count_(0) {}
    void increment() {
        count_ = (count_ < 5) ? count_ + 1 : count_;
        assert(count_ >= 0 && count_ <= 5);
    }
private:
    int count_;
};
"""

_VERIFIED = {"status": "VERIFIED", "claim": "whatever", "output": "proved"}


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_rust_refactor_mints_contract_preserved(tmp_path):
    baseline = _write(tmp_path, "lib.rs", RUST_BASE)
    refactored = _write(tmp_path, "lib_refactored.rs", RUST_REFACTORED)
    with patch("pipeline.verify_rust.verify_rust", return_value=dict(_VERIFIED)):
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert result["language"] == "rust"
    assert result["verifier"] == "prusti"
    assert result["baseline_deductive_proof"] is True
    assert result["behavior_equivalence_proved"] is False


def test_c_refactor_mints_contract_preserved(tmp_path):
    baseline = _write(tmp_path, "counter.c", C_BASE)
    refactored = _write(tmp_path, "counter_refactored.c", C_REFACTORED)
    with patch("pipeline.verify_c.verify_c", return_value=dict(_VERIFIED)):
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert result["verifier"] == "frama-c-wp"


def test_cpp_refactor_ceiling_is_bounded(tmp_path):
    baseline = _write(tmp_path, "counter.cpp", CPP_BASE)
    refactored = _write(tmp_path, "counter_refactored.cpp", CPP_REFACTORED)
    with patch("pipeline.verify_cpp.verify_cpp",
               return_value={"status": "VERIFIED", "claim": "BOUNDED_CPP_PROOF",
                             "output": "VERIFICATION SUCCESSFUL", "vcs": []}):
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["claim"] == "BOUNDED_REFACTOR_CONTRACT_PRESERVED"
    assert result["baseline_deductive_proof"] is False  # bounded prover, not deductive
    assert result["contract_surface_preserved"] is True


def test_user_test_3_3_pub_to_private_fails_closed(tmp_path):
    demoted = RUST_REFACTORED.replace("pub fn process", "fn process")
    baseline = _write(tmp_path, "lib.rs", RUST_BASE)
    refactored = _write(tmp_path, "lib_refactored.rs", demoted)
    result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["status"] == "FAIL"
    assert result["code"] == "method_surface_changed"


def test_contract_clause_change_fails_closed(tmp_path):
    weakened = RUST_REFACTORED.replace("#[ensures(result >= 0)]", "#[ensures(result >= 1)]")
    baseline = _write(tmp_path, "lib.rs", RUST_BASE)
    refactored = _write(tmp_path, "lib_refactored.rs", weakened)
    result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "contract_surface_changed"


def test_failed_native_verification_fails_closed(tmp_path):
    baseline = _write(tmp_path, "lib.rs", RUST_BASE)
    refactored = _write(tmp_path, "lib_refactored.rs", RUST_REFACTORED)
    with patch("pipeline.verify_rust.verify_rust",
               side_effect=[dict(_VERIFIED),
                            {"status": "VERIFY_FAILED", "output": "postcondition failed"}]):
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "refactored_not_verified"


def test_mixed_languages_and_unchanged_source_fail_closed(tmp_path):
    baseline = _write(tmp_path, "lib.rs", RUST_BASE)
    java = _write(tmp_path, "Lib.java", "public class Lib {}")
    assert verify_contract_preserving_refactor(
        baseline, java)["code"] == "unsupported_language"

    identical = _write(tmp_path, "copy.rs", RUST_BASE)
    with patch("pipeline.verify_rust.verify_rust", return_value=dict(_VERIFIED)):
        result = verify_contract_preserving_refactor(baseline, identical)
    assert result["code"] == "source_unchanged"


def test_missing_contract_and_baseline_verification_failure(tmp_path):
    baseline = _write(tmp_path, "bare.rs", "pub fn process(value: i32) -> i32 { value }")
    refactored = _write(tmp_path, "bare_refactored.rs",
                        "pub fn process(value: i32) -> i32 { value + 0 }")
    result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "missing_trusted_contract"

    base = _write(tmp_path, "lib.rs", RUST_BASE)
    good = _write(tmp_path, "lib_refactored.rs", RUST_REFACTORED)
    with patch("pipeline.verify_rust.verify_rust",
               return_value={"status": "VERIFY_FAILED", "output": "assertion failed"}):
        result = verify_contract_preserving_refactor(base, good)
    assert result["code"] == "baseline_not_verified"
