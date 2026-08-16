"""E2E: polyglot extract-method splicing judged by the REAL Prusti and Frama-C provers."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.polyglot_extract_method import apply_extract_method_polyglot

pytestmark = pytest.mark.toolchain

# Overflow-safe contracts (i32/INT arithmetic must stay in bounds or the
# native provers correctly reject the VC).
RUST_BASE = """#![allow(unused_imports)]
use prusti_contracts::*;

#[requires(value >= 0 && value < 1000000)]
#[ensures(result >= 1)]
pub fn process(value: i32) -> i32 {
    let mut acc = value;
    acc = acc + 1;
    acc
}
"""

C_BASE = """/*@
  requires \\valid(count);
  requires 0 <= *count <= 1000000;
  requires 0 <= val <= 1000000;
  assigns *count;
  ensures *count == \\old(*count) + val;
*/
void add(int* count, int val) {
    *count += val;
}
"""

CPP_BASE = """#include <cassert>

class Counter {
public:
    int count;
    void add(int val) {
        assert(val >= 0);
        count += val;
    }
};

int main() {
    Counter c{0};
    c.add(3);
    assert(c.count == 3);
    return 0;
}
"""


def _skip_unless(tool: str, binary: str) -> None:
    try:
        from pipeline import config
        candidate = getattr(config, binary)
        if not candidate or not Path(candidate).exists():
            pytest.skip(f"{tool} unavailable: {candidate}")
    except Exception:
        pytest.skip(f"{tool} unavailable")


def test_rust_extract_method_proves_with_real_prusti(tmp_path):
    _skip_unless("Prusti", "PRUSTI_BIN")
    baseline = tmp_path / "lib.rs"
    baseline.write_text(RUST_BASE, encoding="utf-8")
    result = apply_extract_method_polyglot(baseline, "process",
                                           tmp_path / "lib_refactored.rs")
    assert result["status"] == "VERIFIED", json.dumps(result, default=str)[:1200]
    assert result["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert result["verification"]["verifier"] == "prusti"
    refactored = (tmp_path / "lib_refactored.rs").read_text(encoding="utf-8")
    assert "fn process_helper(value: i32) -> i32 {" in refactored
    assert "pub fn process(value: i32) -> i32 { process_helper(value) }" in refactored


def test_c_extract_method_proves_with_real_frama_c(tmp_path):
    _skip_unless("Frama-C", "FRAMAC_BIN")
    baseline = tmp_path / "add.c"
    baseline.write_text(C_BASE, encoding="utf-8")
    result = apply_extract_method_polyglot(baseline, "add", tmp_path / "add_ref.c")
    assert result["status"] == "VERIFIED", json.dumps(result, default=str)[:1200]
    assert result["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert result["verification"]["verifier"] == "frama-c-wp"
    refactored = (tmp_path / "add_ref.c").read_text(encoding="utf-8")
    assert "static void add_helper(int* count, int val) {" in refactored
    assert refactored.count("/*@") == 2  # contract on helper AND wrapper


def test_cpp_extract_method_proves_with_real_esbmc(tmp_path):
    import shutil
    if shutil.which("esbmc") is None:
        pytest.skip("esbmc unavailable")
    baseline = tmp_path / "counter.cpp"
    baseline.write_text(CPP_BASE, encoding="utf-8")
    result = apply_extract_method_polyglot(baseline, "add",
                                           tmp_path / "counter_ref.cpp")
    assert result["status"] == "VERIFIED", json.dumps(result, default=str)[:1200]
    assert result["claim"] == "BOUNDED_REFACTOR_CONTRACT_PRESERVED"
    refactored = (tmp_path / "counter_ref.cpp").read_text(encoding="utf-8")
    assert "void add_helper(int val) {" in refactored
    assert "void add(int val) { add_helper(val); }" in refactored
