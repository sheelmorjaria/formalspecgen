"""E2E: polyglot verify-refactor with the REAL Prusti and Frama-C provers."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import cli
from pipeline.refactor_gate import verify_contract_preserving_refactor

pytestmark = pytest.mark.toolchain

REPO_ROOT = Path(__file__).resolve().parents[1]

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

RUST_REFACTORED = """#![allow(unused_imports)]
use prusti_contracts::*;
#[requires(value >= 0 && value < 1000000)]
#[ensures(result >= 1)]
pub fn process(value: i32) -> i32 {
    value + 1
}
"""


def _esbmc_available() -> bool:
    import shutil
    return shutil.which("esbmc") is not None


def test_rust_identity_gate_with_real_prusti(tmp_path, prusti_tool=None):
    """Contract-preserving refactor over real Prusti: same surface, simpler body."""
    try:
        from pipeline.config import PRUSTI_BIN
        if not Path(PRUSTI_BIN).exists():
            pytest.skip(f"Prusti unavailable: {PRUSTI_BIN}")
    except Exception:
        pytest.skip("Prusti unavailable")

    baseline = tmp_path / "lib.rs"
    baseline.write_text(RUST_BASE, encoding="utf-8")
    refactored = tmp_path / "lib_refactored.rs"
    refactored.write_text(RUST_REFACTORED, encoding="utf-8")
    result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["status"] == "VERIFIED", json.dumps(result, default=str)[:600]
    assert result["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert result["verifier"] == "prusti"


def test_c_identity_gate_with_real_frama_c(tmp_path):
    """Contract-preserving refactor over real Frama-C WP on the canonical bounded counter."""
    try:
        from pipeline.config import FRAMAC_BIN
        if not Path(FRAMAC_BIN).exists():
            pytest.skip(f"Frama-C unavailable: {FRAMAC_BIN}")
    except Exception:
        pytest.skip("Frama-C unavailable")

    from pipeline.v2_acsl_serializer import render_reviewed_v2_acsl_file
    reviewed = REPO_ROOT / "domains" / "v2" / "bounded_counter.json"
    if not reviewed.exists():
        pytest.skip("canonical bounded_counter reviewed domain missing")
    _, code = render_reviewed_v2_acsl_file(reviewed)

    baseline = tmp_path / "bounded_counter.c"
    baseline.write_text(code, encoding="utf-8")
    # Identity-with-whitespace-change satisfies "changed source" while the
    # contract/API surfaces remain identical; both revisions re-prove with WP.
    refactored = tmp_path / "bounded_counter_refactored.c"
    refactored.write_text(code + "\n/* refactored: comment-only change */\n",
                          encoding="utf-8")
    result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["status"] == "VERIFIED", json.dumps(result, default=str)[:600]
    assert result["verifier"] == "frama-c-wp"
