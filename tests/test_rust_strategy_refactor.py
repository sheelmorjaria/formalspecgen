# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M31: Rust strategy extraction on the probed static-dispatch shape.

Probed against real Prusti 0.2.2 BEFORE the transformer was written:
trait-object dispatch (&dyn / Box<dyn> / const-hoisted &dyn) is rejected as
loan-creating casts, and impl-block #[ensures] fails rustc E0407 — the
verified shape carries the contract on the trait METHOD DECLARATION with a
selecting enum forwarding to per-arm unit structs (6/6 items verified).
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from pipeline.rust_strategy_refactor import extract_strategy_rust

BASELINE = """use prusti_contracts::*;

pub struct Meter {
    pub price: i32,
}

impl Meter {
    #[ensures(self.price >= 100)]
    pub fn set_price(&mut self, kind: i32) {
        match kind {
            1 => self.price = 100,
            2 => self.price = 250,
            _ => self.price = 100,
        }
    }
}
"""

_VERIFIED = {"status": "VERIFIED", "output": "proved", "claim": "DEDUCTIVE_PROOF"}


def _prusti_installed() -> bool:
    from pipeline.rust_support import _prusti_binary
    return _prusti_binary() is not None


def test_transform_emits_trait_structs_enum_and_dispatch_call():
    """Test 3.1: trait + concrete implementations + dispatch call, with the
    original #[ensures] preserved on the delegating method."""
    result = extract_strategy_rust(BASELINE, "set_price")
    assert result["status"] == "TRANSFORMED", result
    code = result["source"]
    assert "pub trait SetPriceStrategy {" in code
    assert "#[ensures(t.price >= 100)]" in code          # contract on the trait method
    assert "impl SetPriceStrategy for SetPriceStrategy1 {" in code
    assert "t.price = 250;" in code                      # the arm literal moved
    assert "enum SelectedSetPriceStrategy {" in code
    assert "fn select_set_price(kind: i32) -> SelectedSetPriceStrategy {" in code
    assert "select_set_price(kind).apply(self);" in code  # the dispatch call
    assert "#[ensures(self.price >= 100)]" in code        # original attr survives
    # the value-mapping match is GONE from the method body
    method_body = code[code.index("pub fn set_price"):code.index("select_set_price(kind)")]
    assert "self.price = 250" not in method_body


def test_out_of_dialect_sources_fail_closed():
    """The narrow dialect is a boundary, not a preference."""
    refusals = {
        "strategy_contract_required":
            BASELINE.replace("    #[ensures(self.price >= 100)]\n", ""),
        "strategy_single_field_required":
            BASELINE.replace("_ => self.price = 100,", "_ => self.fee = 100,"),
        "strategy_catchall_required":
            BASELINE.replace("            _ => self.price = 100,\n", ""),
        "strategy_match_body_required":
            BASELINE.replace("match kind {", "self.price = 100;\n        match kind {"),
        "unsupported_method_shape":
            BASELINE.replace("kind: i32", "kind: i64"),
        "name_collision":
            BASELINE.replace("pub struct Meter", "pub struct SetPriceStrategy"),
    }
    for expected_code, source in refusals.items():
        verdict = extract_strategy_rust(source, "set_price")
        assert verdict["status"] == "FAIL", (expected_code, verdict)
        assert verdict["code"] == expected_code, (expected_code, verdict["code"])

    unprovable = extract_strategy_rust(
        BASELINE.replace(">= 100)]", ">= 200)]"), "set_price")
    assert unprovable["code"] == "strategy_contract_not_established"

    # locator passthrough + remaining dialect corners
    assert extract_strategy_rust(BASELINE, "nope")["code"] == "method_not_found"
    assert extract_strategy_rust(
        BASELINE.replace("1 => self.price = 100,", "1 => self.price = self.price + 1,"),
        "set_price")["code"] == "strategy_arm_shape_required"
    assert extract_strategy_rust(
        BASELINE.replace("2 => self.price = 250,", "1 => self.price = 250,"),
        "set_price")["code"] == "strategy_distinct_patterns_required"


def test_gate_accepts_added_trait_contract_but_not_dropped_clauses(tmp_path):
    """The subset gate: baseline clauses must survive verbatim; added clauses
    on new items (the trait method declaration) are permitted."""
    from pipeline.refactor_gate import verify_contract_preserving_refactor
    baseline = tmp_path / "meter.rs"
    baseline.write_text(BASELINE, encoding="utf-8")
    transformed = extract_strategy_rust(BASELINE, "set_price")
    refactored = tmp_path / "meter_strategy.rs"
    refactored.write_text(transformed["source"], encoding="utf-8")

    with patch("pipeline.refactor_gate._polyglot_verification",
               side_effect=[dict(_VERIFIED), dict(_VERIFIED)]):
        verdict = verify_contract_preserving_refactor(baseline, refactored)
    assert verdict["status"] == "VERIFIED", verdict
    assert verdict["claim"] == "REFACTOR_CONTRACT_PRESERVED"

    # A baseline clause that disappears is still a contract-surface change.
    dropped = tmp_path / "dropped.rs"
    dropped.write_text(BASELINE.replace("#[ensures(self.price >= 100)]",
                                         "#[ensures(self.price >= 99)]"),
                       encoding="utf-8")
    with patch("pipeline.refactor_gate._polyglot_verification",
               side_effect=[dict(_VERIFIED), dict(_VERIFIED)]):
        verdict = verify_contract_preserving_refactor(baseline, dropped)
    assert verdict["code"] == "contract_surface_changed"


def test_apply_writes_file_and_runs_gate(tmp_path):
    from pipeline.rust_strategy_refactor import apply_strategy_rust
    baseline = tmp_path / "meter.rs"
    baseline.write_text(BASELINE, encoding="utf-8")
    destination = tmp_path / "meter_strategy.rs"
    with patch("pipeline.refactor_gate._polyglot_verification",
               side_effect=[dict(_VERIFIED), dict(_VERIFIED)]):
        result = apply_strategy_rust(baseline, "set_price", destination)
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert "pub trait SetPriceStrategy" in destination.read_text(encoding="utf-8")
    assert result["transformation"]["pattern"].startswith("Strategy")


def test_cli_dispatches_rust_strategy(tmp_path, monkeypatch):
    import argparse
    from pipeline.cli import command_apply_refactor
    monkeypatch.chdir(tmp_path)
    (tmp_path / "meter.rs").write_text(BASELINE, encoding="utf-8")

    class _Console:
        @staticmethod
        def print(*_a, **_k): pass
    class _UI:
        console = _Console()

    args = argparse.Namespace(source="meter.rs", method="set_price",
                              pattern="strategy", out="meter_strategy.rs",
                              inspection=None, json=None)
    with patch("pipeline.refactor_gate._polyglot_verification",
               side_effect=[dict(_VERIFIED), dict(_VERIFIED)]):
        code = command_apply_refactor(args, _UI())
    assert code == 0
    assert (tmp_path / "meter_strategy.rs").exists()

    # Non-Rust polyglot suffixes still refuse the strategy pattern.
    (tmp_path / "logic.c").write_text("int f(void) { return 1; }\n", encoding="utf-8")
    args.source, args.pattern = "logic.c", "strategy"
    assert command_apply_refactor(args, _UI()) == 2


@pytest.mark.skipif(not _prusti_installed(), reason="real Prusti not installed")
def test_real_prusti_proves_the_strategy_refactor(tmp_path):
    """The probed 6/6 shape, produced end to end by the transformer."""
    from pipeline.rust_strategy_refactor import apply_strategy_rust
    baseline = tmp_path / "meter.rs"
    baseline.write_text(BASELINE, encoding="utf-8")
    result = apply_strategy_rust(baseline, "set_price",
                                 tmp_path / "meter_strategy.rs")
    assert result["status"] == "VERIFIED", result
    assert result["verification"]["verifier"] == "prusti"
