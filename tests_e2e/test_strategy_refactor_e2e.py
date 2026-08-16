"""E2E Test 2: Strategy extraction detected, applied, and proven by real OpenJML."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import cli

pytestmark = pytest.mark.toolchain

PRICING_SERVICE = """public class PricingService {
    private /*@ spec_public @*/ int price;

    //@ requires customerType == 1 || customerType == 2;
    //@ ensures price >= 0;
    public void calculatePrice(int customerType) {
        if (customerType == 1) {
            price = 100; // Standard
        } else if (customerType == 2) {
            price = 80; // Premium
        }
    }
}
"""


def test_strategy_chain_preserves_contract(tmp_path, openjml_tool):
    """inspect -> apply-refactor strategy -> verify-refactor on real OpenJML/Z3."""
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    source = baseline / "PricingService.java"
    source.write_text(PRICING_SERVICE, encoding="utf-8")
    inspection = tmp_path / "inspection.json"
    refactored = tmp_path / "refactored"
    verdict = tmp_path / "verdict.json"

    # Step A: the type-switch smell is detected and Strategy recommended.
    assert cli.main(["inspect", str(source), "--json", str(inspection)]) == 0
    findings = json.loads(inspection.read_text(encoding="utf-8"))["findings"]
    assert any(item["code"] == "type-switch" and
               item["suggested_pattern"] == "Strategy" and
               "calculatePrice" in item.get("methods", []) for item in findings)

    # Step B: the transform emits the strategy surface.
    assert cli.main(["apply-refactor", str(source), "--inspection", str(inspection),
                     "--pattern", "strategy", "--method", "calculatePrice",
                     "--out", str(refactored), "--json",
                     str(tmp_path / "applied.json")]) == 0
    for name in ("PriceStrategy.java", "StandardPrice.java",
                 "PremiumPrice.java", "PricingService.java"):
        assert (refactored / name).exists(), f"missing {name}"

    # Step C: the orchestrator no longer branches; it selects and delegates.
    primary = (refactored / "PricingService.java").read_text(encoding="utf-8")
    assert "if (customerType == 1)" not in primary
    assert "strategy.calculate()" in primary
    assert "PriceStrategy strategy = PriceStrategy.forCustomerType(customerType);" in primary

    # Step D: the multifile gate proves the public contract still holds.
    assert cli.main(["verify-refactor", str(source), str(refactored),
                     "--json", str(verdict)]) == 0
    result = json.loads(verdict.read_text(encoding="utf-8"))
    assert result["claim"] == "MULTIFILE_REFACTOR_CONTRACT_PRESERVED"
    assert result["contract_surface_preserved"] is True
    assert result["behavior_equivalence_proved"] is False
