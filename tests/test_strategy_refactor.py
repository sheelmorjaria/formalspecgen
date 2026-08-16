"""Unit tests for the narrow deterministic Strategy extraction profile."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from pipeline.java_inspection import inspect_java_file
from pipeline.refactor_actions import apply_refactor
from pipeline.strategy_refactor import extract_strategy_from_inspection

FIXTURE = """public class PricingService {
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


def _setup(tmp_path: Path, source: str = FIXTURE, name: str = "PricingService.java"):
    source_file = tmp_path / name
    source_file.write_text(source, encoding="utf-8")
    inspection = tmp_path / "inspection.json"
    inspection.write_text(json.dumps(inspect_java_file(source_file)), encoding="utf-8")
    return source_file, inspection


def test_strategy_extraction_emits_interface_implementations_and_delegating_primary(tmp_path):
    source, inspection = _setup(tmp_path)
    result = extract_strategy_from_inspection(source, inspection, "calculatePrice")
    assert result["status"] == "TRANSFORMED"
    assert result["pattern"] == "Strategy"
    assert result["requires_multifile_refactor_gate"] is True
    files = result["files"]
    assert sorted(files) == ["PremiumPrice.java", "PriceStrategy.java",
                             "PricingService.java", "StandardPrice.java"]
    interface = files["PriceStrategy.java"]
    assert "int calculate();" in interface
    assert "//@ ensures \\result >= 0;" in interface
    assert "//@ requires customerType == 1 || customerType == 2;" in interface
    assert "static PriceStrategy forCustomerType(int customerType)" in interface
    assert "return new StandardPrice();" in interface
    assert "return new PremiumPrice();" in interface
    assert "throw new IllegalArgumentException" in interface
    assert "public class StandardPrice implements PriceStrategy" in files["StandardPrice.java"]
    assert "return 100;" in files["StandardPrice.java"]
    primary = files["PricingService.java"]
    assert "PriceStrategy strategy = PriceStrategy.forCustomerType(customerType);" in primary
    assert "price = strategy.calculate();" in primary
    assert "if (customerType == 1)" not in primary
    assert "//@ ensures price >= 0;" in primary  # the trusted contract stays on the primary


def test_strategy_extraction_names_unlabeled_branches_deterministically(tmp_path):
    source = FIXTURE.replace(" // Standard", "").replace(" // Premium", "")
    source, inspection = _setup(tmp_path, source)
    files = extract_strategy_from_inspection(source, inspection, "calculatePrice")["files"]
    assert "Branch1Price.java" in files and "Branch2Price.java" in files


def test_apply_refactor_routes_strategy_through_multifile_gate(tmp_path):
    source, inspection = _setup(tmp_path)
    proof = {"status": "VERIFIED", "claim": "MULTIFILE_REFACTOR_CONTRACT_PRESERVED"}
    destination = tmp_path / "refactored"
    with patch("pipeline.refactor_gate.verify_multifile_contract_refactor",
               return_value=proof) as gate:
        result = apply_refactor(str(source), str(inspection), "strategy",
                                "calculatePrice", str(destination))
        gate.assert_called_once()
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "MULTIFILE_REFACTOR_CONTRACT_PRESERVED"
    assert (destination / "PriceStrategy.java").exists()


def test_strategy_extraction_fail_closed_on_binding_and_shapes(tmp_path):
    missing = extract_strategy_from_inspection(tmp_path / "Nope.java",
                                               tmp_path / "i.json", "calculatePrice")
    assert missing["code"] == "input_unavailable"

    source, inspection = _setup(tmp_path)
    stale = json.loads(inspection.read_text(encoding="utf-8"))
    stale["source_sha256"] = "0" * 64
    inspection.write_text(json.dumps(stale), encoding="utf-8")
    assert extract_strategy_from_inspection(
        source, inspection, "calculatePrice")["code"] == "inspection_binding_mismatch"

    (tmp_path / "b1").mkdir()
    source, inspection = _setup(tmp_path / "b1")
    unlisted = json.loads(inspection.read_text(encoding="utf-8"))
    unlisted["findings"] = [f for f in unlisted["findings"] if f["code"] != "type-switch"]
    inspection.write_text(json.dumps(unlisted), encoding="utf-8")
    assert extract_strategy_from_inspection(
        source, inspection, "calculatePrice")["code"] == "inspection_binding_mismatch"


def test_strategy_extraction_rejects_out_of_profile_methods(tmp_path):
    variants = {
        "two-params": FIXTURE.replace("public void calculatePrice(int customerType)",
                                      "public void calculatePrice(int customerType, int extra)"),
        "non-void": FIXTURE.replace("public void calculatePrice(int customerType)",
                                    "public int calculatePrice(int customerType)"),
        "field-condition": FIXTURE.replace("if (customerType == 1)", "if (price == 1)")
                                  .replace("else if (customerType == 2)", "else if (price == 2)"),
        "no-ensures": FIXTURE.replace("    //@ ensures price >= 0;\n", ""),
        "wrong-ensures-field": FIXTURE.replace("ensures price >= 0", "ensures total >= 0"),
        "violating-literal": FIXTURE.replace("price = 80; // Premium", "price = -5; // Premium"),
        "duplicate-values": FIXTURE.replace("customerType == 2", "customerType == 1"),
        "two-fields": FIXTURE.replace("price = 80; // Premium", "total = 80; // Premium"),
        "extra-statement": FIXTURE.replace("price = 100; // Standard",
                                           "price = 100; total = 1; // Standard"),
        "private-method": FIXTURE.replace("public void calculatePrice", "private void calculatePrice"),
    }
    for label, mutated in variants.items():
        directory = tmp_path / label
        directory.mkdir()
        source, inspection = _setup(directory, mutated)
        result = extract_strategy_from_inspection(source, inspection, "calculatePrice")
        assert result["status"] == "FAIL", label
        # mutants that lose the type-switch finding fail at the binding gate instead
        assert result["code"] in {"unsupported_strategy_shape",
                                  "unsupported_java_syntax",
                                  "inspection_binding_mismatch"}, label


def test_strategy_extraction_rejects_unknown_method_single_branch_and_collisions(tmp_path):
    source, inspection = _setup(tmp_path)
    assert extract_strategy_from_inspection(
        source, inspection, "nonexistent")["code"] in {
            "unsupported_strategy_shape", "inspection_binding_mismatch"}

    single = FIXTURE.replace("""        } else if (customerType == 2) {
            price = 80; // Premium
        }
""", "        }\n")
    (tmp_path / "one").mkdir()
    source, inspection = _setup(tmp_path / "one", single)
    assert extract_strategy_from_inspection(
        source, inspection, "calculatePrice")["code"] in {
            "unsupported_strategy_shape", "inspection_binding_mismatch"}

    no_requires = FIXTURE.replace(
        "    //@ requires customerType == 1 || customerType == 2;\n", "")
    (tmp_path / "nr").mkdir()
    source, inspection = _setup(tmp_path / "nr", no_requires)
    assert extract_strategy_from_inspection(
        source, inspection, "calculatePrice")["code"] in {
            "unsupported_strategy_shape", "inspection_binding_mismatch"}

    colliding = FIXTURE.replace("// Premium", "// Standard")
    (tmp_path / "col").mkdir()
    source, inspection = _setup(tmp_path / "col", colliding)
    assert extract_strategy_from_inspection(
        source, inspection, "calculatePrice")["code"] in {
            "unsupported_strategy_shape", "inspection_binding_mismatch"}
