"""Rust attribute interpretation and qualified declaration ownership."""
from unittest.mock import patch

import pytest

from pipeline.polyglot_surface import native_contract_surface
from pipeline.refactor_gate import verify_contract_preserving_refactor


BASE = """use prusti_contracts::*;

#[ensures(result == 1)]
pub fn f(x: i32) -> i32 {
    1
}
"""


def _files(tmp_path, before: str, after: str):
    baseline = tmp_path / "before.rs"
    candidate = tmp_path / "after.rs"
    baseline.write_text(before, encoding="utf-8")
    candidate.write_text(after, encoding="utf-8")
    return baseline, candidate


@pytest.mark.parametrize(
    ("attribute", "surface_key"),
    [
        ("#[prusti_contracts::trusted]", "proof_trust"),
        ("#[prusti_contracts::requires(x == 1)]", "functions"),
    ],
)
def test_qualified_prusti_attributes_are_semantic(attribute, surface_key):
    changed = BASE.replace("#[ensures", f"{attribute}\n#[ensures")
    baseline = native_contract_surface(BASE, "rust")
    candidate = native_contract_surface(changed, "rust")
    assert candidate["parse_errors"] == []
    assert candidate[surface_key] != baseline[surface_key]


@pytest.mark.parametrize(
    "attribute",
    [
        "#[cfg(all())]",
        "#[cfg_attr(all(), trusted)]",
        "#[cfg_attr(all(), requires(x == 1))]",
    ],
)
def test_conditional_semantic_attributes_fail_closed(attribute):
    changed = BASE.replace("#[ensures", f"{attribute}\n#[ensures")
    surface = native_contract_surface(changed, "rust")
    assert any("conditional Rust attribute" in item for item in surface["parse_errors"])


@pytest.mark.parametrize(
    "attribute",
    [
        "#[prusti_contracts::trusted]",
        "#[prusti_contracts::requires(x == 1)]",
        "#[cfg_attr(all(), trusted)]",
        "#[cfg_attr(all(), requires(x == 1))]",
    ],
)
def test_attribute_mutations_are_rejected_before_proof(tmp_path, attribute):
    changed = BASE.replace("#[ensures", f"{attribute}\n#[ensures")
    baseline, candidate = _files(tmp_path, BASE, changed)
    with patch("pipeline.refactor_gate._polyglot_verification") as verifier:
        result = verify_contract_preserving_refactor(baseline, candidate)
    assert result["code"] in {
        "contract_surface_changed", "proof_trust_changed",
        "unsupported_contract_syntax",
    }
    verifier.assert_not_called()


def test_module_ownership_is_part_of_callable_identity(tmp_path):
    before = """pub mod left {
    #[ensures(result == 1)]
    pub fn f() -> i32 { 1 }
}
pub mod right {
    #[ensures(result == 2)]
    pub fn f() -> i32 { 2 }
}
"""
    after = before.replace("mod left", "mod temporary", 1) \
        .replace("mod right", "mod left", 1) \
        .replace("mod temporary", "mod right", 1)
    baseline_surface = native_contract_surface(before, "rust")
    candidate_surface = native_contract_surface(after, "rust")
    assert baseline_surface != candidate_surface
    assert {item["identity"] for item in baseline_surface["functions"]} == {
        "crate::module:pub mod left::f",
        "crate::module:pub mod right::f",
    }

    baseline, candidate = _files(tmp_path, before, after)
    with patch("pipeline.refactor_gate._polyglot_verification") as verifier:
        result = verify_contract_preserving_refactor(baseline, candidate)
    assert result["code"] in {"method_surface_changed", "contract_surface_changed"}
    verifier.assert_not_called()


def test_impl_ownership_is_part_of_callable_identity():
    source = """pub struct Left;
pub struct Right;
impl Left {
    #[ensures(result == 1)]
    pub fn f(&self) -> i32 { 1 }
}
impl Right {
    #[ensures(result == 2)]
    pub fn f(&self) -> i32 { 2 }
}
"""
    changed = source.replace("impl Left", "impl Temporary", 1) \
        .replace("impl Right", "impl Left", 1) \
        .replace("impl Temporary", "impl Right", 1)
    assert native_contract_surface(source, "rust") != \
        native_contract_surface(changed, "rust")


def test_unclassified_attribute_is_not_silently_ignored():
    changed = BASE.replace("#[ensures", "#[some_macro]\n#[ensures")
    surface = native_contract_surface(changed, "rust")
    assert any("unclassified #[some_macro]" in item
               for item in surface["proof_trust"])


def test_rust_contract_surface_requires_complete_structural_parse(monkeypatch):
    import pipeline.polyglot_surface as surface_module

    monkeypatch.setattr(surface_module, "Parser", None)
    unavailable = surface_module.native_contract_surface(BASE, "rust")
    assert unavailable["parse_errors"] == [
        "tree-sitter Rust parsing is required for contract preservation"]

    monkeypatch.undo()
    malformed = native_contract_surface("pub fn broken( {", "rust")
    assert malformed["parse_errors"] == [
        "Rust source could not be parsed completely at the contract boundary"]


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("mod external;\n", "external Rust module ownership"),
        ("generate_items!{}\n", "item-level Rust macros"),
        ("generate_items!();\n", "item-level Rust macros"),
        (
            "pub fn outer() { #[ensures(result == 1)] fn inner() -> i32 { 1 } }\n",
            "unsupported Rust callable ownership",
        ),
    ],
)
def test_unsupported_rust_ownership_forms_fail_closed(source, message):
    surface = native_contract_surface(source, "rust")
    assert any(message in item for item in surface["parse_errors"])


def test_body_only_change_keeps_qualified_surface():
    changed = BASE.replace("    1\n", "    1 + 0\n")
    assert native_contract_surface(BASE, "rust") == \
        native_contract_surface(changed, "rust")


def test_private_helper_extraction_remains_supported(tmp_path):
    changed = BASE.replace("    1\n", "    helper()\n", 1) + """
#[ensures(result == 1)]
fn helper() -> i32 { 1 }
"""
    baseline, candidate = _files(tmp_path, BASE, changed)
    verified = {"status": "VERIFIED", "claim": "DEDUCTIVE_PROOF", "output": "proved"}
    with patch("pipeline.refactor_gate._polyglot_verification",
               side_effect=[verified, dict(verified)]) as verifier:
        result = verify_contract_preserving_refactor(baseline, candidate)
    assert result["status"] == "VERIFIED"
    assert verifier.call_count == 2
