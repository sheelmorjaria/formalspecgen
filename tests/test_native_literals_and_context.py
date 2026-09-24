"""Rust literal fidelity and declarations that determine contract meaning."""
from unittest.mock import patch

import pytest

from pipeline.polyglot_surface import native_contract_surface
from pipeline.refactor_gate import verify_contract_preserving_refactor


BASE = '''use prusti_contracts::*;

const EXPECTED: i32 = 1;

#[ensures(result == EXPECTED)]
pub fn f() -> i32 { EXPECTED }
'''


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ('#[ensures(result == b"A  B"[2])]', '#[ensures(result == b"A B"[2])]'),
        ('#[ensures(result == "A  B".len())]', '#[ensures(result == "A B".len())]'),
        ('#[ensures(result == br"A  B"[2])]', '#[ensures(result == br"A B"[2])]'),
    ],
)
def test_rust_contract_literal_bytes_are_not_whitespace_normalized(before, after):
    left = native_contract_surface(f"{before}\npub fn f() -> usize {{ 0 }}\n", "rust")
    right = native_contract_surface(f"{after}\npub fn f() -> usize {{ 0 }}\n", "rust")
    assert left["parse_errors"] == right["parse_errors"] == []
    assert left["functions"] != right["functions"]


def test_constant_value_is_part_of_semantic_context():
    changed = BASE.replace("EXPECTED: i32 = 1", "EXPECTED: i32 = 2")
    baseline = native_contract_surface(BASE, "rust")
    candidate = native_contract_surface(changed, "rust")
    assert baseline["functions"] == candidate["functions"]
    assert baseline["semantic_declarations"] != candidate["semantic_declarations"]


def test_added_constant_cannot_shadow_a_contract_binding(tmp_path):
    baseline = tmp_path / "before.rs"
    candidate = tmp_path / "after.rs"
    baseline.write_text(BASE, encoding="utf-8")
    candidate.write_text(BASE.replace(
        "const EXPECTED: i32 = 1;", "const EXPECTED: i32 = 1;\nconst EXTRA: i32 = 2;"),
        encoding="utf-8")
    with patch("pipeline.refactor_gate._polyglot_verification") as verifier:
        result = verify_contract_preserving_refactor(baseline, candidate)
    assert result["code"] == "semantic_context_changed"
    verifier.assert_not_called()


def test_constant_and_import_changes_are_rejected_before_backend(tmp_path):
    baseline = tmp_path / "before.rs"
    candidate = tmp_path / "after.rs"
    baseline.write_text(BASE, encoding="utf-8")
    candidate.write_text(BASE.replace("EXPECTED: i32 = 1", "EXPECTED: i32 = 2"),
                         encoding="utf-8")
    with patch("pipeline.refactor_gate._polyglot_verification") as verifier:
        result = verify_contract_preserving_refactor(baseline, candidate)
    assert result["code"] == "semantic_context_changed"
    verifier.assert_not_called()

    candidate.write_text(BASE.replace("use prusti_contracts::*;",
                                      "use other_contracts::*;"), encoding="utf-8")
    with patch("pipeline.refactor_gate._polyglot_verification") as verifier:
        result = verify_contract_preserving_refactor(baseline, candidate)
    assert result["code"] == "binding_context_changed"
    verifier.assert_not_called()


def test_body_change_preserves_literal_and_context_surface():
    changed = BASE.replace("{ EXPECTED }", "{ EXPECTED + 0 }")
    assert native_contract_surface(BASE, "rust") == \
        native_contract_surface(changed, "rust")
