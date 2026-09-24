"""Regression coverage for the complete Java/JML contract-front-end boundary."""
from unittest.mock import patch

import pytest

from pipeline.implementation import trusted_surface_matches
from pipeline.java_contracts import contract_surface, has_reviewed_contract
from pipeline.refactor_gate import (
    verify_contract_preserving_refactor,
    verify_multifile_contract_refactor,
)


PAIR_NEXT_LINE = r'''public class Pair {
    //@ ensures \result == 1;
    public int first()
    {
        return 1;
    }

    //@ ensures \result == 2;
    public int second()
    {
        return 2;
    }
}
'''


def _swap_method_names(source: str) -> str:
    return (source.replace("first()", "temporaryName()")
            .replace("second()", "first()")
            .replace("temporaryName()", "second()"))


def _java_files(tmp_path, before: str, after: str):
    baseline = tmp_path / "before" / "Pair.java"
    refactored = tmp_path / "after" / "Pair.java"
    baseline.parent.mkdir(parents=True)
    refactored.parent.mkdir(parents=True)
    baseline.write_text(before, encoding="utf-8")
    refactored.write_text(after, encoding="utf-8")
    return baseline, refactored


@pytest.mark.parametrize("brace", [" {", "\n    {"])
def test_method_declarations_are_completely_represented_for_brace_layout(brace):
    source = PAIR_NEXT_LINE.replace("\n    {", brace)
    surface = contract_surface(source)
    assert surface["parse_errors"] == []
    assert surface["methods"] == ["public int first ( )", "public int second ( )"]
    assert surface["clauses"]["members"]["public int first ( )"] == [
        r"ensures \result == 1"]


def test_next_line_method_name_reassignment_changes_implementation_surface():
    trusted, differences = trusted_surface_matches(
        PAIR_NEXT_LINE, _swap_method_names(PAIR_NEXT_LINE))
    assert trusted is False
    assert "clauses" in differences


def test_single_file_gate_rejects_next_line_reassignment_before_proof(tmp_path):
    baseline, refactored = _java_files(
        tmp_path, PAIR_NEXT_LINE, _swap_method_names(PAIR_NEXT_LINE))
    with patch("pipeline.refactor_gate.verify") as verifier:
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "contract_surface_changed"
    verifier.assert_not_called()


def test_multifile_gate_rejects_next_line_reassignment_before_proof(tmp_path):
    baseline, refactored = _java_files(
        tmp_path, PAIR_NEXT_LINE, _swap_method_names(PAIR_NEXT_LINE))
    with patch("pipeline.refactor_gate.verify") as verifier, \
         patch("pipeline.refactor_gate.verify_files") as verifier_files:
        result = verify_multifile_contract_refactor(baseline, refactored.parent)
    assert result["code"] == "primary_contract_surface_changed"
    verifier.assert_not_called()
    verifier_files.assert_not_called()


@pytest.mark.parametrize("scope", ["class", "method"])
def test_nullness_default_changes_are_part_of_the_scoped_surface(scope):
    if scope == "class":
        nullable = "//@ nullable_by_default\n" + PAIR_NEXT_LINE
    else:
        nullable = PAIR_NEXT_LINE.replace(
            "    //@ ensures", "    //@ nullable_by_default\n    //@ ensures", 1)
    non_null = nullable.replace("nullable_by_default", "non_null_by_default")
    trusted, differences = trusted_surface_matches(nullable, non_null)
    assert trusted is False
    assert "semantic_modifiers" in differences
    assert has_reviewed_contract(contract_surface(nullable, public_only=True))


def test_nullness_default_formatting_only_change_is_preserved():
    baseline = "//@ nullable_by_default\n" + PAIR_NEXT_LINE
    reformatted = baseline.replace(
        "//@ nullable_by_default", "/*@   nullable_by_default   @*/")
    assert trusted_surface_matches(baseline, reformatted)[0] is True


@pytest.mark.parametrize("escaped_annotation", [
    r"\u002f\u002f\u0040 assume false;",
    r"\uuuu002f\u002f\u0040 assume false;",
])
def test_unicode_escape_bearing_java_fails_closed(escaped_annotation):
    changed = PAIR_NEXT_LINE.replace("        return 1;", escaped_annotation +
                                     "\n        return 1;", 1)
    trusted, differences = trusted_surface_matches(PAIR_NEXT_LINE, changed)
    assert trusted is False
    assert "Unicode escapes are unsupported" in " ".join(
        differences["parse_errors"]["actual"])


def test_unicode_escape_is_rejected_by_refactor_gate_before_proof(tmp_path):
    changed = PAIR_NEXT_LINE.replace(
        "        return 1;",
        r"\u002f\u002f\u0040 assume false;" + "\n        return 1;", 1)
    baseline, refactored = _java_files(tmp_path, PAIR_NEXT_LINE, changed)
    with patch("pipeline.refactor_gate.verify") as verifier:
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "unsupported_contract_syntax"
    verifier.assert_not_called()


def test_unrepresented_java_declaration_fails_closed():
    source = r'''public class Pair {
    //@ ensures \result == 1;
    int packageMethod() { return 1; }
}
'''
    surface = contract_surface(source)
    assert surface["methods"] == []
    assert any("unrepresented=packageMethod" in issue
               for issue in surface["parse_errors"])


def test_private_helper_extraction_remains_permitted_by_public_projection():
    helper = PAIR_NEXT_LINE.replace(
        "        return 1;",
        "        return helper();", 1).replace(
        "\n}", "\n    private int helper()\n    {\n        return 1;\n    }\n}\n")
    baseline = contract_surface(PAIR_NEXT_LINE, public_only=True)
    refactored = contract_surface(helper, public_only=True)
    assert baseline == refactored


def test_inline_method_and_field_nullness_modifiers_keep_their_owners():
    source = r'''public class Nullness {
    public /*@ nullable @*/ Object value;
    public /*@ non_null @*/ Object get()
    {
        return value;
    }
}
'''
    surface = contract_surface(source)
    assert surface["parse_errors"] == []
    assert surface["semantic_modifiers"]["fields"] == {
        "public / * @ nullable @ * / Object value ;": ["nullable"]}
    assert surface["semantic_modifiers"]["members"] == {
        "public / * @ non_null @ * / Object get ( )": ["non_null"]}


def test_standalone_field_modifier_binds_to_the_following_field():
    source = r'''public class Nullness {
    //@ non_null
    public Object value;
}
'''
    surface = contract_surface(source)
    assert surface["semantic_modifiers"]["fields"] == {
        "public Object value ;": ["non_null"]}
    assert has_reviewed_contract(surface)


@pytest.mark.parametrize("source, expected", [
    ("public class Broken { public int f( { }", "unsupported Java syntax"),
    ("public class Outer { class Inner { public int f() { return 1; } } }",
     "nested Java type declarations"),
])
def test_unsupported_java_shapes_produce_explicit_boundary_errors(source, expected):
    surface = contract_surface(source)
    assert any(expected in issue for issue in surface["parse_errors"])
