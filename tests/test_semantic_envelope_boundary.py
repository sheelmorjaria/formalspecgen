"""Effective-contract regressions for annotations, effects, and name binding."""
from unittest.mock import patch

import pytest

from pipeline import implementation
from pipeline.implementation import trusted_surface_matches
from pipeline.java_contracts import contract_surface, has_reviewed_contract
from pipeline.refactor_gate import (
    verify_contract_preserving_refactor,
    verify_multifile_contract_refactor,
)


PROBE = r'''public class Probe {
    public int count;

    //@ pure
    //@ ensures \result == 1;
    public int f()
    {
        return 1;
    }
}
'''


def _files(tmp_path, before: str, after: str):
    baseline = tmp_path / "before" / "Probe.java"
    refactored = tmp_path / "after" / "Probe.java"
    baseline.parent.mkdir(parents=True)
    refactored.parent.mkdir(parents=True)
    baseline.write_text(before, encoding="utf-8")
    refactored.write_text(after, encoding="utf-8")
    return baseline, refactored


@pytest.mark.parametrize("annotation", [
    "//+ESC@ assume count == 0;",
    "//+OPENJML@ assume count == 0;",
    "//-RAC@ assume count == 0;",
    "/*+ESC@ assume count == 0; @*/",
])
def test_conditional_jml_annotations_fail_closed(annotation):
    changed = PROBE.replace("        return 1;", f"        {annotation}\n        return 1;")
    trusted, differences = trusted_surface_matches(PROBE, changed)
    assert trusted is False
    assert "conditional JML annotations are unsupported" in " ".join(
        differences["parse_errors"]["actual"])


def test_conditional_marker_text_inside_literals_and_comments_remains_inactive():
    changed = PROBE.replace(
        "return 1;",
        'String marker = "//+ESC@ assume false;"; '
        '/* ordinary //+ESC@ assume false; */ return 1;',
    )
    assert trusted_surface_matches(PROBE, changed)[0] is True


def test_comment_form_purity_is_a_method_bound_contract_modifier():
    changed = PROBE.replace("    //@ pure\n", "").replace(
        "return 1;", "count = 1;\n        return 1;")
    trusted, differences = trusted_surface_matches(PROBE, changed)
    assert trusted is False
    assert differences["semantic_modifiers"]["expected"]["members"]


def test_java_annotation_purity_is_preserved():
    baseline = PROBE.replace("    //@ pure", "    @Pure")
    changed = baseline.replace("    @Pure\n", "").replace(
        "return 1;", "count = 1;\n        return 1;")
    trusted, differences = trusted_surface_matches(baseline, changed)
    assert trusted is False
    assert differences["java_annotations"]["expected"]["members"]
    assert has_reviewed_contract(contract_surface(baseline, public_only=True))


def test_java_spec_visibility_annotation_is_bound_to_private_field():
    source = PROBE.replace(
        "    public int count;",
        "    @org.jmlspecs.annotation.SpecPublic\n    private int count;")
    surface = contract_surface(source, public_only=True)
    assert surface["java_annotations"]["fields"]
    assert has_reviewed_contract(surface)


def test_noncontract_java_annotation_is_preserved_without_minting_a_contract():
    source = "@Deprecated\npublic class Plain {}\n"
    surface = contract_surface(source, public_only=True)
    assert surface["java_annotations"]["class"]
    assert has_reviewed_contract(surface) is False


@pytest.mark.parametrize("modifier", [
    "helper", "spec_public", "spec_protected", "model", "ghost",
])
def test_remaining_standalone_jml_modifiers_are_never_silently_discarded(modifier):
    baseline = PROBE.replace("    //@ pure", f"    //@ {modifier}")
    changed = baseline.replace(f"    //@ {modifier}\n", "")
    assert trusted_surface_matches(baseline, changed)[0] is False


def test_static_import_binding_is_part_of_the_trusted_context():
    baseline = PROBE.replace(
        "public class Probe", "import static java.lang.Byte.MAX_VALUE;\n\npublic class Probe",
    ).replace(r"\result == 1", r"\result == MAX_VALUE").replace(
        "return 1", "return MAX_VALUE")
    changed = baseline.replace("java.lang.Byte.MAX_VALUE", "java.lang.Short.MAX_VALUE")
    trusted, differences = trusted_surface_matches(baseline, changed)
    assert trusted is False
    assert differences["context"]["expected"]["imports"] == [
        "static java.lang.Byte.MAX_VALUE"]


@pytest.mark.parametrize("before, after", [
    ("package one;", "package two;"),
    ("public class Probe", "public final class Probe"),
    ("public class Probe", "public class Probe<T>"),
    ("public class Probe", "public class Probe implements java.io.Serializable"),
])
def test_type_and_package_context_changes_are_rejected(before, after):
    baseline = (before + "\n" + PROBE) if before.startswith("package") else PROBE
    changed = baseline.replace(before, after)
    trusted, differences = trusted_surface_matches(baseline, changed)
    assert trusted is False
    assert "context" in differences


def test_additional_top_level_type_context_is_rejected_as_unsupported():
    source = PROBE + "\nclass ContractValues { static final int ONE = 1; }\n"
    surface = contract_surface(source)
    assert any("additional top-level Java types" in issue
               for issue in surface["parse_errors"])


def test_harmless_body_edits_and_private_helper_extraction_remain_permitted():
    body_edit = PROBE.replace("return 1;", "int result = 1;\n        return result;")
    assert trusted_surface_matches(PROBE, body_edit)[0] is True

    helper = PROBE.replace("return 1;", "return helper();").replace(
        "\n}", "\n    private int helper() { return 1; }\n}\n")
    assert (contract_surface(PROBE, public_only=True) ==
            contract_surface(helper, public_only=True))


def test_single_and_multifile_gates_reject_import_rebinding_before_proof(tmp_path):
    baseline_source = PROBE.replace(
        "public class Probe", "import static java.lang.Byte.MAX_VALUE;\npublic class Probe",
    ).replace(r"\result == 1", r"\result == MAX_VALUE").replace(
        "return 1", "return MAX_VALUE")
    changed = baseline_source.replace("java.lang.Byte.MAX_VALUE", "java.lang.Short.MAX_VALUE")
    baseline, refactored = _files(tmp_path, baseline_source, changed)
    with patch("pipeline.refactor_gate.verify") as verifier, \
         patch("pipeline.refactor_gate.verify_files") as verifier_files:
        single = verify_contract_preserving_refactor(baseline, refactored)
        multi = verify_multifile_contract_refactor(baseline, refactored.parent)
    assert single["code"] == "contract_surface_changed"
    assert multi["code"] == "primary_contract_surface_changed"
    verifier.assert_not_called()
    verifier_files.assert_not_called()


def test_both_refactor_gates_reject_removed_purity_before_proof(tmp_path):
    changed = PROBE.replace("    //@ pure\n", "").replace(
        "return 1;", "count = 1;\n        return 1;")
    baseline, refactored = _files(tmp_path, PROBE, changed)
    with patch("pipeline.refactor_gate.verify") as verifier, \
         patch("pipeline.refactor_gate.verify_files") as verifier_files:
        single = verify_contract_preserving_refactor(baseline, refactored)
        multi = verify_multifile_contract_refactor(baseline, refactored.parent)
    assert single["code"] == "contract_surface_changed"
    assert multi["code"] == "primary_contract_surface_changed"
    verifier.assert_not_called()
    verifier_files.assert_not_called()


def test_postprocessed_artifact_is_rechecked_before_compilation(tmp_path):
    transformed = PROBE.replace(
        "return 1;", "//@ assume count == 0;\n        return 1;")
    with patch.object(implementation, "apply_passes", return_value={
             "code": transformed, "changed": True, "passes": []}), \
         patch.object(implementation, "_javac") as javac, \
         patch.object(implementation, "verify") as verifier:
        result = implementation.synthesize_implementation(
            PROBE, candidate=PROBE, out_dir=tmp_path, max_attempts=1,
            accepted_passes=["inject_nonlinear_index_assume"])
    assert result["final_status"] == "TRUST_BOUNDARY_VIOLATION"
    assert result["attempts"][0]["boundary_stage"] == "postprocess"
    javac.assert_not_called()
    verifier.assert_not_called()
