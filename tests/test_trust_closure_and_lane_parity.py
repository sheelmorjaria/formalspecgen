"""Proof-trust coverage across Java declarations and native refactor lanes."""
from unittest.mock import patch

import pytest

from pipeline import implementation
from pipeline.implementation import trusted_surface_matches
from pipeline.java_contracts import contract_surface
from pipeline.polyglot_surface import native_contract_surface
from pipeline.refactor_gate import (
    _java_fileset_trust_manifest,
    verify_contract_preserving_refactor,
    verify_multifile_contract_refactor,
)


JAVA_BASE = r'''public class Probe {
    //@ ensures \result == 1;
    public int f(int x)
    {
        return 1;
    }
}
'''

RUST_BASE = """#[ensures(result == 1)]
pub fn f(x: i32) -> i32 {
    1
}
"""

C_BASE = r'''/*@ ensures \result == 1; */
int first(void) { return 1; }

/*@ ensures \result == 2; */
int second(void) { return 2; }
'''


def _java_files(tmp_path, before: str, after: str):
    baseline = tmp_path / "before" / "Probe.java"
    refactored = tmp_path / "after" / "Probe.java"
    baseline.parent.mkdir(parents=True)
    refactored.parent.mkdir(parents=True)
    baseline.write_text(before, encoding="utf-8")
    refactored.write_text(after, encoding="utf-8")
    return baseline, refactored


def _native_files(tmp_path, suffix: str, before: str, after: str):
    baseline = tmp_path / f"before{suffix}"
    refactored = tmp_path / f"after{suffix}"
    baseline.write_text(before, encoding="utf-8")
    refactored.write_text(after, encoding="utf-8")
    return baseline, refactored


def test_private_skip_esc_is_recorded_outside_public_api_projection():
    changed = JAVA_BASE.replace(
        "        return 1;",
        "        return helper();", 1).replace(
        "\n}",
        "\n    @org.jmlspecs.annotation.SkipEsc\n"
        "    private int helper() { return 2; }\n}\n")
    surface = contract_surface(changed, public_only=True)
    assert not any("helper" in signature for signature in surface["methods"])
    assert any("helper" in signature for signature in surface["proof_trust"]["members"])
    assert trusted_surface_matches(JAVA_BASE, changed)[0] is False


def test_single_java_gate_rejects_private_skip_esc_before_proof(tmp_path):
    changed = JAVA_BASE.replace("return 1;", "return helper();", 1).replace(
        "\n}",
        "\n    //@ ensures \\result == 1;\n"
        "    @org.jmlspecs.annotation.SkipEsc\n"
        "    private int helper() { return 2; }\n}\n")
    baseline, refactored = _java_files(tmp_path, JAVA_BASE, changed)
    with patch("pipeline.refactor_gate.verify") as verifier:
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "contract_surface_changed"
    verifier.assert_not_called()


def test_ordinary_private_helper_extraction_remains_allowed(tmp_path):
    changed = JAVA_BASE.replace("return 1;", "return helper();", 1).replace(
        "\n}", "\n    private int helper() { return 1; }\n}\n")
    baseline, refactored = _java_files(tmp_path, JAVA_BASE, changed)
    with patch("pipeline.refactor_gate.verify", return_value=(0, "proved")) as verifier:
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["status"] == "VERIFIED"
    assert verifier.call_count == 4


def test_multifile_gate_inspects_new_collaborator_proof_trust(tmp_path):
    baseline, primary = _java_files(tmp_path, JAVA_BASE, JAVA_BASE)
    collaborator = r'''public class Helper {
    @org.jmlspecs.annotation.SkipEsc
    public int value() { return 2; }
}
'''
    (primary.parent / "Helper.java").write_text(collaborator, encoding="utf-8")
    with patch("pipeline.refactor_gate.verify") as verifier, \
         patch("pipeline.refactor_gate.verify_files") as verifier_files:
        result = verify_multifile_contract_refactor(baseline, primary.parent)
    assert result["code"] == "proof_trust_changed"
    verifier.assert_not_called()
    verifier_files.assert_not_called()


def test_multifile_gate_allows_ordinary_new_collaborator(tmp_path):
    baseline, primary = _java_files(tmp_path, JAVA_BASE, JAVA_BASE)
    (primary.parent / "Helper.java").write_text(
        "public class Helper { public int value() { return 1; } }\n",
        encoding="utf-8")
    with patch("pipeline.refactor_gate.verify", return_value=(0, "proved")), \
         patch("pipeline.refactor_gate.verify_files", return_value=(0, "proved")):
        result = verify_multifile_contract_refactor(baseline, primary.parent)
    assert result["status"] == "VERIFIED"


def test_multifile_gate_rejects_unparseable_collaborator_before_proof(tmp_path):
    baseline, primary = _java_files(tmp_path, JAVA_BASE, JAVA_BASE)
    (primary.parent / "Helper.java").write_text(
        "public class Helper { //+ESC@ assume false;\n}\n", encoding="utf-8")
    with patch("pipeline.refactor_gate.verify") as verifier, \
         patch("pipeline.refactor_gate.verify_files") as verifier_files:
        result = verify_multifile_contract_refactor(baseline, primary.parent)
    assert result["code"] == "fileset_contract_syntax_unsupported"
    verifier.assert_not_called()
    verifier_files.assert_not_called()


def test_java_fileset_manifest_reports_unreadable_source(tmp_path):
    missing = tmp_path / "Missing.java"
    errors, manifest = _java_fileset_trust_manifest([missing])
    assert "Missing.java" in errors
    assert manifest == {}


def test_bare_carriage_return_fails_string_boundary_before_tools(tmp_path):
    changed = JAVA_BASE.replace(
        "        return 1;",
        "        // ordinary\r        //@ assume x == 1;\n        return x;")
    trusted, differences = trusted_surface_matches(JAVA_BASE, changed)
    assert trusted is False
    assert "bare carriage-return" in " ".join(differences["parse_errors"]["actual"])
    with patch.object(implementation, "_javac") as javac, \
         patch.object(implementation, "verify") as verifier:
        result = implementation.synthesize_implementation(
            JAVA_BASE, candidate=changed, out_dir=tmp_path, max_attempts=1)
    assert result["final_status"] == "TRUST_BOUNDARY_VIOLATION"
    javac.assert_not_called()
    verifier.assert_not_called()


def test_crlf_line_terminator_keeps_following_assumption_active():
    changed = JAVA_BASE.replace(
        "        return 1;",
        "        // ordinary\r\n        //@ assume x == 1;\r\n        return x;")
    trusted, differences = trusted_surface_matches(JAVA_BASE, changed)
    assert trusted is False
    assert differences["proof_trust"]["actual"]["assumptions"]
    assert contract_surface(changed)["parse_errors"] == []


def test_refactor_gate_preserves_raw_line_endings_for_boundary_check(tmp_path):
    changed = JAVA_BASE.replace(
        "        return 1;",
        "        // ordinary\r        //@ assume x == 1;\n        return x;")
    baseline, refactored = _java_files(tmp_path, JAVA_BASE, changed)
    with patch("pipeline.refactor_gate.verify") as verifier:
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "unsupported_contract_syntax"
    verifier.assert_not_called()


def test_rust_added_precondition_is_not_contract_preservation(tmp_path):
    changed = RUST_BASE.replace(
        "#[ensures(result == 1)]", "#[requires(x == 1)]\n#[ensures(result == 1)]",
    ).replace("    1", "    x")
    baseline, refactored = _native_files(tmp_path, ".rs", RUST_BASE, changed)
    with patch("pipeline.refactor_gate._polyglot_verification") as verifier:
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "contract_surface_changed"
    verifier.assert_not_called()


def test_rust_trusted_attribute_is_independent_proof_trust(tmp_path):
    changed = RUST_BASE.replace(
        "#[ensures(result == 1)]", "#[trusted]\n#[ensures(result == 1)]")
    surface = native_contract_surface(changed, "rust")
    assert surface["proof_trust"]
    baseline, refactored = _native_files(tmp_path, ".rs", RUST_BASE, changed)
    with patch("pipeline.refactor_gate._polyglot_verification") as verifier:
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "proof_trust_changed"
    verifier.assert_not_called()


def test_unbound_rust_contract_fails_closed_and_trust_is_still_visible(tmp_path):
    unbound_contract = "#[requires(x > 0)]\npub struct Value;\n"
    contract_surface_result = native_contract_surface(unbound_contract, "rust")
    assert contract_surface_result["parse_errors"]

    unbound_trust = "#[trusted]\npub struct Value;\n"
    trust_surface = native_contract_surface(unbound_trust, "rust")
    assert trust_surface["proof_trust"]

    baseline, refactored = _native_files(
        tmp_path, ".rs", unbound_contract, unbound_contract + "// changed\n")
    with patch("pipeline.refactor_gate._polyglot_verification") as verifier:
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "unsupported_contract_syntax"
    verifier.assert_not_called()


def test_c_contracts_remain_bound_to_function_identity(tmp_path):
    changed = (C_BASE.replace("first(void)", "temporary(void)")
               .replace("second(void)", "first(void)")
               .replace("temporary(void)", "second(void)"))
    baseline, refactored = _native_files(tmp_path, ".c", C_BASE, changed)
    with patch("pipeline.refactor_gate._polyglot_verification") as verifier:
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "contract_surface_changed"
    verifier.assert_not_called()


def test_acsl_loop_and_trust_controls_are_classified_separately():
    source = r'''/*@ loop invariant i >= 0; */
int looped(void) { return 0; }

/*@ admit established_elsewhere; */
int trusted(void) { return 1; }
'''
    surface = native_contract_surface(source, "c")
    assert surface["parse_errors"] == []
    assert surface["proof_trust"]
    assert all(not item["contracts"] for item in surface["functions"])


def test_unbound_acsl_contract_fails_closed_and_unbound_trust_is_visible():
    source = r'''/*@ requires x > 0; */
int data;
/*@ admit external_fact; */
int other;
int f(void) { return 1; }
'''
    surface = native_contract_surface(source, "c")
    assert surface["parse_errors"]
    assert surface["proof_trust"]


def test_native_gate_rejects_contract_without_public_api(tmp_path):
    baseline_source = "/*@ ensures \\result == 1; */\nstatic int f(void) { return 1; }\n"
    changed = baseline_source.replace("return 1", "return 1 + 0")
    baseline, refactored = _native_files(
        tmp_path, ".c", baseline_source, changed)
    with patch("pipeline.refactor_gate._polyglot_verification") as verifier:
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "method_surface_changed"
    verifier.assert_not_called()


def test_cpp_global_assertion_change_is_not_contract_preservation(tmp_path):
    baseline_source = "class Counter { public: int f() { assert(x > 0); return x; } int x; };\n"
    changed = baseline_source.replace("x > 0", "x >= 0")
    baseline, refactored = _native_files(
        tmp_path, ".cpp", baseline_source, changed)
    with patch("pipeline.refactor_gate._polyglot_verification") as verifier:
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["code"] == "contract_surface_changed"
    verifier.assert_not_called()


def test_native_surface_rejects_unknown_language():
    with pytest.raises(ValueError, match="unsupported native contract language"):
        native_contract_surface("", "zig")


def test_java_proof_trust_annotations_include_class_and_private_field():
    source = r'''@org.jmlspecs.annotation.SkipEsc
public class TrustControls {
    @org.jmlspecs.annotation.SkipRac
    private int hidden;

    //@ ensures \result == 1;
    public int f() { return 1; }
}
'''
    surface = contract_surface(source, public_only=True)
    assert surface["proof_trust"]["class"]
    assert surface["proof_trust"]["fields"]
    assert surface["java_annotations"]["fields"] == {}


def test_native_private_helper_with_contract_remains_permitted(tmp_path):
    changed = RUST_BASE.replace("    1", "    helper()", 1) + """
#[ensures(result == 1)]
fn helper() -> i32 { 1 }
"""
    baseline, refactored = _native_files(tmp_path, ".rs", RUST_BASE, changed)
    verified = {"status": "VERIFIED", "claim": "DEDUCTIVE_PROOF", "output": "proved"}
    with patch("pipeline.refactor_gate._polyglot_verification",
               side_effect=[verified, dict(verified)]) as verifier:
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["status"] == "VERIFIED"
    assert verifier.call_count == 2
