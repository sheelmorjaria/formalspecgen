"""P0.1 adversarial closure for parsing, preservation, and normalization."""
from unittest.mock import patch

import pytest

from pipeline.implementation import trusted_surface_matches
from pipeline.refactor_gate import (
    verify_contract_preserving_refactor,
    verify_multifile_contract_refactor,
)
from pipeline.verification_policy import decide_result, decide_verification


PAIR = r'''public class Pair {
    //@ ensures \result == 1;
    public int first() { return 1; }

    //@ ensures \result == 2;
    public int second() { return 2; }
}
'''


def _swap_contracts_and_bodies(source: str) -> str:
    return (source.replace(r"\result == 1", "CONTRACT_PLACEHOLDER")
            .replace(r"\result == 2", r"\result == 1")
            .replace("CONTRACT_PLACEHOLDER", r"\result == 2")
            .replace("return 1", "RETURN_PLACEHOLDER")
            .replace("return 2", "return 1")
            .replace("RETURN_PLACEHOLDER", "return 2"))


def test_line_assert_cannot_hide_following_assumption():
    changed = PAIR.replace(
        "public int first() { return 1; }",
        "public int first() {\n        //@ assert true; assume false;\n        return 1;\n    }",
    )
    assert trusted_surface_matches(PAIR, changed)[0] is False


def test_block_assert_cannot_hide_following_assumption():
    changed = PAIR.replace(
        "public int first() { return 1; }",
        "public int first() {\n        /*@ assert true; assume false; @*/\n"
        "        return 1;\n    }",
    )
    assert trusted_surface_matches(PAIR, changed)[0] is False


def test_ordinary_comment_cannot_keep_disabled_contract_active():
    changed = PAIR.replace(
        r"    //@ ensures \result == 1;",
        "    /*\n    //@ ensures \\result == 1;\n    */",
    )
    assert trusted_surface_matches(PAIR, changed)[0] is False


def test_jml_markers_inside_java_literals_and_comments_are_inactive():
    changed = PAIR.replace(
        "return 1;",
        'String text = "//@ assume false;"; /* //@ assume false; */ return 1;',
    )
    assert trusted_surface_matches(PAIR, changed)[0] is True


def test_unsupported_active_jml_fails_closed():
    changed = PAIR.replace(
        "return 1;", "//@ mystery_proof_directive false;\n        return 1;", 1)
    trusted, differences = trusted_surface_matches(PAIR, changed)
    assert trusted is False
    assert differences["parse_errors"]["actual"]


def test_quantifier_semicolons_do_not_split_contract_statement():
    quantified = PAIR.replace(
        r"\result == 1", r"\result == (\sum int i; 0 <= i && i < 1; 1)")
    reformatted = quantified.replace("i; 0 <=", "i ;  0 <=")
    assert trusted_surface_matches(quantified, reformatted)[0] is True


def test_single_file_refactor_rejects_contract_reassignment_before_proof(tmp_path):
    before = tmp_path / "before" / "Pair.java"
    after = tmp_path / "after" / "Pair.java"
    before.parent.mkdir()
    after.parent.mkdir()
    before.write_text(PAIR, encoding="utf-8")
    after.write_text(_swap_contracts_and_bodies(PAIR), encoding="utf-8")
    with patch("pipeline.refactor_gate.verify") as verifier:
        result = verify_contract_preserving_refactor(before, after)
    assert result["code"] == "contract_surface_changed"
    verifier.assert_not_called()


def test_multifile_refactor_rejects_contract_reassignment_before_proof(tmp_path):
    before = tmp_path / "before" / "Pair.java"
    after = tmp_path / "after"
    before.parent.mkdir()
    after.mkdir()
    before.write_text(PAIR, encoding="utf-8")
    (after / "Pair.java").write_text(_swap_contracts_and_bodies(PAIR), encoding="utf-8")
    with patch("pipeline.refactor_gate.verify") as verifier, \
         patch("pipeline.refactor_gate.verify_files") as verifier_files:
        result = verify_multifile_contract_refactor(before, after)
    assert result["code"] == "primary_contract_surface_changed"
    verifier.assert_not_called()
    verifier_files.assert_not_called()


@pytest.mark.parametrize("negative", [
    {"dropped_obligations": True},
    {"obligations_complete": False},
    {"request_satisfied": False},
])
def test_normalization_preserves_explicit_negative_evidence(negative):
    incoming = {"status": "VERIFIED", "exit_code": 0,
                "claim": "DEDUCTIVE_PROOF", **negative}
    result = decide_result(incoming, tool="openjml", mode="esc")
    assert result["claim"] == "NO_PROOF"
    assert result["request_satisfied"] is False


def test_same_request_normalization_is_assurance_idempotent():
    incoming = {"status": "VERIFIED", "exit_code": 0,
                "claim": "DEDUCTIVE_PROOF"}
    once = decide_result(incoming, tool="openjml", mode="esc")
    twice = decide_result(once, tool="openjml", mode="esc")
    for field in ("verification", "claim", "request_satisfied",
                  "dropped_obligations", "obligations_complete",
                  "evidence_consistent"):
        assert twice[field] == once[field]


def test_explicit_false_cannot_suppress_dropped_obligation_marker():
    result = decide_verification(
        tool="openjml", mode="esc", exit_code=0, status="VERIFIED",
        output="Not implemented for static checking",
        dropped_obligations=False,
    )
    assert result["dropped_obligations"] is True
    assert result["request_satisfied"] is False
    assert result["evidence_consistent"] is False
