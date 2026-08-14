from types import SimpleNamespace
from unittest.mock import patch

from pipeline import cli
from pipeline.refactor_gate import public_method_surface, verify_contract_preserving_refactor


BASELINE = """public class Account {
    //@ requires true;
    //@ ensures \\result >= 0;
    public int balance() { return 1; }
}
"""
REFACTORED = BASELINE.replace("return 1", "int current = 1; return current")


def _files(tmp_path, before=BASELINE, after=REFACTORED, suffix=".java"):
    baseline = tmp_path / "before" / f"Account{suffix}"
    refactored = tmp_path / "after" / f"Account{suffix}"
    baseline.parent.mkdir(exist_ok=True)
    refactored.parent.mkdir(exist_ok=True)
    baseline.write_text(before, encoding="utf-8")
    refactored.write_text(after, encoding="utf-8")
    return baseline, refactored


def test_contract_preserving_refactor_mints_only_scoped_claim(tmp_path):
    baseline, refactored = _files(tmp_path)
    with patch("pipeline.refactor_gate.verify", side_effect=[(0, ""), (0, "proved"),
                                                             (0, ""), (0, "proved")]):
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert result["contract_surface_preserved"]
    assert not result["behavior_equivalence_proved"]
    assert not result["refactor_verified"]
    assert result["baseline_sha256"] != result["refactored_sha256"]


def test_algorithm_refactor_allows_different_loop_proof_hints(tmp_path):
    before = BASELINE.replace(
        "public int balance() { return 1; }",
        "//@ loop_invariant i >= 0;\n    //@ decreases 10 - i;\n"
        "    public int balance() { return 1; }")
    after = REFACTORED.replace(
        "public int balance() { int current = 1; return current; }",
        "//@ loop_invariant j >= 0;\n    //@ decreases j;\n"
        "    public int balance() { int current = 1; return current; }")
    baseline, refactored = _files(tmp_path, before=before, after=after)
    with patch("pipeline.refactor_gate.verify", side_effect=[(0, ""), (0, "proved"),
                                                               (0, ""), (0, "proved")]):
        result = verify_contract_preserving_refactor(baseline, refactored)
    assert result["claim"] == "REFACTOR_CONTRACT_PRESERVED"


def test_refactor_surface_boundaries_fail_closed(tmp_path):
    missing = verify_contract_preserving_refactor(tmp_path / "missing.java", tmp_path / "x.java")
    assert missing["code"] == "source_unavailable"

    baseline, refactored = _files(tmp_path, suffix=".txt")
    assert verify_contract_preserving_refactor(baseline, refactored)["code"] == \
        "unsupported_language"

    baseline, refactored = _files(tmp_path, after=REFACTORED.replace("Account", "Ledger"))
    assert verify_contract_preserving_refactor(baseline, refactored)["code"] == \
        "class_identity_changed"

    wrong_layout = tmp_path / "after" / "Wrong.java"
    wrong_layout.write_text(REFACTORED, encoding="utf-8")
    assert verify_contract_preserving_refactor(baseline, wrong_layout)["code"] == \
        "source_layout_invalid"

    baseline, refactored = _files(tmp_path, before="public class Account {}",
                                  after="public class Account { }\n")
    assert verify_contract_preserving_refactor(baseline, refactored)["code"] == \
        "missing_trusted_contract"

    baseline, refactored = _files(
        tmp_path, after=REFACTORED.replace("\\result >= 0", "\\result > 0"))
    assert verify_contract_preserving_refactor(baseline, refactored)["code"] == \
        "contract_surface_changed"

    baseline, refactored = _files(
        tmp_path, after=REFACTORED.replace("balance()", "balance(int ignored)"))
    assert verify_contract_preserving_refactor(baseline, refactored)["code"] == \
        "method_surface_changed"

    baseline, refactored = _files(tmp_path, after=BASELINE)
    assert verify_contract_preserving_refactor(baseline, refactored)["code"] == \
        "source_unchanged"


def test_each_openjml_failure_blocks_the_refactor_claim(tmp_path):
    baseline, refactored = _files(tmp_path)
    cases = [
        ([(1, "compile")], "baseline_not_verified"),
        ([(0, ""), (6, "vc")], "baseline_not_verified"),
        ([(0, ""), (0, "dropped")], "baseline_not_verified"),
        ([(0, ""), (0, "ok"), (1, "compile")], "refactored_not_verified"),
    ]
    for responses, expected in cases:
        with patch("pipeline.refactor_gate.verify", side_effect=responses), \
             patch("pipeline.refactor_gate.has_dropped_vc",
                   return_value=responses[-1][1] == "dropped"):
            result = verify_contract_preserving_refactor(baseline, refactored)
        assert result["code"] == expected
        assert result["verification"]["status"] == "FAIL"


def test_public_method_surface_and_cli_route(tmp_path):
    assert public_method_surface(
        "public class A {\n protected static final int f( int x ) throws E { return x; }\n}") == [
            "protected static final int f( int x ) throws E"]
    baseline, refactored = _files(tmp_path)
    output = tmp_path / "verdict.json"
    args = cli.build_parser().parse_args([
        "verify-refactor", str(baseline), str(refactored), "--json", str(output)])
    ui = SimpleNamespace(console=SimpleNamespace(print=lambda *_args, **_kwargs: None))
    with patch("pipeline.refactor_gate.verify_contract_preserving_refactor",
               return_value={"status": "VERIFIED", "claim": "REFACTOR_CONTRACT_PRESERVED"}):
        assert cli.dispatch(args, ui, None, {}) == 0
    assert "REFACTOR_CONTRACT_PRESERVED" in output.read_text(encoding="utf-8")
    with patch("pipeline.refactor_gate.verify_contract_preserving_refactor",
               return_value={"status": "FAIL", "claim": "NO_PROOF"}):
        assert cli.command_verify_refactor(args, ui) == 1
