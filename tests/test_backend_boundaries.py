import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pipeline import jml_to_dafny as dafny
from pipeline import tla_backend as tla


REVERSE = r"""public class R {
//@ ensures a[0] == \old(a)[a.length-1];
public static void reverse(int[] a) {}
}"""

PERMUTATION = r"""public class S {
//@ ensures (\num_of int k; 0 <= k && k < a.length; a[k] == 1) >= 0;
public static void sort(int[] a) {}
}"""


def test_dafny_boundary_detection_and_array_lowerings():
    assert dafny.detect_boundary("plain") is None
    assert dafny.detect_boundary(PERMUTATION) == "permutation_multiset"
    assert dafny.detect_boundary(REVERSE) == "heap_snapshot"
    reverse = dafny.translate_jml_to_dafny(REVERSE)
    assert reverse.boundary == "heap_snapshot" and "ghost var a_snapshot" in reverse.dafny_code
    permutation = dafny.translate_jml_to_dafny(PERMUTATION)
    assert "multiset(a[..]) == multiset(old(a[..]))" in permutation.dafny_code


def test_dafny_translation_rejects_unknown_or_ambiguous_shapes():
    with pytest.raises(dafny.UnsupportedBoundary, match="no known"):
        dafny.translate_jml_to_dafny("public static int add(int x) { return x; }")
    with pytest.raises(dafny.UnsupportedBoundary, match="exactly one"):
        dafny.translate_jml_to_dafny(REVERSE.replace("int[] a", "int[] a, int[] b"))
    wrong = REVERSE.replace(r"\old(a)", r"\old(other)")
    with pytest.raises(dafny.UnsupportedBoundary, match="method array"):
        dafny.translate_jml_to_dafny(wrong)


def test_recursive_expression_helpers_fail_closed():
    assert dafny._pure_int_params("") == []
    assert dafny._pure_int_params("int a, int b") == [("a", "int"), ("b", "int")]
    with pytest.raises(dafny.UnsupportedBoundary, match="parameter"):
        dafny._pure_int_params("long value")
    assert dafny._render_pure_expression("n == 0 ? 0 : gcd(n - 1)") == (
        "if n == 0 then 0 else gcd(n - 1)")
    for expression in ("new X()", "this.value", "n ? 1", "(n + 1"):
        with pytest.raises(dafny.UnsupportedBoundary):
            dafny._render_pure_expression(expression)
    assert dafny._preceding_requires("//@ requires n >= 0;\n//@ requires n < 10;\n") == [
        "n >= 0", "n < 10"]


def test_translate_and_verify_missing_success_failure_and_timeout(tmp_path):
    missing = tmp_path / "missing"
    with patch.object(dafny.config, "DAFNY_BIN", str(missing)):
        assert dafny.translate_and_verify(REVERSE).status == "TOOL_MISSING"
    binary = tmp_path / "dafny"
    binary.write_text("", encoding="utf-8")
    for returncode, expected in ((0, "VERIFIED"), (1, "VERIFY_FAILED")):
        completed = SimpleNamespace(returncode=returncode, stdout="out", stderr="err")
        with (patch.object(dafny.config, "DAFNY_BIN", str(binary)),
              patch.object(dafny.subprocess, "run", return_value=completed) as run):
            result = dafny.translate_and_verify(REVERSE)
        assert result.status == expected and result.output == "outerr"
        assert run.call_args.args[0][1] == "verify"
        assert run.call_args.kwargs["env"]["DOTNET_ROOT"] == dafny.config.DOTNET_ROOT
    with (patch.object(dafny.config, "DAFNY_BIN", str(binary)),
          patch.object(dafny.subprocess, "run", side_effect=subprocess.TimeoutExpired("d", 1))):
        assert dafny.translate_and_verify(REVERSE).status == "TIMEOUT"


MODULE = """---- MODULE Mini ----
VARIABLE x
Init == x = 0
Next == x' = x + 1
Spec == Init /\\ [][Next]_<<x>>
===="""
CFG = "SPECIFICATION Spec\nINVARIANT TypeOK\nCHECK_DEADLOCK FALSE"


def test_tla_parse_output_forms_and_validation():
    assert tla.parse_output(f"=== TLA ===\n{MODULE}\n=== CFG ===\n{CFG}\n=== END ===") == (MODULE, CFG)
    fenced = f"```tla+\n{MODULE}\n```\n```cfg\n{CFG}\n```"
    assert tla.parse_output(fenced) == (MODULE, CFG)
    recovered = tla.parse_output(f"prefix\n{MODULE}\nCONFIG:\n{CFG}")
    assert recovered == (MODULE, CFG)
    with pytest.raises(ValueError, match="complete TLA"):
        tla.parse_output("garbage")
    with pytest.raises(ValueError, match="header"):
        tla._validate_output("Init == TRUE", CFG)
    with pytest.raises(ValueError, match="configuration"):
        tla._validate_output(MODULE, "comments only")


def test_tla_cfg_and_syntax_normalization():
    cfg = """SPEC Spec
INIT Ignored
NEXT Ignored
INVARIANTS
- TypeOK
Safe, Bounded
PROPERTY Live
CONSTANT X = 1
"""
    normalized = tla.normalize_cfg(cfg)
    assert "SPECIFICATION Spec" in normalized
    assert "INIT" not in normalized and "NEXT" not in normalized
    assert all(item in normalized for item in ("INVARIANT TypeOK", "INVARIANT Safe",
                                                "INVARIANT Bounded", "PROPERTY Live"))
    source = "---- MODULE M ----\nEXTENDS Int, TLC\nMax = 4L\n===="
    fixed = tla.normalize_tla_syntax(source)
    assert "EXTENDS Integers" in fixed and "Max == 4" in fixed


def test_tla_model_lint_parse_and_process_outcomes():
    conflicting = """---- MODULE M ----
VARIABLES x
Init == x = 0
Next == /\\ x' = 1 /\\ UNCHANGED <<x>>
===="""
    assert "both assigns" in tla.lint_tla_model(conflicting)[0]
    assert tla.lint_tla_model("Init == TRUE") == ["model does not define a top-level Next operator"]
    assert tla.check_tla(conflicting, CFG)["status"] == "MODEL_LINT_FAILED"
    assert tla.check_tla("Init == TRUE", CFG)["status"] == "MODEL_LINT_FAILED"

    outputs = "State 1: <Initial>\n/\\ x = 0\nState 2: <Next>\n/\\ x = 1\n"
    for returncode, expected in ((0, "VERIFIED"), (12, "INVARIANT_VIOLATION"), (1, "TLC_FAILED")):
        completed = SimpleNamespace(returncode=returncode, stdout=outputs, stderr="")
        with patch.object(tla.subprocess, "run", return_value=completed) as run:
            result = tla.check_tla(MODULE, CFG)
        assert result["status"] == expected and len(result["counterexample"]) == 2
        assert "-deadlock" in run.call_args.args[0]
    with patch.object(tla.subprocess, "run", side_effect=subprocess.TimeoutExpired("tlc", 1)):
        assert tla.check_tla(MODULE, CFG)["status"] == "TIMEOUT"
    with patch.object(tla.subprocess, "run", side_effect=FileNotFoundError("java")):
        assert tla.check_tla(MODULE, CFG)["status"] == "TOOL_MISSING"


def test_tla_trace_empty_and_multiple_states():
    assert tla._trace("no states") == []
    assert len(tla._trace("State 1: a\nfoo\nState 2: b\nbar")) == 2


def test_tla_trace_table_extracts_values_and_changes():
    states = tla._trace(
        "State 1: <Initial predicate>\n/\\ balance = 0\n/\\ lock = FALSE\n"
        "State 2: <Deposit line 9>\n/\\ balance = 1\n/\\ lock = FALSE\n"
        "State 3: <Complex>\n/\\ balance = [a |-> 1,\n    b |-> 0]\n/\\ lock = TRUE\n"
    )
    rows = tla.trace_table(states)
    assert rows[0] == {
        "state": 1, "label": "<Initial predicate>",
        "variables": {"balance": "0", "lock": "FALSE"},
        "changed": ["balance", "lock"], "raw": states[0],
    }
    assert rows[1]["changed"] == ["balance"]
    assert rows[2]["variables"]["balance"] == "[a |-> 1, b |-> 0]"
    assert rows[2]["changed"] == ["balance", "lock"]
