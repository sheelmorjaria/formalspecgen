import importlib

import pytest

from pipeline.architecture import lint_architecture, parse_architecture
from pipeline.jml_to_dafny import UnsupportedBoundary, translate_jml_to_dafny

pp = importlib.import_module("formalspec_core.postprocess")


def test_bitshift_and_sum_passes_cover_safe_fallbacks():
    already_bounded = "while ((1 << shift) < n) { } // shift <= 30"
    assert pp.inject_bitshift_bounds(already_bounded) == already_bounded

    no_loop = "int shifted = 1 << shift;"
    assert pp.inject_bitshift_bounds(no_loop) == no_loop

    base = r"//@ ensures \result == (\sum int j; j >= 0; a[j]);\nreturn sum;"
    assert pp.inject_sum_invariant(base) == base

    no_matching_loop = (
        r"//@ ensures \result == (\sum int j; 0 <= j && j < a.length; a[j]);"
        "\nwhile (i < n) {}\nreturn sum;"
    )
    assert pp.inject_sum_invariant(no_matching_loop) == no_matching_loop

    no_return = (
        r"//@ ensures \result == (\sum int j; 0 <= j && j < a.length; a[j]);"
        "\nwhile (i < a.length) {}"
    )
    assert pp.inject_sum_invariant(no_return) == no_return

    counter_is_result = (
        r"//@ ensures \result == (\sum int j; 0 <= j && j < a.length; a[j]);"
        "\nwhile (i < a.length) {}\nreturn i;"
    )
    assert pp.inject_sum_invariant(counter_is_result) == counter_is_result

    without_prior_invariant = (
        r"//@ ensures \result == (\sum int j; 0 <= j && j < a.length; a[j]);"
        "\nwhile (i < a.length) {}\nreturn sum;"
    )
    assert "loop_invariant sum ==" in pp.inject_sum_invariant(without_prior_invariant)


def test_sum_helper_defaults_and_unsupported_aggregate_are_fail_safe():
    unsupported = r"//@ ensures \result == (\sum int k; 0 <= k && k < n; k);"
    assert pp.inject_sum_helper(unsupported) == unsupported

    supported = r"""public class Sum {
//@ ensures \result == (\sum int k; 0 <= k && k < a.length; a[k]);
public static int total(int[] a) { int sum = 0; return sum; }
}"""
    result = pp.inject_sum_helper(supported)
    assert "a.length <= 100" in result
    assert "a[k] <= 1000000" in result


def test_old_snapshot_and_pure_injection_ignore_unreviewed_shapes():
    unrelated = r"//@ loop_invariant (\forall int k; 0 <= k && k < i; a[k] >= 0);"
    assert pp.inject_bidirectional_old(unrelated) == unrelated

    library_call = "//@ ensures Math.abs(x) >= 0;\npublic int f(int x) { return x; }"
    assert pp.inject_pure(library_call) == library_call

    already_pure = "//@ ensures helper(x) >= 0;\n/*@ pure @*/\nprivate int helper(int x) { return x; }"
    assert pp.inject_pure(already_pure) == already_pure


def test_dafny_translation_rejects_missing_or_ambiguous_recursive_helpers():
    with pytest.raises(UnsupportedBoundary, match="expected one public static method"):
        translate_jml_to_dafny(r"class C { //@ ensures \old(a)[0] == 1; }")

    multiple = """
public class Helpers {
  public static /*@ pure @*/ int first(int n) {
    return n == 0 ? 0 : first(n - 1);
  }
  public static /*@ pure @*/ int second(int n) {
    return n == 0 ? 0 : second(n - 1);
  }
}
"""
    with pytest.raises(UnsupportedBoundary, match="exactly one recursive pure helper"):
        translate_jml_to_dafny(multiple)

    wrong_counted_array = r"""
public class Sort {
  //@ ensures (\num_of int k; 0 <= k && k < a.length; b[k] == 1) >= 0;
  public static void sort(int[] a) {}
}
"""
    with pytest.raises(UnsupportedBoundary, match="does not count values"):
        translate_jml_to_dafny(wrong_counted_array)

    unterminated = """
public class Helper {
  public static /*@ pure @*/ int helper(int n) {
    return n == 0 ? 0 : helper(n - 1);
"""
    with pytest.raises(UnsupportedBoundary, match="unterminated pure helper"):
        translate_jml_to_dafny(unterminated)


def test_dafny_recursive_precondition_and_balance_rejections():
    jml_precondition = r"""
public class Helper {
  //@ requires (\forall int k; 0 <= k && k < n; k >= 0);
  public static /*@ pure @*/ int helper(int n) {
    return n == 0 ? 0 : helper(n - 1);
  }
}
"""
    with pytest.raises(UnsupportedBoundary, match="unsupported JML construct"):
        translate_jml_to_dafny(jml_precondition)

    unbalanced = """
public class Helper {
  public static /*@ pure @*/ int helper(int n) {
    return helper(n - 1));
  }
}
"""
    with pytest.raises(UnsupportedBoundary, match="unbalanced pure-helper expression"):
        translate_jml_to_dafny(unbalanced)


@pytest.mark.parametrize(
    ("expression", "message"),
    [
        ("n == 0 ? 0 : helper(n - 1", "unbalanced or incomplete"),
        ("helper(n - 1) : 1", "nested"),
        ("this.value + helper(n - 1)", "mutation, allocation, or member access"),
    ],
)
def test_dafny_recursive_expression_rejections(expression, message):
    source = f"""
public class Helper {{
  public static /*@ pure @*/ int helper(int n) {{
    return {expression};
  }}
}}
"""
    with pytest.raises(UnsupportedBoundary, match=message):
        translate_jml_to_dafny(source)


def test_architecture_reports_concrete_edges_and_unestablished_preconditions():
    architecture = parse_architecture({
        "name": "Edges",
        "components": [
            {"id": "adapter", "name": "Adapter", "layer": "adapters", "kind": "class",
             "dependencies": [{"target": "infra", "abstraction": False}]},
            {"id": "infra", "name": "Infra", "layer": "infrastructure", "kind": "class",
             "operations": [{"name": "save", "requires": ["authorized"], "ensures": ["saved"]}]},
        ],
        "use_cases": [{"name": "Save", "requires": [], "ensures": ["saved"],
                       "steps": [{"component": "infra", "operation": "save"}]}],
    })
    codes = {warning["code"] for warning in lint_architecture(architecture)}
    assert {"concrete-dependency", "composition-precondition"} <= codes
