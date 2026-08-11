import importlib

pp = importlib.import_module("formalspec_core.postprocess")


def test_condition_normalization_negation_and_exit_stripping():
    assert pp._norm(" a <  b ") == "a<b"
    assert {"i >= n", "n <= i"} <= set(pp._negate_cond("i < n"))
    assert pp._negate_cond("ready") == []
    code = """//@ loop_invariant i >= n;
while (i < n) {
    i++;
}"""
    assert "STRIPPED exit-condition" in pp.strip_exit_invariants(code)
    assert pp.strip_exit_invariants("while (ready) {}") == "while (ready) {}"


def test_result_invariant_and_inner_loop_spec_rewrites():
    code = """for (int i = 0; i < n; i++) {
    //@ loop_invariant \\result >= 0;
    //@ decreases n - i;
    work();
}"""
    stripped = pp.strip_result_from_invariants(code)
    assert "\\result not valid" in stripped
    movable = """for (int i = 0; i < n; i++) {
    //@ loop_invariant 0 <= i;
    //@ decreases n - i;
    work();
}"""
    moved = pp.fix_inner_loop_spec_placement(movable)
    assert moved.index("decreases") < moved.index("for (")


def test_overflow_and_bitshift_bounds_are_injected_once():
    overflow = """//@ requires y <= 100;
//@ loop_invariant r * r <= y;
while (r < y) {
}"""
    transformed = pp.inject_overflow_bounds(overflow)
    assert "loop_invariant r <= 10" in transformed
    assert pp.inject_overflow_bounds(transformed) == transformed
    assert pp.inject_overflow_bounds("//@ loop_invariant r * r <= y;\n") == "//@ loop_invariant r * r <= y;\n"

    with_inv = "//@ loop_invariant shift >= 0;\nwhile ((1 << shift) < n) {}\n"
    assert "shift <= 30" in pp.inject_bitshift_bounds(with_inv)
    no_inv = "while ((1 << shift) < n) {}\n"
    assert pp.inject_bitshift_bounds(no_inv).lstrip().startswith("//@ loop_invariant shift <= 30")
    assert pp.inject_bitshift_bounds("while (i < n) {}") == "while (i < n) {}"


def test_sum_invariant_injection_and_skip_paths():
    code = r"""//@ ensures \result == (\sum int j; 0 <= j && j < a.length; a[j]);
//@ loop_invariant 0 <= i;
while (i < a.length) {
    sum += a[i++];
}
return sum;
"""
    result = pp.inject_sum_invariant(code)
    assert r"sum == (\sum int j; 0 <= j && j < i; a[j])" in result
    assert pp.inject_sum_invariant(result) == result
    assert pp.inject_sum_invariant("return sum;") == "return sum;"


def test_sum_helper_replaces_supported_aggregate_and_appends_pure_helper():
    code = r"""public class Sum {
//@ requires a.length <= 20;
//@ requires (\forall int k; 0 <= k && k < a.length; a[k] >= 0);
//@ ensures \result == (\sum int k; 0 <= k && k < a.length; a[k]);
//@ ensures (\sum int k; 0 <= k && k < a.length; a[k]) <= 500;
public static int total(int[] a) {
  int sum = 0;
  //@ loop_invariant sum <= 500;
  return sum;
}
}"""
    result = pp.inject_sum_helper(code)
    assert "\\sum" not in result
    assert "sumOf(a, a.length)" in result
    assert "public static int sumOf(int[] a, int n)" in result
    assert "a[k] <= 500" in result and "a.length <= 20" in result
    assert "loop_invariant sum <= 500" not in result
    assert pp.inject_sum_helper("class C {}") == "class C {}"


def test_old_array_mirror_frame_and_array_guard():
    code = r"""//@ loop_invariant (\forall int k; 0 <= k && k < i; a[k] == \old(a)[a.length - 1 - k]);
while (i < a.length / 2) {
}
"""
    result = pp.inject_bidirectional_old(code)
    assert r"a[a.length - 1 - k] == \old(a)[k]" in result
    assert r"i <= k" in result and r"a[k] == \old(a)[k]" in result
    guarded = pp.guard_array_access("result == -1 || a[result] == key;")
    assert "0 <= result && result < a.length" in guarded
    assert pp.guard_array_access(guarded) == guarded


def test_sorted_pure_and_nonlinear_index_rewrites_are_idempotent():
    sorted_contract = r"""//@ requires (\forall int q; 0 <= q && q < a.length - 1; a[q] <= a[q + 1]);
public int find(int[] a) { return 0; }
"""
    strengthened = pp.strengthen_sorted(sorted_contract)
    assert r"\forall int i, j" in strengthened
    assert pp.strengthen_sorted(strengthened) == strengthened

    pure_code = """//@ ensures helper(x) > 0;
public int api(int x) { return helper(x); }
private static int helper(int x) { return x; }
"""
    pure = pp.inject_pure(pure_code)
    assert "/*@ pure @*/" in pure
    assert pp.inject_pure(pure) == pure

    access = "int x = a[i * cols + j];\n"
    assumed = pp.inject_nonlinear_index_assume(access)
    assert "assume 0 <= i * cols + j" in assumed
    assert pp.inject_nonlinear_index_assume(assumed) == assumed
    assert pp.inject_nonlinear_index_assume("//@ ensures a[i * n] == 0;") == "//@ ensures a[i * n] == 0;"


def test_full_postprocess_pipeline_combines_safe_rewrites():
    code = """public class Shift {
//@ ensures helper(x) >= 0;
public int f(int x) {
  //@ loop_invariant \\result >= 0;
  while ((1 << x) < 100) { x++; }
  return helper(x);
}
private int helper(int x) { return x; }
}"""
    result = pp.postprocess(code)
    assert "\\result not valid" in result
    assert "x <= 30" in result
    assert "/*@ pure @*/" in result


def test_exclusion_invariant_guard_is_narrow_and_idempotent():
    code = """public class Lights {
//@ public invariant !(north == 2 && east == 2);
public boolean northGreen() {
  if (north != 2) {
    north = 2;
    return true;
  }
  return false;
}
public boolean eastGreen() {
  if (north == 0) {
    east = 2;
    return true;
  }
  return false;
}
}"""
    guarded = pp.guard_exclusion_invariants(code)
    assert "if ((north != 2) && east != 2)" in guarded
    assert "if (north == 0)" in guarded
    assert pp.guard_exclusion_invariants(guarded) == guarded
    assert pp.guard_exclusion_invariants("if (x) { north = 2; }") == "if (x) { north = 2; }"
