from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pipeline import ide
from pipeline.jml_to_dafny import UnsupportedBoundary


def test_apply_passes_order_diff_and_fail_closed_selection():
    calls = []

    def transform(name):
        return lambda code: calls.append(name) or (code + f"\n{name}")

    selected = ["inject_pure", "strip_exit_invariants"]
    patches = [patch.object(ide.local_postprocess, name, transform(name)) for name in selected]
    with patches[0], patches[1]:
        result = ide.apply_passes("source", selected)
    assert calls == ["strip_exit_invariants", "inject_pure"]
    assert result["changed"] and result["requires_human_acceptance"]
    assert all(item["diff"] for item in result["passes"])
    assert ide.apply_passes("source", [])["changed"] is False
    with pytest.raises(ValueError, match="unknown postprocessor"):
        ide.apply_passes("source", ["invent_invariant"])


def test_route_backend_concurrency_jml_and_supported_dafny():
    assert ide.route_backend("synchronized void transfer() {}") ["backend"] == "tla"
    assert ide.route_backend("public int add(int a, int b) {}") ["backend"] == "jml"

    translated = SimpleNamespace(boundary="old_array")
    with patch.object(ide, "translate_jml_to_dafny", return_value=translated):
        result = ide.route_backend(r"ensures a[0] == \old(a)[0]")
    assert result["backend"] == "dafny" and result["executable"]
    assert result["boundary"] == "old_array"


def test_route_backend_reports_unsupported_dafny_without_claiming_execution():
    with patch.object(ide, "translate_jml_to_dafny",
                      side_effect=UnsupportedBoundary("ambiguous old array")):
        result = ide.route_backend(r"ensures a[0] == \old(a)[0]")
    assert result["backend"] == "dafny" and not result["executable"]
    assert "ambiguous" in result["reasons"][-1]


def test_route_backend_identifies_permutation_and_recursive_reasons():
    translated = SimpleNamespace(boundary="permutation_multiset")
    with patch.object(ide, "translate_jml_to_dafny", return_value=translated):
        permutation = ide.route_backend(r"//@ ensures \num_of int k; true; true;")
    assert permutation["backend"] == "dafny"
    assert "multiset" in permutation["reasons"][0]

    translated = SimpleNamespace(boundary="recursive_helper")
    with patch.object(ide, "translate_jml_to_dafny", return_value=translated):
        recursive = ide.route_backend("recursive helper")
    assert recursive["backend"] == "dafny"
    assert "induction" in recursive["reasons"][0]


def test_discover_passes_detects_all_reviewed_shapes():
    code = r"""//@ ensures \sum int i; 0 <= i && i < a.length; a[i] == total;
//@ ensures sorted(a);
//@ ensures a[0] == \old(a)[0];
x = left << shift;
y = width * height;
z = a[i * width];
while (i < n) { //@ loop_invariant i >= 0;
a[i] = z;
"""
    names = {item["name"] for item in ide.discover_passes(code)}
    assert {"inject_bitshift_bounds", "inject_overflow_bounds", "inject_sum_helper",
            "inject_sum_invariant", "inject_bidirectional_old", "guard_array_access",
            "strengthen_sorted", "inject_nonlinear_index_assume",
            "fix_inner_loop_spec_placement"} <= names
