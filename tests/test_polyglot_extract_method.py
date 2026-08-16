"""M2: AST-guided string-splicing extract-method for rust, c, and cpp.

Tree-sitter supplies byte coordinates only; the transformation itself is
slicing and splicing the RAW source so formatting, comments, and native
contracts (Prusti attributes, ACSL blocks, C++ asserts) move verbatim.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.polyglot_extract_method import (
    extract_method_polyglot,
    locate_function,
)

RUST_SRC = """use prusti_contracts::*;

#[requires(val >= 0)]
#[ensures(result >= val)]
pub fn process(val: i32) -> i32 {
    val + 1
}

pub fn untouched() {}
"""

RUST_METHOD = """use prusti_contracts::*;

pub struct Counter { pub count: i32 }

impl Counter {
    #[requires(val >= 0)]
    pub fn add(&mut self, val: i32) {
        self.count += val;
    }
}
"""

C_SRC = """#include <stdbool.h>

/*@
  requires \\valid(count);
  requires val >= 0;
*/
void add(int* count, int val) {
    *count += val;
}

void keep(void) {}
"""

C_BOOL = """#include <stdbool.h>

/*@ requires x > 0; ensures \\result == true; */
bool ok(int x) {
    return x > 0;
}
"""

CPP_IN_CLASS = """#include <cassert>

class Counter {
public:
    int count;
    void add(int val) {
        assert(val >= 0);
        this->count += val;
    }
};
"""

CPP_OUT_OF_LINE = """class Counter {
public:
    int count;
    void add(int val);
};

void Counter::add(int val) {
    this->count += val;
}
"""


# ------------------------------------------------------------- phase 1: find ---

def test_rust_function_offsets_include_attributes_and_body():  # user Test 1.1
    located = locate_function(RUST_SRC, "rust", "process")
    assert RUST_SRC[located["body_start"]:located["body_end"]] == "{\n    val + 1\n}"
    signature = RUST_SRC[located["function_start"]:located["body_start"]]
    assert "pub fn process(val: i32) -> i32" in signature
    contract = RUST_SRC[located["contract_start"]:located["function_start"]]
    assert contract == "#[requires(val >= 0)]\n#[ensures(result >= val)]\n"


def test_c_function_offsets_capture_preceding_acsl():  # user Test 1.2
    located = locate_function(C_SRC, "c", "add")
    assert C_SRC[located["body_start"]:located["body_end"]] == "{\n    *count += val;\n}"
    assert "void add(int* count, int val)" in C_SRC[located["function_start"]:located["body_start"]]
    assert C_SRC[located["contract_start"]:located["function_start"]].startswith("/*@")


def test_cpp_method_offsets_for_out_of_line_definition():  # user Test 1.3
    located = locate_function(CPP_OUT_OF_LINE, "cpp", "add")
    assert "this->count += val;" in CPP_OUT_OF_LINE[located["body_start"]:located["body_end"]]


def test_locate_failures():
    assert locate_function(RUST_SRC, "rust", "missing")["status"] == "FAIL"
    assert locate_function(RUST_SRC, "rust", "missing")["code"] == "method_not_found"
    prototype_only = "void decl(int);\n"
    assert locate_function(prototype_only, "c", "decl")["code"] == "method_not_found"
    duplicate = RUST_SRC + "\npub fn process() {}\n"
    assert locate_function(duplicate, "rust", "process")["code"] == "ambiguous_method"
    assert locate_function("int broken({", "c", "broken")["code"] == "source_parse_error"


# -------------------------------------------------- phase 2: splice and inject ---

def test_rust_value_function_delegates_via_tail_expression():  # user Test 2.1
    result = extract_method_polyglot(RUST_SRC, "rust", "process")
    assert result["status"] == "TRANSFORMED"
    refactored = result["source"]
    assert ("#[requires(val >= 0)]\n#[ensures(result >= val)]\n"
            "fn process_helper(val: i32) -> i32 {\n"
            "    val + 1\n}") in refactored
    assert "pub fn process(val: i32) -> i32 { process_helper(val) }" in refactored
    assert refactored.index("fn process_helper(") < refactored.index("pub fn process(")
    assert "pub fn untouched() {}" in refactored  # untouched code stays byte-identical


def test_rust_method_helper_stays_inside_impl_and_threads_self():
    result = extract_method_polyglot(RUST_METHOD, "rust", "add")
    assert result["status"] == "TRANSFORMED"
    refactored = result["source"]
    assert "fn add_helper(&mut self, val: i32) {" in refactored
    assert "self.count += val;" in refactored  # body moved intact
    assert "pub fn add(&mut self, val: i32) { self.add_helper(val); }" in refactored
    impl_start = refactored.index("impl Counter {")
    impl_body = refactored[impl_start:refactored.rindex("}")]
    assert "fn add_helper" in impl_body and "pub fn add" in impl_body  # helper inside impl


def test_c_helper_is_static_and_carries_the_acsl_contract():  # user Test 2.2
    result = extract_method_polyglot(C_SRC, "c", "add")
    assert result["status"] == "TRANSFORMED"
    refactored = result["source"]
    assert "static void add_helper(int* count, int val) {" in refactored
    assert "void add(int* count, int val) { add_helper(count, val); }" in refactored
    assert refactored.index("add_helper(int* count") < refactored.index("void add(int* count")
    assert refactored.count("/*@") == 2  # contract duplicated onto helper AND wrapper
    assert "void keep(void) {}" in refactored


def test_c_value_returning_wrapper_returns_helper_call():
    result = extract_method_polyglot(C_BOOL, "c", "ok")
    refactored = result["source"]
    assert "static bool ok_helper(int x) {" in refactored
    assert "bool ok(int x) { return ok_helper(x); }" in refactored


def test_cpp_in_class_helper_and_moved_asserts():
    result = extract_method_polyglot(CPP_IN_CLASS, "cpp", "add")
    assert result["status"] == "TRANSFORMED"
    refactored = result["source"]
    assert "void add_helper(int val) {" in refactored
    assert "void add(int val) { add_helper(val); }" in refactored
    assert "assert(val >= 0);" in refactored  # bounded obligation moved with the body


def test_cpp_override_is_stripped_from_the_helper():
    override = """class Base {
public:
    virtual bool check(int v) { return true; }
};

class Derived : public Base {
public:
    bool validate(int v) override { return v > 0; }
};
"""
    result = extract_method_polyglot(override, "cpp", "validate")
    refactored = result["source"]
    assert "bool validate_helper(int v) {" in refactored  # no override on the helper
    assert "bool validate(int v) override { return validate_helper(v); }" in refactored


def test_locals_move_with_the_body_no_hoisting_needed():  # user Test 2.3, whole-body form
    locals_src = """use prusti_contracts::*;

#[requires(n >= 0)]
pub fn total(n: i32) -> i32 {
    let mut acc = 0;
    acc += n;
    acc
}
"""
    result = extract_method_polyglot(locals_src, "rust", "total")
    refactored = result["source"]
    helper = refactored.index("fn total_helper")
    wrapper = refactored.index("pub fn total(")
    assert "let mut acc = 0;" in refactored[helper:wrapper]  # local lives in the helper
    assert "pub fn total(n: i32) -> i32 { total_helper(n) }" in refactored


def test_unsupported_shapes_fail_closed():
    result = extract_method_polyglot(CPP_OUT_OF_LINE, "cpp", "add")
    assert result["status"] == "FAIL"
    assert result["code"] == "unsupported_cpp_out_of_line"

    assert extract_method_polyglot("int x;", "java", "x")["code"] == "unsupported_language"
    assert extract_method_polyglot(RUST_SRC, "rust", "missing")["code"] == "method_not_found"


def test_transformation_evidence_binds_offsets_and_hashes():
    result = extract_method_polyglot(RUST_SRC, "rust", "process")
    assert result["helper_name"] == "process_helper"
    assert result["language"] == "rust"
    offsets = result["offsets"]
    assert offsets["contract_start"] < offsets["function_start"] < offsets["body_start"]
    assert RUST_SRC[offsets["body_start"]:offsets["body_end"]] == "{\n    val + 1\n}"
    assert result["baseline_sha256"] != result["refactored_sha256"]


# --------------------------------------------- phase 3: gate + CLI integration ---

def test_gate_allows_added_helper_but_not_removed_api(tmp_path):
    from pipeline.refactor_gate import verify_contract_preserving_refactor

    baseline = tmp_path / "add.c"
    refactored = tmp_path / "add_ref.c"
    baseline.write_text(C_SRC, encoding="utf-8")
    transformed = extract_method_polyglot(C_SRC, "c", "add")
    refactored.write_text(transformed["source"], encoding="utf-8")

    verified = {"status": "VERIFIED", "output": "proved", "claim": "DEDUCTIVE_PROOF"}
    from unittest.mock import patch
    with patch("pipeline.refactor_gate._polyglot_verification",
               side_effect=[verified, dict(verified)]) as prove:
        verdict = verify_contract_preserving_refactor(baseline, refactored)
    assert prove.call_count == 2  # baseline and refactored both re-proved
    assert verdict["status"] == "VERIFIED"
    assert verdict["claim"] == "REFACTOR_CONTRACT_PRESERVED"

    shrunk = tmp_path / "shrunk.c"
    shrunk.write_text(C_SRC.replace("void keep(void) {}", ""), encoding="utf-8")
    with patch("pipeline.refactor_gate._polyglot_verification",
               side_effect=[verified, dict(verified)]):
        verdict = verify_contract_preserving_refactor(baseline, shrunk)
    assert verdict["status"] == "FAIL"
    assert verdict["code"] == "method_surface_changed"


def test_apply_writes_refactored_file_and_runs_the_gate(tmp_path):
    from pipeline.polyglot_extract_method import apply_extract_method_polyglot

    baseline = tmp_path / "process.rs"
    baseline.write_text(RUST_SRC, encoding="utf-8")
    destination = tmp_path / "process_refactored.rs"
    verified = {"status": "VERIFIED", "output": "proved", "claim": "DEDUCTIVE_PROOF"}
    from unittest.mock import patch
    with patch("pipeline.refactor_gate._polyglot_verification",
               side_effect=[verified, dict(verified)]):
        result = apply_extract_method_polyglot(baseline, "process", destination)
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert "fn process_helper" in destination.read_text(encoding="utf-8")
    assert result["transformation"]["helper_name"] == "process_helper"
    assert "source" not in result["transformation"]  # code lives on disk, not in JSON

    broken = tmp_path / "broken.rs"
    broken.write_text("pub fn empty() {}\n", encoding="utf-8")
    result = apply_extract_method_polyglot(broken, "process", tmp_path / "out.rs")
    assert result["status"] == "FAIL"


def test_cli_routes_polyglot_and_guards_java_inspection(tmp_path):
    from pipeline import cli

    baseline = tmp_path / "process.rs"
    baseline.write_text(RUST_SRC, encoding="utf-8")
    verdict_path = tmp_path / "verdict.json"

    from unittest.mock import patch
    ok = {"status": "VERIFIED", "claim": "REFACTOR_CONTRACT_PRESERVED",
          "transformation": {"helper_name": "process_helper"}, "verification": {}}
    with patch("pipeline.polyglot_extract_method.apply_extract_method_polyglot",
               return_value=dict(ok)) as apply:
        args = cli.build_parser().parse_args(
            ["apply-refactor", str(baseline), "--method", "process",
             "--pattern", "extract-method", "--out", str(tmp_path / "out.rs"),
             "--json", str(verdict_path)])
        code = cli.command_apply_refactor(args, _ui())
    assert code == 0
    assert apply.call_args.args[1] == "process"
    assert json.loads(verdict_path.read_text(encoding="utf-8"))["claim"] == \
        "REFACTOR_CONTRACT_PRESERVED"

    with patch("pipeline.polyglot_extract_method.apply_extract_method_polyglot",
               return_value={"status": "FAIL", "claim": "NO_PROOF"}):
        args = cli.build_parser().parse_args(
            ["apply-refactor", str(baseline), "--method", "process",
             "--pattern", "extract-method", "--out", str(tmp_path / "o.rs")])
        assert cli.command_apply_refactor(args, _ui()) == 1

    # polyglot lane rejects non-extract-method patterns; java lane needs --inspection
    args = cli.build_parser().parse_args(
        ["apply-refactor", str(baseline), "--method", "process",
         "--pattern", "strategy", "--out", str(tmp_path / "o.rs")])
    assert cli.command_apply_refactor(args, _ui()) == 2

    java = tmp_path / "Plain.java"
    java.write_text("public class Plain {}\n", encoding="utf-8")
    args = cli.build_parser().parse_args(
        ["apply-refactor", str(java), "--method", "m",
         "--pattern", "extract-method", "--out", str(tmp_path / "p.java")])
    assert cli.command_apply_refactor(args, _ui()) == 2


def _ui():
    import io
    from rich.console import Console
    from pipeline import cli
    return cli.TerminalUI(Console(file=io.StringIO(), force_terminal=False, width=120),
                          lambda _prompt: "answer")


def test_exotic_c_shapes_and_apply_failures(tmp_path, monkeypatch):
    """Pointer returns, callback params, (void) lists, non-adjacent contracts."""
    exotic = """int* pick(int* xs) { return xs; }

void run_cb(int (*cb)(int), int v) { cb(v); }

static void nop(void) { (void)0; }

int (paren)(int x) { return x; }

/*@ requires x > 0; */
int split_contract(int x) { return x; }
"""
    for name, fragment in (("pick", "return xs;"), ("run_cb", "cb(v);"),
                           ("nop", "(void)0;"), ("split_contract", "return x;")):
        result = extract_method_polyglot(exotic, "c", name)
        assert result["status"] == "TRANSFORMED", (name, result)
        refactored = result["source"]
        assert fragment in refactored
        assert f"{name}_helper(" in refactored
    nop = extract_method_polyglot(exotic, "c", "nop")["source"]
    assert "static void nop_helper(void) {" in nop  # signature copies (void)
    assert "nop(void) { nop_helper(); }" in nop      # but the call passes NO arguments
    # split_contract's ACSL is adjacent (newline-only gap), so it is duplicated
    # onto BOTH the helper and the wrapper like every adjacent contract.
    once = extract_method_polyglot(exotic, "c", "split_contract")["source"]
    assert once.count("/*@") == 2
    assert "static int split_contract_helper(int x)" in once  # value → return splice
    assert "int split_contract(int x) { return split_contract_helper(x); }" in once

    from pipeline.polyglot_extract_method import apply_extract_method_polyglot
    assert apply_extract_method_polyglot(
        tmp_path / "missing.rs", "any", tmp_path / "o.rs")["code"] == "source_unavailable"

    java = tmp_path / "Plain.java"
    java.write_text("public class Plain {}\n", encoding="utf-8")
    assert apply_extract_method_polyglot(
        java, "m", tmp_path / "o.java")["code"] == "unsupported_language"

    import pipeline.polyglot_extract_method as splicer
    monkeypatch.setattr(splicer, "Parser", None)
    assert splicer.locate_function(RUST_SRC, "rust", "process")["code"] == \
        "tree_sitter_unavailable"
