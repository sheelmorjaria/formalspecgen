# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M32 Phase 1-3: LLVM IR (.ll) module parsing, CFG extraction, and V2
state-machine transition extraction from the IR — the scale lane.

The fixtures are real `clang 18 -S -emit-llvm -O0` output committed to the
tree (hermetic CI); the round-trip test re-compiles the C at run time when
clang is installed. machine.ll lowers `switch (c->st)` over
``enum state {A,B,C}`` with a guarded case (B branches on ``sig > 0``) —
four (case, stored-constant) pairs in total.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pipeline.llvm_ir import (
    extract_ir_transitions, find_switches, function_cfg,
    ir_cfg_correspondence, parse_llvm_ir,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MACHINE_LL = (FIXTURES / "machine.ll").read_text(encoding="utf-8")
DEVICE_LL = (FIXTURES / "device.ll").read_text(encoding="utf-8")

MACHINE_C = """enum state { A = 0, B = 1, C = 2 };

struct conn {
    enum state st;
};

void step(struct conn *c, int sig) {
    switch (c->st) {
    case A:
        c->st = B;
        break;
    case B:
        if (sig > 0) { c->st = C; } else { c->st = A; }
        break;
    case C:
        c->st = A;
        break;
    }
}
"""


def test_parse_module_functions_and_blocks():
    """Test 1.1: the .ll module parses into functions and basic blocks."""
    module = parse_llvm_ir(MACHINE_LL)
    assert module["status"] == "PARSED"
    assert [f["name"] for f in module["functions"]] == ["step"]
    labels = [b["label"] for b in module["functions"][0]["blocks"]]
    assert labels[0] == "entry"
    assert "24" in labels          # the switch default / merge block
    # garbage fails closed: llvmlite rejects it when installed (the real
    # parser), otherwise the text parser finds no functions
    assert parse_llvm_ir("not llvm at all")["code"] in {
        "ir_parse_error", "no_functions"}


def test_cfg_edges_follow_terminators():
    """Test 1.2: successors come from br / conditional br / switch."""
    cfg = function_cfg(parse_llvm_ir(MACHINE_LL)["functions"][0])
    # switch dispatch: entry -> default + each case block
    assert set(cfg["edges"]["entry"]) == {"24", "8", "11", "21"}
    # the guarded case B branches on sig
    assert set(cfg["edges"]["11"]) == {"14", "17"}


def test_switch_identified_with_case_table():
    """Test 2.1: switch blocks in the IR are found with their cases."""
    switches = find_switches(parse_llvm_ir(MACHINE_LL)["functions"][0])
    assert len(switches) == 1
    assert switches[0]["default"] == "24"
    assert {case["value"] for case in switches[0]["cases"]} == {0, 1, 2}
    assert {case["target"] for case in switches[0]["cases"]} == {"8", "11", "21"}


def test_transitions_extracted_from_ir_cfg():
    """Test 2.2: (case, stored constant) pairs become V2 transitions; the
    guarded case yields one transition per branch arm, exactly like the
    source-level switch dialect."""
    transitions, notes = extract_ir_transitions(
        parse_llvm_ir(MACHINE_LL)["functions"][0])
    assert not notes
    assert {(t["case"], t["value"]) for t in transitions} == {
        (0, 1), (1, 2), (1, 0), (2, 0)}
    assert all(t["field"] == "conn_f0" for t in transitions)


def test_analyze_codebase_registers_ir_candidate(tmp_path):
    """Test 2.2 (end to end): analyze-codebase accepts .ll and registers a
    V2 candidate from the CFG — not the source text."""
    from pipeline.codebase_analysis import analyze_codebase
    import yaml
    source = tmp_path / "legacy"
    source.mkdir()
    (source / "machine.ll").write_text(MACHINE_LL, encoding="utf-8")
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    extracted = [w for w in result["warnings"]
                 if w["code"] == "IR_MACHINE_EXTRACTED"]
    assert extracted and "4 transitions" in extracted[0]["message"]
    candidate = tmp_path / "domains" / "candidates" / "conn.v2.yaml"
    assert candidate.exists()
    payload = yaml.safe_load(candidate.read_text(encoding="utf-8"))
    assert payload["state_variables"][0]["name"] == "conn_f0"
    assert len(payload["operations"]) == 4
    guards = {op["guards"][0]["expression"]["right"]["value"]
              for op in payload["operations"]}
    assert guards == {0, 1, 2}


def test_correspondence_gate_proves_and_fails_closed():
    """Test 2.3: the deterministic CFG<->model correspondence — every IR
    case-store is modeled, every model transition traces back. Missing and
    untraced transitions both fail closed by name."""
    transitions, _ = extract_ir_transitions(
        parse_llvm_ir(MACHINE_LL)["functions"][0])
    proved = ir_cfg_correspondence(transitions, MACHINE_LL)
    assert proved["status"] == "CORRESPONDENCE_PROVED"
    assert proved["correspondence_proved"] is True
    assert proved["transitions"] == 4

    missing = ir_cfg_correspondence(transitions[:-1], MACHINE_LL)
    assert missing["code"] == "cfg_transition_missing"
    assert "('conn_f0', 2, 0)" in missing["message"]

    untraced = ir_cfg_correspondence(
        transitions + [{"field": "conn_f0", "case": 5, "value": 9}],
        MACHINE_LL)
    assert untraced["code"] == "model_transition_untraced"


def test_two_ir_modules_yield_two_candidates(tmp_path):
    """Test 3.1: modular extraction — two .ll modules, two V2 domains."""
    from pipeline.codebase_analysis import analyze_codebase
    source = tmp_path / "legacy"
    source.mkdir()
    (source / "machine.ll").write_text(MACHINE_LL, encoding="utf-8")
    (source / "device.ll").write_text(DEVICE_LL, encoding="utf-8")
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    candidates = [Path(d).name for d in result["domains"]]
    assert "conn.v2.yaml" in candidates
    assert "dev.v2.yaml" in candidates
    # device.ll: 0->1 and 1->0, two transitions
    device = tmp_path / "domains" / "candidates" / "dev.v2.yaml"
    payload = __import__("yaml").safe_load(device.read_text(encoding="utf-8"))
    assert len(payload["operations"]) == 2


def test_out_of_dialect_ir_fails_closed_with_notes():
    """Switches whose operand is not a struct-field load, cases that store
    nothing, and stores to other fields are refused with notes — never
    approximated."""
    # switch over a plain local: the operand load doesn't trace to a field
    local_switch = """define i32 @f(i32 %0) {
  %2 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  %3 = load i32, ptr %2, align 4
  switch i32 %3, label %6 [
    i32 0, label %4
  ]

4:
  ret i32 1

6:
  ret i32 0
}
"""
    module = parse_llvm_ir(local_switch)
    assert module["status"] == "PARSED"
    transitions, notes = extract_ir_transitions(module["functions"][0])
    assert transitions == []
    assert any("does not trace" in note for note in notes)

    # field-store case exists but its case block never stores the field back:
    # the machine.ll default arm reaches the merge block with no store
    machine = parse_llvm_ir(MACHINE_LL)["functions"][0]
    cfg = function_cfg(machine)
    assert _stores_reachable(machine, cfg, "24", ("conn", 0)) == set()
    # stores through a different pointer shape are not field stores
    assert _trace_field(machine, "%3") is None   # the raw struct-pointer alloca

    # a case whose block stores nothing back: switch on a traced field, but
    # the case arm only returns
    no_store = """%struct.box = type { i32 }

define void @g(ptr %0) {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  %4 = getelementptr inbounds %struct.box, ptr %3, i32 0, i32 0
  %5 = load i32, ptr %4, align 4
  switch i32 %5, label %7 [
    i32 1, label %6
  ]

6:
  ret void

7:
  ret void
}
"""
    module = parse_llvm_ir(no_store)
    transitions, notes = extract_ir_transitions(module["functions"][0])
    assert transitions == []
    assert any("no constant store" in note for note in notes)

    # correspondence on a module with no machine at all fails named
    assert ir_cfg_correspondence([], no_store)["code"] == "no_machine_extracted"
    # a malformed module fails the correspondence's module parse too
    assert ir_cfg_correspondence([], "garbage")["status"] == "FAIL"
    # and a malformed module is rejected by the module-level parse
    assert parse_llvm_ir("define void @h() {")["status"] == "FAIL"
    assert parse_llvm_ir("define void @h() { ret void }")["status"] == "PARSED"


def test_text_fallback_without_llvmlite(monkeypatch):
    """Without llvmlite the deterministic text parser still runs, and garbage
    with no functions fails closed there (the minimal-environment path)."""
    import pipeline.llvm_ir as lane
    monkeypatch.setattr(lane, "_llvm", None)
    assert lane.parse_llvm_ir("define void @h() { ret void }")["status"] == "PARSED"
    assert lane.parse_llvm_ir("nothing here")["code"] == "no_functions"
    assert lane.parse_llvm_ir("define void @h()")["status"] == "FAIL"


def test_non_load_and_non_gep_operands_refused():
    """A switch over a raw parameter (no load) and a load from a plain
    alloca (no getelementptr) are both refused by name, never approximated."""
    param_switch = """define i32 @f(i32 %0) {
  switch i32 %0, label %3 [
    i32 0, label %2
  ]

2:
  ret i32 1

3:
  ret i32 0
}
"""
    module = parse_llvm_ir(param_switch)
    transitions, notes = extract_ir_transitions(module["functions"][0])
    assert transitions == []
    assert any("is not a struct-field load" in note for note in notes)
    # load from a plain i32 alloca: load matches, but no getelementptr chain
    plain = """define i32 @g(i32 %0) {
  %2 = alloca i32, align 4
  %3 = load i32, ptr %2, align 4
  switch i32 %3, label %6 [
    i32 0, label %4
  ]

4:
  ret i32 1

6:
  ret i32 0
}
"""
    module = parse_llvm_ir(plain)
    function = module["functions"][0]
    assert _trace_field(function, "%2") is None          # no GEP definition
    transitions, notes = extract_ir_transitions(function)
    assert transitions == []
    assert any("does not trace" in note for note in notes)

    # a GEP over a global (not a loaded struct pointer) does not trace either
    global_gep = """%struct.box = type { i32 }
@b = global %struct.box zeroinitializer, align 4

define void @h() {
  %1 = getelementptr inbounds %struct.box, ptr @b, i32 0, i32 0
  %2 = load i32, ptr %1, align 4
  switch i32 %2, label %5 [
    i32 0, label %3
  ]

3:
  store i32 1, ptr %1, align 4
  br label %5

5:
  ret void
}
"""
    module = parse_llvm_ir(global_gep)
    function = module["functions"][0]
    assert _trace_field(function, "%1") is None
    transitions, notes = extract_ir_transitions(function)
    assert transitions == [] and notes

    # aggregate constants nest braces INSIDE a define; the brace matcher
    # must survive them, and a GEP over a non-load base (an inline alloca)
    # does not trace to a struct field either
    nested = """%struct.pair = type { i32, i32 }
@g2 = global %struct.pair zeroinitializer, align 8

define void @k() {
  store { i32, i32 } { i32 1, i32 2 }, ptr @g2, align 4
  ret void
}

define void @m() {
  %1 = alloca %struct.pair, align 8
  %2 = getelementptr inbounds %struct.pair, ptr %1, i32 0, i32 0
  ret void
}
"""
    module = parse_llvm_ir(nested)
    assert module["status"] == "PARSED"
    assert len(module["functions"]) == 2
    assert _trace_field(module["functions"][1], "%2") is None   # base not a load


def test_analyze_reports_ir_failures_and_notes(tmp_path, monkeypatch):
    """Analyzer-level fail-closed: a garbage .ll warns ir_parse_error; a
    module whose switch doesn't trace to a field yields an EXTRACTION_NOTE
    and no candidates — never a fabricated machine."""
    from pipeline.codebase_analysis import analyze_codebase
    source = tmp_path / "legacy"
    source.mkdir()
    (source / "garbage.ll").write_text("not llvm", encoding="utf-8")
    (source / "plain.ll").write_text(
        "define i32 @f(i32 %0) {\n"
        "  %2 = alloca i32, align 4\n"
        "  store i32 %0, ptr %2, align 4\n"
        "  %3 = load i32, ptr %2, align 4\n"
        "  switch i32 %3, label %6 [\n"
        "    i32 0, label %4\n"
        "  ]\n\n"
        "4:\n"
        "  ret i32 1\n\n"
        "6:\n"
        "  ret i32 0\n"
        "}\n", encoding="utf-8")
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    codes = {w["code"] for w in result["warnings"]}
    assert "ir_parse_error" in codes
    assert "EXTRACTION_NOTE" in codes
    assert result["domains"] == []

    # an undefined-register operand and a never-defined store pointer both
    # trace to None without crashing
    machine = parse_llvm_ir(MACHINE_LL)["functions"][0]
    assert _trace_field(machine, "%999") is None      # register never defined
    assert _trace_field(machine, "%4") is None        # defined, but no GEP

    # _stores_reachable against a label that is not a block is a no-op
    cfg = function_cfg(machine)
    assert _stores_reachable(machine, cfg, "nope", ("conn", 0)) == set()

    # correspondence failure at the analyzer level: the just-extracted
    # transitions must correspond or no candidate is registered
    (source / "machine.ll").write_text(MACHINE_LL, encoding="utf-8")
    import pipeline.llvm_ir as lane
    monkeypatch.setattr(lane, "ir_cfg_correspondence",
                        lambda transitions, text: {
                            "status": "FAIL", "code": "cfg_transition_missing",
                            "message": "IR case-stores absent from the model"})
    result = analyze_codebase(source, tmp_path / "out2", project_root=tmp_path)
    failures = [w for w in result["warnings"]
                if w["code"] == "cfg_transition_missing"]
    assert failures
    assert not any("conn.v2.yaml" in d for d in result["domains"])


def _stores_reachable(function, cfg, start, field):
    from pipeline.llvm_ir import _stores_reachable as reach
    return reach(function, cfg, start, field)


def _trace_field(function, register):
    from pipeline.llvm_ir import _trace_field as trace
    return trace(function, register)


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_clang_roundtrip_extracts_the_same_machine(tmp_path):
    """The committed fixture and a live `clang -S -emit-llvm` run agree."""
    import subprocess
    c_file = tmp_path / "machine.c"
    c_file.write_text(MACHINE_C, encoding="utf-8")
    ll_file = tmp_path / "machine.ll"
    subprocess.run(["clang", "-S", "-emit-llvm", "-O0",
                    str(c_file), "-o", str(ll_file)], check=True, timeout=120)
    transitions, notes = extract_ir_transitions(
        parse_llvm_ir(ll_file.read_text(encoding="utf-8"))["functions"][0])
    assert not notes
    assert {(t["case"], t["value"]) for t in transitions} == {
        (0, 1), (1, 2), (1, 0), (2, 0)}
