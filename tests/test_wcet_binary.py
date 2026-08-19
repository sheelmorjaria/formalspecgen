# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M44: binary-level WCET — real rustc + objdump over the emitted object."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pipeline.wcet_binary import (_build_cfg, _classify, parse_functions,
                                  wcet_bound_binary)

SPIN = """#[no_mangle]
pub fn spin(mut n: i32) -> i32 {
    while n > 0 {
        n = n - 1;
    }
    n
}
"""

STRAIGHT = """#[no_mangle]
pub fn clamp(x: i32) -> i32 {
    let y = x + 1;
    if y > 10 { 10 } else { y }
}
"""

# hand-written disassembly: a two-block loop with a back edge
FAKE_LOOP = """
0000000000000000 <loop>:
   0:	89 f8                	mov    %edi,%eax
   2:	eb 04                	jmp    8 <loop+0x8>
   4:	0f 1f 40 00          	nopl   0x0(%rax)
   8:	83 e8 01             	sub    $0x1,%eax
   b:	75 fb                	jne    8 <loop+0x8>
   d:	c3                   	ret
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _toolchain() -> bool:
    return shutil.which("rustc") is not None and \
        shutil.which("objdump") is not None


def test_parser_and_cfg_on_hand_written_disassembly():
    functions = parse_functions(FAKE_LOOP)
    assert list(functions) == ["loop"]
    cfg = _build_cfg(functions["loop"])
    assert (8, 8) in cfg["back_edges"]        # jne 8 — the loop (block leaders)
    assert cfg["indirect"] == []
    assert _classify("jne", "8 <loop>") == "branch"
    assert _classify("mov", "%edi,%eax") == "instruction"
    assert _classify("mov", "0x4(%rsp),%eax") == "memory"
    assert _classify("lea", "0x8(%rdi),%eax") == "instruction"
    assert _classify("push", "%rax") == "memory"


@pytest.mark.skipif(not _toolchain(), reason="rustc/objdump not installed")
def test_real_spin_loop_is_bounded_with_declared_trips(tmp_path):
    """The probed O0 dialect: the while loop survives as a back edge and
    the O0 overflow check leaves an indirect panic call — bounded only
    under the human's bounded_abort declaration."""
    source = _write(tmp_path, "spin.rs", SPIN)
    timing = {"max_cycles": 500, "loop_bounds": {"spin": 8},
              "panic_paths": "bounded_abort", "panic_cost_cycles": 10}
    verdict = wcet_bound_binary(source, timing)
    assert verdict["status"] == "WCET_BOUND_PROVEN", verdict
    assert verdict["claim"] == "WCET_BOUND_PROVEN"
    assert verdict["judge"] == "objdump_static_analysis"
    assert verdict["scope"] == "binary_cfg"
    assert verdict["wcet_cycles"] <= 500
    assert verdict["loop_cost_overapprox"] is True
    assert "spin" in verdict["per_function_cycles"]


@pytest.mark.skipif(not _toolchain(), reason="rustc/objdump not installed")
def test_real_straight_line_function_needs_no_loop_bounds(tmp_path):
    verdict = wcet_bound_binary(_write(tmp_path, "clamp.rs", STRAIGHT),
                                {"max_cycles": 200,
                                 "panic_paths": "bounded_abort",
                                 "panic_cost_cycles": 10})
    assert verdict["status"] == "WCET_BOUND_PROVEN"
    assert verdict["wcet_cycles"] > 0


@pytest.mark.skipif(not _toolchain(), reason="rustc/objdump not installed")
def test_real_fail_closed_paths(tmp_path):
    source = _write(tmp_path, "spin.rs", SPIN)
    # no declared trips → the binary lane never guesses
    assert wcet_bound_binary(source, {"max_cycles": 500})["code"] == \
        "WCET_UNBOUNDED_INDIRECT"   # panic path hits the indirect call first
    assert wcet_bound_binary(source, {
        "max_cycles": 500, "panic_paths": "bounded_abort"})["code"] == \
        "timing_constraints_missing"          # no panic_cost_cycles
    unbounded = wcet_bound_binary(source, {
        "max_cycles": 500, "loop_bounds": {},
        "panic_paths": "bounded_abort", "panic_cost_cycles": 10})
    assert unbounded["code"] == "UNBOUNDED_LOOP_DETECTED"
    tight = wcet_bound_binary(source, {
        "max_cycles": 1, "loop_bounds": {"spin": 8},
        "panic_paths": "bounded_abort", "panic_cost_cycles": 10})
    assert tight["code"] == "DEADLINE_MISSED"


def test_residuals_fail_closed_hermetically(tmp_path, monkeypatch):
    assert wcet_bound_binary(tmp_path / "nope.rs",
                             {"max_cycles": 10})["code"] == \
        "input_unavailable"
    assert wcet_bound_binary(_write(tmp_path, "x.c", "int f(void){return 0;}"),
                             {"max_cycles": 10})["code"] == \
        "UNSUPPORTED_BOUNDARY"
    assert wcet_bound_binary(_write(tmp_path, "x.rs", "fn f(){}"),
                             {})["code"] == "timing_constraints_missing"
    # CI runners: no rustc — named refusal, source-level M38 remains
    monkeypatch.setattr("pipeline.wcet_binary.RUSTC_BIN", None)
    assert wcet_bound_binary(_write(tmp_path, "y.rs", SPIN),
                             {"max_cycles": 10})["code"] == \
        "toolchain_unavailable"
    monkeypatch.undo()
    monkeypatch.setattr("pipeline.wcet_binary.OBJDUMP_BIN", None)
    assert wcet_bound_binary(_write(tmp_path, "z.rs", SPIN),
                             {"max_cycles": 10})["code"] == \
        "toolchain_unavailable"


def test_rustc_failures_refuse_by_name(tmp_path, monkeypatch):
    from subprocess import CompletedProcess
    from unittest.mock import patch
    monkeypatch.setattr("pipeline.wcet_binary.RUSTC_BIN", "/usr/bin/false")
    monkeypatch.setattr("pipeline.wcet_binary.OBJDUMP_BIN", "/usr/bin/false")
    broken = _write(tmp_path, "broken.rs", "this is not rust")
    assert wcet_bound_binary(broken, {"max_cycles": 10})["code"] == \
        "rustc_failed"
    good = _write(tmp_path, "ok.rs", SPIN)
    with patch("subprocess.run", side_effect=TimeoutError("slow")):
        assert wcet_bound_binary(good, {"max_cycles": 10})["code"] == \
            "rustc_timeout"
