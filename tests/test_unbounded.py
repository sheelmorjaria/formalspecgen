# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M25 (roadmap Feature 5): inductive loop verification — k-induction over
ESBMC. The invariant is LLM-proposed (or human-supplied); the machine proves
only its INDUCTIVENESS (establishment + one-step preservation), which is the
honest division: the tool proves the induction, the invariant's sufficiency
for the intended property is the reviewer's accepted assumption.
"""
from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

from pipeline.unbounded import (
    build_induction_harnesses, extract_loops, verify_unbounded,
)

COUNTER_LOOP = """#include <cassert>

int sum_upto(int n) {
    int i = 0;
    while (i < n) {
        i = i + 1;
    }
    return i;
}
"""

NESTED_LOOP = """int f(int n) {
    for (int i = 0; i < n; i++) {
        while (true) { g(); }
    }
    return 0;
}
"""


def test_extract_loops_finds_the_counter_loop():
    loops = extract_loops(COUNTER_LOOP)
    assert len(loops) == 1
    loop = loops[0]
    assert loop["condition"] == "i < n"
    assert "i = i + 1;" in loop["body"]


def test_extract_loops_refuses_nested_bodies():
    assert extract_loops(NESTED_LOOP) == []      # inner loop makes it unsupported


def test_harnesses_carry_assume_and_assert():
    loops = extract_loops(COUNTER_LOOP)
    establishment, step = build_induction_harnesses(COUNTER_LOOP, loops[0],
                                                    "i >= 0 && i <= n")
    assert "assert((i >= 0 && i <= n));" in establishment
    assert "int i = 0;" in establishment        # the program's own entry state
    assert "if (!(i >= 0 && i <= n)) return 0;" in step      # assume invariant
    assert "if (!(i < n)) return 0;" in step                 # assume guard
    assert "i = i + 1;" in step                              # one body copy
    assert "assert((i >= 0 && i <= n));" in step


def test_verify_unbounded_proves_with_supplied_invariant(tmp_path):
    """The lane proves establishment + one-step preservation with ESBMC
    (mocked here) and mints DEDUCTIVE_PROOF scoped to the induction."""
    source = tmp_path / "counter.cpp"
    source.write_text(COUNTER_LOOP, encoding="utf-8")
    with patch("pipeline.unbounded.run_esbmc",
               return_value={"status": "VERIFIED"}) as esbmc:
        result = verify_unbounded(source, invariant="i >= 0 && i <= n")
    assert result["status"] == "UNBOUNDED_VERIFIED"
    assert result["claim"] == "DEDUCTIVE_PROOF"
    assert result["scope"] == "unbounded_loop_induction"
    assert esbmc.call_count == 2            # establishment + step
    args = [call.args[0] for call in esbmc.call_args_list]
    assert all(re.search(r"assume|assert", code) for code in args)


def test_verify_unbounded_generates_invariant_when_absent(tmp_path):
    """Milestone 1: the LLM proposes the invariant; a residual requires it to
    mention the loop counter."""
    source = tmp_path / "counter.cpp"
    source.write_text(COUNTER_LOOP, encoding="utf-8")
    with patch("pipeline.llm._chat_fn") as chat, \
         patch("pipeline.unbounded.run_esbmc",
               return_value={"status": "VERIFIED"}):
        chat.return_value.return_value = ("i >= 0 && i <= n", "fixture", {})
        result = verify_unbounded(source, provider="ollama")
    assert result["status"] == "UNBOUNDED_VERIFIED"
    assert result["invariant"] == "i >= 0 && i <= n"
    assert result["invariant_source"] == "llm_proposed"

    # an invariant that never mentions the counter is refused pre-prover
    with patch("pipeline.llm._chat_fn") as chat, \
         patch("pipeline.unbounded.run_esbmc") as esbmc:
        chat.return_value.return_value = ("n > 100", "fixture", {})
        result = verify_unbounded(source, provider="ollama")
    assert result["code"] == "invariant_rejected"
    assert "counter" in result["message"]
    esbmc.assert_not_called()


def test_verify_unbounded_fails_closed_on_shapes_and_steps(tmp_path):
    source = tmp_path / "nested.cpp"
    source.write_text(NESTED_LOOP, encoding="utf-8")
    assert verify_unbounded(source, invariant="i >= 0")["code"] == \
        "no_verifiable_loop"

    good = tmp_path / "counter.cpp"
    good.write_text(COUNTER_LOOP, encoding="utf-8")
    # a NON-inductive invariant fails at the step harness
    with patch("pipeline.unbounded.run_esbmc",
               side_effect=[{"status": "VERIFIED"},
                            {"status": "FAILED", "vcs": [{"detail": "assertion"}]}]):
        result = verify_unbounded(good, invariant="i >= 0 && i <= n")
    assert result["status"] == "UNBOUNDED_FAILED"
    assert result["failed_harness"] == "step"
    assert result["claim"] == "NO_PROOF"


def test_verify_unbounded_missing_tool_and_file(tmp_path):
    real = tmp_path / "counter.cpp"
    real.write_text(COUNTER_LOOP, encoding="utf-8")
    with patch("pipeline.unbounded.ESBMC_AVAILABLE", False):
        result = verify_unbounded(real, invariant="i >= 0")
    assert result["code"] == "esbmc_unavailable"
    result = verify_unbounded(tmp_path / "nope.cpp", invariant="i >= 0")
    assert result["code"] == "input_unavailable"


def test_real_esbmc_induction_end_to_end(tmp_path):
    """Real ESBMC: an inductive invariant proves, a non-inductive one fails
    at the step harness."""
    import pytest
    from pipeline.unbounded import ESBMC_AVAILABLE
    if not ESBMC_AVAILABLE:
        pytest.skip("ESBMC unavailable")
    source = tmp_path / "counter.cpp"
    source.write_text(COUNTER_LOOP, encoding="utf-8")
    # honest inductive invariant: for n <= 0 the loop never runs, so i stays 0
    good = verify_unbounded(source,
                            invariant="i >= 0 && (n <= 0 || i <= n)")
    assert good["status"] == "UNBOUNDED_VERIFIED", good
    assert good["claim"] == "DEDUCTIVE_PROOF"
    assert good["loops_proved"] == ["i < n"]

    # `i <= n` alone is NOT established for negative n — the machinery
    # correctly refuses it at the establishment harness
    bad = verify_unbounded(source, invariant="i <= n")
    assert bad["status"] == "UNBOUNDED_FAILED"
    assert bad["failed_harness"] == "establishment"


def test_cli_verify_unbounded_writes_evidence(tmp_path, monkeypatch):
    import argparse
    from pipeline.cli import command_verify_unbounded
    monkeypatch.chdir(tmp_path)
    (tmp_path / "counter.cpp").write_text(COUNTER_LOOP, encoding="utf-8")
    args = argparse.Namespace(source="counter.cpp",
                              invariant="i >= 0 && (n <= 0 || i <= n)",
                              provider="ollama", json_out="u.json")
    assert command_verify_unbounded(args, _SilentUI()) == 0
    import json
    payload = json.loads((tmp_path / "u.json").read_text(encoding="utf-8"))
    assert payload["claim"] == "DEDUCTIVE_PROOF"
    assert payload["scope"] == "unbounded_loop_induction"


class _SilentUI:
    class console:
        @staticmethod
        def print(*_a, **_k): pass


def test_extract_and_proposal_edge_branches(tmp_path):
    """Nested brace depth, empty bodies, constant guards, and provider
    failure all take their distinct paths."""
    mixed = """int g(int n) {
    while (n > 0) { }
    while (true) { n = n - 1; }
    while (nested(i)) { if (i) { i = i - 1; } }
    while (j < 3) { j = j + 1; }
    return 0;
}
"""
    loops = extract_loops(mixed)
    assert [loop["condition"] for loop in loops] == ["j < 3"]
    assert loops[0]["init"] is None           # no prior j assignment

    # provider failure fails closed without touching the prover
    source = tmp_path / "c.cpp"
    source.write_text(COUNTER_LOOP, encoding="utf-8")
    with patch("pipeline.llm._chat_fn", side_effect=RuntimeError("offline")), \
         patch("pipeline.unbounded.run_esbmc") as esbmc:
        result = verify_unbounded(source, provider="ollama")
    assert result["code"] == "invariant_generation_failed"
    esbmc.assert_not_called()


def test_brace_depth_and_main_dispatch(tmp_path, monkeypatch):
    """Nested braces inside a loop body exercise the depth walk, and the
    argparse-level dispatch reaches verify-unbounded."""
    nested_body = """int h(int n) {
    while (n > 0) { n = f({ n - 1 }); }
    return 0;
}
"""
    assert extract_loops(nested_body) == []   # initializer braces refuse the shape

    monkeypatch.chdir(tmp_path)
    (tmp_path / "c.cpp").write_text(COUNTER_LOOP, encoding="utf-8")
    import sys
    import pipeline.cli as cli
    monkeypatch.setattr(sys, "argv", ["formalspecgen", "verify-unbounded",
                                      "c.cpp", "--invariant",
                                      "i >= 0 && (n <= 0 || i <= n)"])
    try:
        cli.main()
        dispatched = True
    except SystemExit as exc:
        dispatched = exc.code == 0
    assert dispatched
