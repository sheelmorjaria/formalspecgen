# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M29 (roadmap Feature 7): dynamic heap reasoning via ghost predicates on
the Prusti/Viper lane. The reachability predicate is a structurally
recursive #[pure] ghost function over Option<Box<Node>> — unbounded chain
length, no bounding. Rust's ownership makes acyclicity a type-system
guarantee (Box graphs are DAGs by construction) and aliased &mut a rustc
borrow error, so the framing gate is deterministic. The machine proves the
predicate's inductiveness across the operations; the predicate's adequacy
for the reviewer's intended property is the accepted assumption.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from pipeline.heap import (
    extract_dynamic_structs, verify_heap,
)

LINKED_LIST = """use prusti_contracts::*;

pub struct Node {
    pub value: i32,
    pub next: Option<Box<Node>>,
}

pub struct LinkedList {
    pub head: Option<Box<Node>>,
}

#[pure]
pub fn list_contains(head: &Option<Box<Node>>, target: i32) -> bool {
    match head {
        None => false,
        Some(node) => node.value == target || list_contains(&node.next, target),
    }
}

impl LinkedList {
    pub fn new() -> Self {
        LinkedList { head: None }
    }

    #[ensures(list_contains(&self.head, v))]
    pub fn push(&mut self, v: i32) {
        let node = Box::new(Node { value: v, next: self.head.take() });
        self.head = Some(node);
    }

    #[requires(list_contains(&self.head, target))]
    #[ensures(result)]
    pub fn contains(&self, target: i32) -> bool {
        list_contains(&self.head, target)
    }
}
"""

# The source WITHOUT predicates: the lane's job is to add them.
BARE_LIST = """pub struct Node {
    pub value: i32,
    pub next: Option<Box<Node>>,
}

pub struct LinkedList {
    pub head: Option<Box<Node>>,
}

impl LinkedList {
    pub fn new() -> Self {
        LinkedList { head: None }
    }

    pub fn push(&mut self, v: i32) {
        let node = Box::new(Node { value: v, next: self.head.take() });
        self.head = Some(node);
    }
}
"""

# Aliasing: two live &mut to the same node — rustc E0499 borrow error.
ALIASED = """pub struct Node {
    pub value: i32,
}

pub struct LinkedList {
    pub head: Option<Box<Node>>,
}

impl LinkedList {
    pub fn alias(&mut self) {
        let a = &mut self.head;
        let b = &mut self.head;   // E0499: cannot borrow again
        a.take();
        b.take();
    }
}
"""

# An UNSATISFIABLE spec: push guarantees v is NOT reachable after the call,
# but push links v at the head — the implementation contradicts the spec and
# Prusti must reject it. (A predicate that merely "lies" consistently with
# its implementation is provable — predicate adequacy is the accepted
# assumption; what the machine rejects is implementation-vs-spec mismatch.)
UNSATISFIABLE_SPEC = LINKED_LIST.replace(
    "#[ensures(list_contains(&self.head, v))]",
    "#[ensures(!list_contains(&self.head, v))")

FLAT_STRUCT = """pub struct Point {
    pub x: i32,
    pub y: i32,
}
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_extract_dynamic_structs_finds_pointer_linked_shapes():
    """Milestone 1 gate: structs whose fields link through Box."""
    structs = extract_dynamic_structs(LINKED_LIST)
    assert {item["name"] for item in structs} == {"Node", "LinkedList"}
    linked = next(s for s in structs if s["name"] == "LinkedList")
    assert linked["node_type"] == "Node"
    assert extract_dynamic_structs(FLAT_STRUCT) == []


def test_verify_heap_fails_closed_on_shapes_and_languages(tmp_path):
    """Test 4.2: non-Rust targets fail closed; no dynamic structure and
    missing files fail closed too."""
    result = verify_heap(_write(tmp_path, "L.java", "class L {}"))
    assert result["code"] == "UNSUPPORTED_BOUNDARY"
    assert "Rust" in result["message"]

    result = verify_heap(_write(tmp_path, "flat.rs", FLAT_STRUCT))
    assert result["code"] == "no_dynamic_structure"

    result = verify_heap(tmp_path / "nope.rs")
    assert result["code"] == "input_unavailable"


def test_predicate_generation_with_residuals(tmp_path):
    """Milestone 1 (Tests 1.1/1.2): the LLM proposes the ghost predicate;
    residuals demand a boolean #[pure]/#[predicate] fn naming the node type
    and refuse arithmetic-recursive predicates (overflow-unsound)."""
    from pipeline.heap import _PREDICATE_PROMPT, _propose_predicates
    source = _write(tmp_path, "bare.rs", BARE_LIST)
    good = """#[pure]
pub fn list_contains(head: &Option<Box<Node>>, target: i32) -> bool {
    match head {
        None => false,
        Some(node) => node.value == target || list_contains(&node.next, target),
    }
}
"""
    with patch("pipeline.llm._chat_fn") as chat:
        chat.return_value.return_value = (good, "fixture", {})
        text = _propose_predicates(source.read_text(), "Node", "ollama")
    assert "list_contains" in text and "#[pure]" in text

    # residuals refuse: no predicate, non-boolean, arithmetic recursion
    from pipeline.heap import _predicate_residuals
    assert _predicate_residuals(good, "Node") is None
    assert _predicate_residuals("fn f() {}", "Node").startswith(
        "no_ghost_predicate")
    assert _predicate_residuals(
        "#[pure] pub fn p(x: &Node) -> i32 { 1 }", "Node").startswith(
        "predicate_not_boolean")
    arithmetic = good.replace(
        "node.value == target || list_contains(&node.next, target)",
        "true && (1 + list_len(&node.next)) >= 0")
    assert _predicate_residuals(arithmetic, "Node").startswith(
        "arithmetic_predicate_rejected")


def test_verify_heap_aliased_mutation_rejected(tmp_path):
    """Test 2.2: two live &mut aliases never reach Prusti — rustc's borrow
    check is the framing gate and fails closed."""
    result = verify_heap(_write(tmp_path, "alias.rs", ALIASED),
                         predicates=LINKED_LIST.split("impl LinkedList")[0])
    assert result["status"] == "HEAP_VERIFICATION_FAILED"
    assert result["code"] == "aliasing_rejected"
    assert "borrow" in result["message"].lower()


def _prusti_installed() -> bool:
    from pipeline.rust_support import _prusti_binary
    return _prusti_binary() is not None


@pytest.mark.skipif(not _prusti_installed(),
                    reason="real Prusti not installed")
def test_cli_verify_heap_mints_and_fails(tmp_path, monkeypatch):
    """Test 4.1: the command mints HEAP_REASONING_PROVED, scope
    separation_logic; an unsatisfiable spec fails closed."""
    import argparse
    from pipeline.cli import command_verify_heap
    monkeypatch.chdir(tmp_path)
    (tmp_path / "list.rs").write_text(LINKED_LIST, encoding="utf-8")
    ui = _SilentUI()
    args = argparse.Namespace(source="list.rs", provider="ollama",
                              json_out="h.json")
    assert command_verify_heap(args, ui) == 0
    payload = json.loads((tmp_path / "h.json").read_text(encoding="utf-8"))
    assert payload["claim"] == "HEAP_REASONING_PROVED"
    assert payload["scope"] == "separation_logic"
    assert payload["unbounded_heap_reasoning"] is True
    assert payload["acyclicity_guarantee"] == "rust_ownership_type_system"
    assert payload["predicate_inductiveness_proved"] is True

    (tmp_path / "unsat.rs").write_text(UNSATISFIABLE_SPEC, encoding="utf-8")
    args = argparse.Namespace(source="unsat.rs", provider="ollama",
                              json_out="bad.json")
    assert command_verify_heap(args, ui) == 1
    failed = json.loads((tmp_path / "bad.json").read_text(encoding="utf-8"))
    assert failed["status"] == "HEAP_VERIFICATION_FAILED"


class _SilentUI:
    class console:
        @staticmethod
        def print(*_a, **_k): pass


def test_provider_failure_and_residual_violation_fail_closed(tmp_path):
    """An unreachable provider never reaches a prover; a residual-violating
    proposal is refused pre-prover."""
    source = _write(tmp_path, "bare.rs", BARE_LIST)
    with patch("pipeline.llm._chat_fn",
               side_effect=RuntimeError("offline")):
        result = verify_heap(source, provider="ollama")
    assert result["code"] == "predicate_generation_failed"

    with patch("pipeline.llm._chat_fn") as chat:
        chat.return_value.return_value = ("fn not_a_predicate() {}", "f", {})
        result = verify_heap(source, provider="ollama")
    assert result["code"] == "no_ghost_predicate"


@pytest.mark.skipif(not _prusti_installed(),
                    reason="real Prusti not installed")
def test_argparse_dispatch_reaches_verify_heap(tmp_path, monkeypatch):
    """The argparse-level dispatch line fires end to end."""
    import sys
    import pipeline.cli as cli
    monkeypatch.chdir(tmp_path)
    (tmp_path / "list.rs").write_text(LINKED_LIST, encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["formalspecgen", "verify-heap",
                                      "list.rs"])
    try:
        cli.main()
        ok = True
    except SystemExit as exc:
        ok = exc.code == 0
    assert ok


def test_source_supplied_predicate_needs_no_provider(tmp_path):
    """A source that already carries a well-formed ghost predicate never
    consults the LLM — the happy path is hermetic, so a provider-less
    runner (CI) still reaches the framing gate and Prusti."""
    source = _write(tmp_path, "supplied.rs", LINKED_LIST)
    with patch("pipeline.llm._chat_fn",
               side_effect=RuntimeError("no provider anywhere")):
        with patch("pipeline.rust_support.verify_prusti",
                   return_value={"status": "VERIFIED", "output": "4/4"}):
            result = verify_heap(source, provider="ollama")
    assert result["claim"] == "HEAP_REASONING_PROVED", result
    assert result["predicate_source"] == "source_supplied"


def test_prusti_unavailable_is_not_a_proof_failure(tmp_path):
    """A runner without Prusti reports prusti_unavailable — distinctly from
    predicate_not_proved, and only after the residuals and framing gate."""
    source = _write(tmp_path, "supplied.rs", LINKED_LIST)
    with patch("pipeline.rust_support.verify_prusti",
               return_value={"status": "TOOL_MISSING", "exit_code": 127,
                             "message": "Prusti executable not found"}):
        result = verify_heap(source, provider="ollama")
    assert result["code"] == "prusti_unavailable"
    assert result["claim"] == "NO_PROOF"
    assert "not found" in result["message"]
