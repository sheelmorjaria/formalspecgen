# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic reviewed-V2 to Rust/Prusti serialization (canonical drafting)."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from rich.console import Console

from pipeline import cli, v2_prusti_serializer as prusti
from pipeline.domain_v2 import (
    BinaryExpr, BooleanExpr, FieldExpr, IntegerExpr, NotExpr, OldExpr)
from pipeline.v2_prusti_serializer import (
    UnsupportedPrustiBoundary, render_prusti_expression, render_struct,
    render_reviewed_v2_prusti_file)

REPO = Path(__file__).resolve().parents[1]
BOUNDED_COUNTER = REPO / "domains" / "v2" / "bounded_counter.json"


def reviewed_lock_spec():
    """Synthetic reviewed domain exercising boolean and exception operations."""
    return {
        "schema_version": 2,
        "review_status": "reviewed",
        "domain_name": "DoorLatch",
        "module_name": "door_latch",
        "state_variables": [
            {"kind": "int", "name": "lock_state", "bound": [0, 1], "initial": 0},
        ],
        "operations": [
            {
                "name": "LockDoor", "return_type": "boolean",
                "failure_semantics": "false_and_stutter",
                "guards": [{"id": "g1", "expression": {
                    "kind": "eq",
                    "left": {"kind": "field", "name": "lock_state"},
                    "right": {"kind": "integer", "value": 0}}}],
                "effects": [{"id": "e1", "target": "lock_state",
                             "value": {"kind": "integer", "value": 1}}],
                "frame": ["lock_state"],
                "exception_type": None, "exception_trigger": None,
            },
            {
                "name": "UnlockDoor", "return_type": "void",
                "failure_semantics": "unavailable",
                "guards": [{"id": "g1", "expression": {
                    "kind": "eq",
                    "left": {"kind": "field", "name": "lock_state"},
                    "right": {"kind": "integer", "value": 1}}}],
                "effects": [{"id": "e1", "target": "lock_state",
                             "value": {"kind": "old",
                                       "expression": {"kind": "field",
                                                      "name": "lock_state"}}}],
                "frame": ["lock_state"],
                "exception_type": None, "exception_trigger": None,
            },
        ],
        "tlc_invariants": [
            {"id": "BoundedLock", "expression": {
                "kind": "lte",
                "left": {"kind": "field", "name": "lock_state"},
                "right": {"kind": "integer", "value": 1}}},
        ],
        "accepted_candidate_sha256": "a" * 64,
        "accepted_evidence_sha256": "b" * 64,
    }


# --- Milestone 1: expression AST serialization -------------------------------

def test_m1_expression_serialization():
    field = FieldExpr(name="value")
    assert render_prusti_expression(field) == "self.value"
    assert render_prusti_expression(field, pre_state=True) == "old(self.value)"
    assert render_prusti_expression(IntegerExpr(value=5)) == "5"
    assert render_prusti_expression(BooleanExpr(value=True)) == "true"
    assert render_prusti_expression(
        OldExpr(expression=field)) == "old(self.value)"
    assert render_prusti_expression(BinaryExpr(
        kind="eq", left=field, right=IntegerExpr(value=5))) == "(self.value == 5)"
    assert render_prusti_expression(BinaryExpr(
        kind="lt", left=field, right=IntegerExpr(value=5))) == "(self.value < 5)"
    assert render_prusti_expression(BinaryExpr(
        kind="implies",
        left=BinaryExpr(kind="eq", left=FieldExpr(name="lock_state"),
                        right=IntegerExpr(value=1)),
        right=BinaryExpr(kind="eq", left=FieldExpr(name="door_state"),
                         right=IntegerExpr(value=1)))) == \
        "((self.lock_state == 1) ==> (self.door_state == 1))"
    assert render_prusti_expression(NotExpr(expression=BinaryExpr(
        kind="eq", left=field, right=IntegerExpr(value=5)))) == \
        "!(self.value == 5)"
    bogus = BinaryExpr.model_construct(
        kind="xor", left=field, right=IntegerExpr(value=1))
    with pytest.raises(UnsupportedPrustiBoundary):
        render_prusti_expression(bogus)
    with pytest.raises(UnsupportedPrustiBoundary):
        render_prusti_expression(object())


# --- Milestones 2-4: struct, constructor, operations -------------------------

def _bounded_counter_struct():
    reviewed, code = render_reviewed_v2_prusti_file(BOUNDED_COUNTER)
    return reviewed, code


def test_m2_struct_and_invariants():
    _, code = _bounded_counter_struct()
    assert "use prusti_contracts::*;" in code
    assert "pub struct BoundedCounter {" in code
    assert "    pub value: i32," in code
    assert "#[invariant((0 <= self.value) && (self.value <= 5))]" in code
    assert "#[invariant((self.value >= 0) && (self.value <= 5))]" in code
    reviewed, _ = render_reviewed_v2_prusti_file(BOUNDED_COUNTER)
    boolean_spec = reviewed.model_dump(mode="json")
    boolean_spec["state_variables"].append(
        {"kind": "bool", "name": "sealed", "initial": False})
    source = render_struct(
        prusti.ReviewedDomainSpecV2.model_validate(boolean_spec))
    assert "    pub sealed: bool," in source


def test_m3_constructor_and_getter():
    _, code = _bounded_counter_struct()
    assert "#[ensures(result.value == 0)]" in code
    assert "    pub fn new() -> Self {" in code
    assert "        Self { value: 0 }" in code
    assert "#[pure]" in code
    assert "#[ensures(result == self.value)]" in code
    assert "    pub fn get_value(&self) -> i32 {" in code


def test_m4_void_operation_with_transcribed_body():
    _, code = _bounded_counter_struct()
    assert "#[requires(self.value < 5)]" in code
    assert "#[requires(self.value > 0)]" in code
    assert "#[ensures(self.value == old(self.value) + 1)]" in code
    assert "#[ensures(self.value == old(self.value) - 1)]" in code
    assert "    pub fn increment(&mut self) {" in code
    assert "    pub fn decrement(&mut self) {" in code
    assert "        let pre_value = self.value;" in code
    assert "        self.value = pre_value + 1;" in code
    assert "        self.value = pre_value - 1;" in code


def test_m4_boolean_false_and_stutter_operation():
    reviewed = prusti.ReviewedDomainSpecV2.model_validate(reviewed_lock_spec())
    code = render_struct(reviewed)
    assert "#[ensures(result == (old(self.lock_state) == 0))]" in code
    assert "#[ensures(result ==> (self.lock_state == 1))]" in code
    assert "#[ensures(!result ==> (self.lock_state == old(self.lock_state)))]" in code
    assert "    pub fn lock_door(&mut self) -> bool {" in code
    assert "        if !(self.lock_state == 0) {" in code
    assert "            return false;" in code
    assert "        self.lock_state = 1;" in code
    assert "        true" in code
    # old-valued effect RHS is pre-captured for simultaneous semantics
    assert "#[ensures(self.lock_state == old(self.lock_state))]" in code
    assert "        let pre_lock_state = self.lock_state;" in code
    assert "        self.lock_state = pre_lock_state;" in code


def test_m4_exception_semantics_fail_closed():
    reviewed = prusti.ReviewedDomainSpecV2.model_validate(reviewed_lock_spec())
    spec = reviewed.model_dump(mode="json")
    spec["operations"].append({
        "name": "ForceOpen", "return_type": "void",
        "failure_semantics": "exception",
        "guards": [], "effects": [], "frame": [],
        "exception_type": "IllegalState",
        "exception_trigger": {"kind": "boolean", "value": True}})
    with pytest.raises(UnsupportedPrustiBoundary):
        render_struct(prusti.ReviewedDomainSpecV2.model_validate(spec))


def test_m4_guardless_void_operation_and_body_branches():
    reviewed = prusti.ReviewedDomainSpecV2.model_validate(reviewed_lock_spec())
    spec = reviewed.model_dump(mode="json")
    spec["operations"].append({
        "name": "Idle", "return_type": "void", "failure_semantics": "unavailable",
        "guards": [], "effects": [], "frame": [],
        "exception_type": None, "exception_trigger": None})
    code = render_struct(prusti.ReviewedDomainSpecV2.model_validate(spec))
    assert "#[ensures(true)]" in code
    assert "    pub fn idle(&mut self) {" in code
    # _body_expression branch coverage: literals, old, not, fail-closed
    from pipeline.domain_v2 import BinaryExpr, BooleanExpr, FieldExpr, IntegerExpr, NotExpr, OldExpr
    body = prusti._body_expression
    assert body(IntegerExpr(value=9), {}) == "9"
    assert body(BooleanExpr(value=False), {}) == "false"
    assert body(OldExpr(expression=FieldExpr(name="x")), {"x": "pre_x"}) == "pre_x"
    assert body(NotExpr(expression=BinaryExpr(
        kind="eq", left=FieldExpr(name="x"), right=IntegerExpr(value=1))),
        {"x": "pre_x"}) == "!(pre_x == 1)"
    bogus = BinaryExpr.model_construct(
        kind="xor", left=FieldExpr(name="x"), right=IntegerExpr(value=1))
    with pytest.raises(UnsupportedPrustiBoundary):
        body(bogus, {"x": "pre_x"})
    with pytest.raises(UnsupportedPrustiBoundary):
        body(object(), {})
    with pytest.raises(UnsupportedPrustiBoundary):
        body(FieldExpr(name="ghost"), {})


# --- Milestone 5: rustc syntax gate + CLI integration ------------------------

def test_m5_real_rustc_accepts_generated_struct():
    """The pipeline syntax gate: attributes erased, then real rustc -D warnings."""
    from pipeline.rust_support import check_rust_syntax
    _, code = _bounded_counter_struct()
    result = check_rust_syntax(code)
    assert result["status"] == "RUST_CHECKED", result


class CanonicalRustDraftCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "domains" / "v2").mkdir(parents=True)
        (self.root / "domains" / "v2" / "bounded_counter.json").write_text(
            BOUNDED_COUNTER.read_text(encoding="utf-8"), encoding="utf-8")
        self.output = io.StringIO()
        self.ui = cli.TerminalUI(
            Console(file=self.output, force_terminal=False, width=120),
            lambda _prompt: "answer")
        self.store = cli.SessionStore(self.root)
        self.state = self.store.empty()

    def tearDown(self):
        self.temp.cleanup()

    def _args(self, **overrides):
        values = {"requirement": "Generate the reviewed bounded counter",
                  "provider": "ollama", "model": None, "no_clarify": True,
                  "lang": "rust", "out_file": None, "canonical_domain":
                      "bounded_counter", "fallback_provider": None, "out": None,
                  "max_attempts": None, "resample_budget": None,
                  "feedback_budget": None}
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_m5_cli_deterministic_rust_draft(self):
        with patch("pipeline.rust_support.check_rust_syntax",
                   return_value={"status": "RUST_CHECKED"}) as check:
            code = cli.command_draft(
                self._args(out_file=str(self.root / "BoundedCounter.rs")),
                self.ui, self.store, self.state)
        self.assertEqual(code, 0)
        destination = self.root / "BoundedCounter.rs"
        source = destination.read_text(encoding="utf-8")
        self.assertIn("#[requires(self.value < 5)]", source)
        self.assertIn("pub struct BoundedCounter {", source)
        evidence = json.loads(
            (self.root / "BoundedCounter.rs.canonical.json")
            .read_text(encoding="utf-8"))
        self.assertEqual(evidence["claim"], "REVIEWED_TRANSFORMATION")
        self.assertEqual(evidence["transformation"], "DETERMINISTIC_V2_TO_PRUSTI")
        self.assertEqual(evidence["accepted_candidate_sha256"],
                         evidence["accepted_candidate_sha256"].strip())
        self.assertTrue(evidence["human_acceptance_required"])
        rendered = check.call_args.args[0]
        self.assertIn("use prusti_contracts::*;", rendered)

    def test_m5_cli_fails_closed(self):
        code = cli.command_draft(self._args(canonical_domain="missing_domain"),
                                 self.ui, self.store, self.state)
        self.assertEqual(code, 2)
        self.assertIn("reviewed V2 domain", self.output.getvalue())

        code = cli.command_draft(self._args(canonical_domain="Bad Name!"),
                                 self.ui, self.store, self.state)
        self.assertEqual(code, 2)
        self.assertIn("safe module identifier", self.output.getvalue())

        with patch("pipeline.rust_support.lint_rust",
                   return_value=[{"line": 1, "code": "rust-unsafe",
                                  "message": "unsafe block", "severity": "error"}]):
            code = cli.command_draft(self._args(), self.ui, self.store, self.state)
        self.assertEqual(code, 2)
        self.assertIn("safety lint", self.output.getvalue())

        with patch("pipeline.rust_support.check_rust_syntax",
                   return_value={"status": "RUST_CHECK_FAILED", "exit_code": 1,
                                 "output": "error[E0308]: mismatched types"}):
            code = cli.command_draft(self._args(), self.ui, self.store, self.state)
        self.assertEqual(code, 2)
        self.assertIn("Rust check", self.output.getvalue())
