# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic reviewed-V2 to C/ACSL serialization (canonical drafting)."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from rich.console import Console

from pipeline import cli, v2_acsl_serializer as acsl
from pipeline.domain_v2 import (
    BinaryExpr, BooleanExpr, FieldExpr, IntegerExpr, NotExpr, OldExpr)
from pipeline.v2_acsl_serializer import (
    UnsupportedAcslBoundary, render_acsl_expression, render_translation_unit,
    render_reviewed_v2_acsl_file)

REPO = Path(__file__).resolve().parents[1]
BOUNDED_COUNTER = REPO / "domains" / "v2" / "bounded_counter.json"


def reviewed_lock_spec():
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
    assert render_acsl_expression(field) == "counter->value"
    assert render_acsl_expression(field, pre_state=True) == "\\old(counter->value)"
    assert render_acsl_expression(IntegerExpr(value=5)) == "5"
    assert render_acsl_expression(BooleanExpr(value=True)) == "1"
    assert render_acsl_expression(OldExpr(expression=field)) == \
        "\\old(counter->value)"
    assert render_acsl_expression(BinaryExpr(
        kind="eq", left=field, right=IntegerExpr(value=5))) == \
        "(counter->value == 5)"
    assert render_acsl_expression(BinaryExpr(
        kind="lt", left=field, right=IntegerExpr(value=5))) == \
        "(counter->value < 5)"
    assert render_acsl_expression(BinaryExpr(
        kind="implies",
        left=BinaryExpr(kind="eq", left=FieldExpr(name="lock_state"),
                        right=IntegerExpr(value=1)),
        right=BinaryExpr(kind="eq", left=FieldExpr(name="door_state"),
                         right=IntegerExpr(value=1)))) == \
        "((counter->lock_state == 1) ==> (counter->door_state == 1))"
    assert render_acsl_expression(NotExpr(expression=BinaryExpr(
        kind="eq", left=field, right=IntegerExpr(value=5)))) == \
        "!(counter->value == 5)"
    bogus = BinaryExpr.model_construct(
        kind="xor", left=field, right=IntegerExpr(value=1))
    with pytest.raises(UnsupportedAcslBoundary):
        render_acsl_expression(bogus)
    with pytest.raises(UnsupportedAcslBoundary):
        render_acsl_expression(object())


def _bounded_counter_source():
    reviewed, code = render_reviewed_v2_acsl_file(BOUNDED_COUNTER)
    return reviewed, code


def test_m2_struct_and_per_function_invariants():
    _, code = _bounded_counter_source()
    assert "typedef struct {" in code
    assert "    int value;" in code
    assert "} bounded_counter;" in code
    # ACSL has no persistent struct invariants; the reviewed invariants are
    # assumed by requires and re-established by ensures on every mutator.
    assert "requires (0 <= counter->value) && (counter->value <= 5) && " \
           "(counter->value >= 0) && (counter->value <= 5);" in code
    reviewed, _ = render_reviewed_v2_acsl_file(BOUNDED_COUNTER)
    spec = reviewed.model_dump(mode="json")
    spec["state_variables"].append(
        {"kind": "bool", "name": "sealed", "initial": False})
    source = render_translation_unit(
        acsl.ReviewedDomainSpecV2.model_validate(spec))
    assert "    _Bool sealed;" in source


def test_m3_init_and_getter():
    _, code = _bounded_counter_source()
    assert "void bounded_counter_init(bounded_counter *counter) {" in code
    assert "    counter->value = 0;" in code
    assert "ensures counter->value == 0;" in code
    assert "int bounded_counter_get_value(const bounded_counter *counter) {" in code
    assert "requires \\valid_read(counter);" in code
    assert "ensures \\result == counter->value;" in code
    assert "    return counter->value;" in code


def test_m4_void_operation_with_transcribed_body():
    _, code = _bounded_counter_source()
    assert "void bounded_counter_increment(bounded_counter *counter) {" in code
    assert "requires counter->value < 5;" in code
    assert "requires counter->value > 0;" in code
    assert "assigns counter->value;" in code
    assert "ensures counter->value == \\old(counter->value) + 1;" in code
    assert "ensures counter->value == \\old(counter->value) - 1;" in code
    assert "    int pre_value = counter->value;" in code
    assert "    counter->value = pre_value + 1;" in code
    assert "    counter->value = pre_value - 1;" in code


def test_m4_boolean_false_and_stutter_operation():
    reviewed = acsl.ReviewedDomainSpecV2.model_validate(reviewed_lock_spec())
    code = render_translation_unit(reviewed)
    assert "int door_latch_lock_door(door_latch *counter) {" in code
    assert "ensures \\result == (\\old(counter->lock_state) == 0);" in code
    assert "ensures \\result ==> (counter->lock_state == 1);" in code
    assert "ensures !\\result ==> (counter->lock_state == "
    "\\old(counter->lock_state));" in code
    assert "    if (!(counter->lock_state == 0)) {" in code
    assert "        return 0;" in code
    assert "    counter->lock_state = 1;" in code
    assert "    return 1;" in code
    # old-valued effect RHS is pre-captured for simultaneous semantics
    assert "ensures counter->lock_state == \\old(counter->lock_state);" in code
    assert "    int pre_lock_state = counter->lock_state;" in code
    assert "    counter->lock_state = pre_lock_state;" in code


def test_m4_exception_semantics_fail_closed():
    reviewed = acsl.ReviewedDomainSpecV2.model_validate(reviewed_lock_spec())
    spec = reviewed.model_dump(mode="json")
    spec["operations"].append({
        "name": "ForceOpen", "return_type": "void",
        "failure_semantics": "exception",
        "guards": [], "effects": [], "frame": [],
        "exception_type": "IllegalState",
        "exception_trigger": {"kind": "boolean", "value": True}})
    with pytest.raises(UnsupportedAcslBoundary):
        render_translation_unit(acsl.ReviewedDomainSpecV2.model_validate(spec))


def test_m4_guardless_operation_and_body_branches():
    reviewed = acsl.ReviewedDomainSpecV2.model_validate(reviewed_lock_spec())
    spec = reviewed.model_dump(mode="json")
    spec["operations"].append({
        "name": "Idle", "return_type": "void", "failure_semantics": "unavailable",
        "guards": [], "effects": [], "frame": [],
        "exception_type": None, "exception_trigger": None})
    code = render_translation_unit(acsl.ReviewedDomainSpecV2.model_validate(spec))
    assert "void door_latch_idle(door_latch *counter) {" in code
    assert r"  ensures \true;" in code
    assert r"  assigns \nothing;" in code
    body = acsl._body_expression
    assert body(IntegerExpr(value=4), {}) == "4"
    assert body(BooleanExpr(value=False), {}) == "0"
    assert body(OldExpr(expression=FieldExpr(name="x")), {"x": "pre_x"}) == "pre_x"
    assert body(NotExpr(expression=BinaryExpr(
        kind="eq", left=FieldExpr(name="x"), right=IntegerExpr(value=1))),
        {"x": "pre_x"}) == "!(pre_x == 1)"
    bogus = BinaryExpr.model_construct(
        kind="xor", left=FieldExpr(name="x"), right=IntegerExpr(value=1))
    with pytest.raises(UnsupportedAcslBoundary):
        body(bogus, {"x": "pre_x"})
    with pytest.raises(UnsupportedAcslBoundary):
        body(object(), {})
    with pytest.raises(UnsupportedAcslBoundary):
        body(FieldExpr(name="ghost"), {})


def test_m5_real_gcc_accepts_generated_source():
    from pipeline.c_support import check_c_syntax
    _, code = _bounded_counter_source()
    result = check_c_syntax(code)
    assert result["status"] == "C_CHECKED", result


class CanonicalCBuildCliTests(unittest.TestCase):
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
                  "lang": "c", "out_file": None, "canonical_domain":
                      "bounded_counter", "fallback_provider": None, "out": None,
                  "max_attempts": None, "resample_budget": None,
                  "feedback_budget": None}
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_m5_cli_deterministic_c_draft(self):
        with patch("pipeline.c_support.check_c_syntax",
                   return_value={"status": "C_CHECKED"}) as check:
            code = cli.command_draft(
                self._args(out_file=str(self.root / "bounded_counter.c")),
                self.ui, self.store, self.state)
        self.assertEqual(code, 0)
        source = (self.root / "bounded_counter.c").read_text(encoding="utf-8")
        self.assertIn("requires counter->value < 5;", source)
        self.assertIn("assigns counter->value;", source)
        evidence = json.loads(
            (self.root / "bounded_counter.c.canonical.json")
            .read_text(encoding="utf-8"))
        self.assertEqual(evidence["claim"], "REVIEWED_TRANSFORMATION")
        self.assertEqual(evidence["transformation"], "DETERMINISTIC_V2_TO_ACSL")
        self.assertTrue(evidence["human_acceptance_required"])
        self.assertIn("/*@", check.call_args.args[0])

    def test_m5_cli_fails_closed(self):
        code = cli.command_draft(self._args(canonical_domain="missing_domain"),
                                 self.ui, self.store, self.state)
        self.assertEqual(code, 2)
        self.assertIn("reviewed V2 domain", self.output.getvalue())

        with patch("pipeline.c_support.lint_acsl",
                   return_value=[{"line": 1, "code": "acsl-alloc",
                                  "message": "dynamic allocation",
                                  "severity": "error"}]):
            code = cli.command_draft(self._args(), self.ui, self.store, self.state)
        self.assertEqual(code, 2)
        self.assertIn("ACSL lint", self.output.getvalue())

        with patch("pipeline.c_support.check_c_syntax",
                   return_value={"status": "C_CHECK_FAILED", "exit_code": 1,
                                 "output": "error: unknown type name 'x'"}):
            code = cli.command_draft(self._args(), self.ui, self.store, self.state)
        self.assertEqual(code, 2)
        self.assertIn("C check", self.output.getvalue())
