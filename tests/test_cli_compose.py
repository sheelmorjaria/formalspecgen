# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""CLI surface for multi-tier composition verification and impact re-verification."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from pipeline import cli


def composition_value():
    return {
        "system_name": "GateSystem",
        "architecture": {
            "name": "GateSystem",
            "description": "gate plus control panel",
            "components": [
                {"id": "gate", "name": "Gate", "layer": "entities", "kind": "class",
                 "operations": [], "dependencies": []},
                {"id": "panel", "name": "Panel", "layer": "use_cases", "kind": "class",
                 "operations": [], "dependencies": [{"target": "gate", "abstraction": True}]},
            ],
            "use_cases": [],
        },
        "bindings": [
            {"component": "gate", "module_name": "gate"},
            {"component": "panel", "module_name": "panel"},
        ],
        "use_cases": [
            {"name": "OpenGate", "steps": [{"component": "gate", "operation": "Open"}]},
            {"name": "PanelOpensGate", "steps": [
                {"component": "panel", "operation": "Open"}]},
        ],
    }


class ComposeCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.artifact = self.root / "composition.json"
        self.artifact.write_text(json.dumps(composition_value()), encoding="utf-8")
        self.output = io.StringIO()
        self.ui = cli.TerminalUI(
            Console(file=self.output, force_terminal=False, width=120),
            lambda _prompt: "answer")

    def tearDown(self):
        self.temp.cleanup()

    def _args(self, **overrides):
        values = {"artifact": str(self.artifact), "v2_dir": None, "out_dir": None,
                  "json": None, "no_esc": False}
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_compose_verified_writes_sources_and_verdict(self):
        verdict = {"status": "COMPOSITION_VERIFIED", "claim": "SCOPED_COMPOSITION_PROOF",
                   "scope": "single_threaded_atomic_contract_composition",
                   "concurrent_linearizability_proved": False,
                   "disclaimer": "scoped", "files": {"Gate.java": "public class Gate {}"}}
        out_dir = self.root / "out"
        json_path = self.root / "verdict.json"
        with patch("pipeline.composition_render.verify_composition",
                   return_value=verdict) as verify:
            code = cli.command_compose(
                self._args(out_dir=str(out_dir), json=str(json_path)), self.ui)
        self.assertEqual(code, 0)
        self.assertEqual(verify.call_args.kwargs["run_esc"], True)
        self.assertEqual(verify.call_args.args[0], composition_value())
        self.assertEqual((out_dir / "Gate.java").read_text(encoding="utf-8"),
                         "public class Gate {}")
        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["status"],
                         "COMPOSITION_VERIFIED")
        self.assertIn("COMPOSITION_VERIFIED", self.output.getvalue())

    def test_compose_failure_fails_closed_without_writing(self):
        verdict = {"status": "CHECK_FAILED", "claim": "NO_PROOF", "message": "bad"}
        out_dir = self.root / "out"
        with patch("pipeline.composition_render.verify_composition",
                   return_value=verdict):
            code = cli.command_compose(self._args(out_dir=str(out_dir)), self.ui)
        self.assertEqual(code, 1)
        self.assertFalse(out_dir.exists())
        self.assertIn("CHECK_FAILED", self.output.getvalue())

    def test_compose_no_esc_and_unreadable_artifact(self):
        verdict = {"status": "COMPOSITION_CHECKED", "claim": "STATIC_CHECK"}
        with patch("pipeline.composition_render.verify_composition",
                   return_value=verdict) as verify:
            code = cli.command_compose(self._args(no_esc=True), self.ui)
        self.assertEqual(code, 0)
        self.assertFalse(verify.call_args.kwargs["run_esc"])
        code = cli.command_compose(self._args(artifact=str(self.root / "missing.json")),
                                   self.ui)
        self.assertEqual(code, 2)

    def test_reverify_exit_codes(self):
        for status, expected in (("REVERIFIED", 0), ("REVERIFICATION_FAILED", 1),
                                 ("NOT_IMPACTED", 0)):
            with patch("pipeline.composition_render.reverify_composition",
                       return_value={"status": status, "changed_module": "gate",
                                     "impacted_components": ["gate"],
                                     "impacted_use_cases": ["OpenGate"]}):
                code = cli.command_reverify(SimpleNamespace(
                    artifact=str(self.artifact), changed_module="gate",
                    v2_dir=None, json=None), self.ui)
            self.assertEqual(code, expected)
        with patch("pipeline.composition_render.reverify_composition",
                   return_value={"status": "REVERIFIED", "changed_module": "gate",
                                 "impacted_components": ["gate"],
                                 "impacted_use_cases": ["OpenGate"]}) as reverify:
            json_path = self.root / "reverify.json"
            cli.command_reverify(SimpleNamespace(
                artifact=str(self.artifact), changed_module="gate", v2_dir=None,
                json=str(json_path)), self.ui)
        self.assertEqual(reverify.call_args.args[1], "gate")
        self.assertEqual(
            json.loads(json_path.read_text(encoding="utf-8"))["status"], "REVERIFIED")
        code = cli.command_reverify(SimpleNamespace(
            artifact=str(self.root / "missing.json"), changed_module="gate",
            v2_dir=None, json=None), self.ui)
        self.assertEqual(code, 2)

    def test_parser_registers_compose_and_reverify(self):
        parser = cli.build_parser()
        args = parser.parse_args(["compose", "arch.json", "--no-esc"])
        self.assertEqual(args.command, "compose")
        self.assertTrue(args.no_esc)
        args = parser.parse_args(["reverify", "arch.json", "--changed-module", "smart_lock"])
        self.assertEqual(args.command, "reverify")
        self.assertEqual(args.changed_module, "smart_lock")
        self.assertIn("compose", cli._REPL_COMMANDS)
        self.assertIn("reverify", cli._REPL_COMMANDS)
