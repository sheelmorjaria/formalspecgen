import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pipeline import handoff, refactor_impact


ARCHITECTURE = {
    "name": "System", "description": "",
    "components": [
        {"id": "port", "name": "Port", "layer": "use_cases", "kind": "interface"},
        {"id": "service", "name": "Service", "layer": "use_cases", "kind": "class",
         "dependencies": [{"target": "port", "abstraction": True}]},
    ],
    "use_cases": [{"name": "Do Work", "steps": [{"component": "service", "operation": "run"}]}],
}


class HandoffTests(unittest.TestCase):
    def test_rejects_source_without_public_class(self):
        self.assertFalse(handoff.handoff("interface X {}") ["ok"])

    def test_writes_structured_intent_without_running_missing_dd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(handoff.config, "ROOT", root), patch.object(handoff, "DD_ROOT", root / "missing"):
                result = handoff.handoff("public class C {}", expected_passes=["inject_pure"],
                                         backend="dafny")
            self.assertTrue(result["ok"])
            self.assertFalse(result["dd_available"])
            self.assertIsNone(result["dd_verdict"])
            intent = json.loads(Path(result["intent_file"]).read_text(encoding="utf-8"))
            self.assertEqual(intent["expected_passes"], ["inject_pure"])
            self.assertEqual(intent["backend"], "DAFNY")

    def test_run_loads_verdict_and_generated_implementation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); dd = root / "dd"
            (dd / "pipeline").mkdir(parents=True)
            (dd / "pipeline" / "orchestrator.py").write_text("# available", encoding="utf-8")
            implementation = root / "Generated.java"
            implementation.write_text("public class C { int value() { return 1; } }", encoding="utf-8")

            def run(command, **_kwargs):
                verdict_dir = Path(command[command.index("--out") + 1])
                (verdict_dir / "verdict.json").write_text(json.dumps({
                    "final_status": "VERIFIED", "stub_path": str(implementation)}), encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="verified", stderr="")

            with patch.object(handoff.config, "ROOT", root), patch.object(handoff, "DD_ROOT", dd), \
                 patch.object(handoff, "_dd_python", return_value="python"), \
                 patch.object(handoff.subprocess, "run", side_effect=run):
                result = handoff.handoff("public class C {}", run_dd=True)
            self.assertEqual(result["dd_verdict"]["final_status"], "VERIFIED")
            self.assertIn("return 1", result["implementation_code"])
            self.assertEqual(result["dd_exit"], 0)

    def test_timeout_and_unexpected_error_become_verdicts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "pipeline").mkdir()
            (root / "pipeline" / "orchestrator.py").write_text("# x", encoding="utf-8")
            common = [patch.object(handoff.config, "ROOT", root), patch.object(handoff, "DD_ROOT", root)]
            for item in common: item.start(); self.addCleanup(item.stop)
            with patch.object(handoff.subprocess, "run", side_effect=subprocess.TimeoutExpired("dd", 3)):
                timed = handoff.handoff("public class C {}", run_dd=True, timeout=3)
            self.assertEqual(timed["dd_verdict"]["final_status"], "TIMEOUT")
            with patch.object(handoff.subprocess, "run", side_effect=RuntimeError("broken")):
                failed = handoff.handoff("public class C {}", run_dd=True)
            self.assertEqual(failed["dd_verdict"], {"final_status": "ERROR", "stop_reason": "broken"})


class RefactorImpactTests(unittest.TestCase):
    def test_unchanged_contract_skips_verification(self):
        files = {"Port.java": "//@ ensures true;\npublic interface Port {}"}
        result = refactor_impact.analyze_refactor(ARCHITECTURE, files, files)
        self.assertEqual(result["status"], "UNCHANGED")
        self.assertEqual(result["verification"]["esc_status"], "SKIPPED")

    def test_contract_change_propagates_to_dependents_and_use_cases(self):
        before = {"Port.java": "//@ ensures true;\npublic interface Port {}"}
        after = {"Port.java": "//@ ensures ready;\npublic interface Port {}"}
        with patch.object(refactor_impact, "_verify_sources", return_value={
                "check_status": "VERIFIED", "esc_status": "VERIFIED", "diagnostics": []}):
            result = refactor_impact.analyze_refactor(ARCHITECTURE, before, after)
        self.assertEqual(result["status"], "REVERIFIED")
        self.assertEqual(result["impacted_components"], ["port", "service"])
        self.assertEqual(result["impacted_use_cases"], ["Do Work"])
        self.assertEqual(result["impacted_orchestrators"], ["DoWorkOrchestrator.java"])

    def test_verify_sources_classifies_check_failure_esc_failure_and_vacuity(self):
        files = {"C.java": "public class C {}"}
        with patch.object(refactor_impact, "verify_files", return_value=(1, "C.java:2: error: bad")):
            checked = refactor_impact._verify_sources(files)
        self.assertEqual(checked["check_status"], "COMPILE_FAILED")
        self.assertEqual(checked["esc_status"], "SKIPPED")

        vc = ("C.java:4: verify: The prover cannot establish an assertion "
              "(Postcondition) in method f")
        with patch.object(refactor_impact, "verify_files", side_effect=[(0, ""), (6, vc)]):
            failed = refactor_impact._verify_sources(files)
        self.assertEqual(failed["esc_status"], "VERIFY_FAILED")
        self.assertEqual(failed["diagnostics"][0]["category"], "Postcondition")

        with patch.object(refactor_impact, "verify_files", side_effect=[(0, ""), (0, "dropped")]), \
             patch.object(refactor_impact, "has_dropped_vc", return_value=True):
            vacuous = refactor_impact._verify_sources(files)
        self.assertEqual(vacuous["esc_status"], "VACUOUS_VERIFIED")


if __name__ == "__main__":
    unittest.main()
