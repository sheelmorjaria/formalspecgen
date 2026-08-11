# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import unittest
from unittest.mock import patch

from pipeline import refactor_impact


ARCHITECTURE = {
    "name": "System", "description": "",
    "components": [
        {"id": "port", "name": "Port", "layer": "use_cases", "kind": "interface"},
        {"id": "service", "name": "Service", "layer": "use_cases", "kind": "class",
         "dependencies": [{"target": "port", "abstraction": True}]},
    ],
    "use_cases": [{"name": "Do Work", "steps": [{"component": "service", "operation": "run"}]}],
}


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

    def test_verify_sources_classifies_failures_and_vacuity(self):
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
