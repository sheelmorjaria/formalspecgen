import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pipeline import tla_backend
from test_tla_banking import ATOMIC_CLARIFICATIONS, BANKING_JML


class TlaRepairTests(unittest.TestCase):
    def test_unsupported_domain_fails_closed_without_calling_tlc(self):
        with patch.object(tla_backend, "check_tla") as check:
            result = tla_backend.generate_and_check("class ConcurrentQueue {}")
        check.assert_not_called()
        self.assertEqual(result["status"], "UNSUPPORTED_BOUNDARY")
        self.assertIn("Direct LLM-to-TLA+ generation is disabled", result["message"])

    def test_invariant_violation_returns_original_ir_without_source_repair(self):
        failed = {"status": "INVARIANT_VIOLATION", "exit_code": 12,
                  "counterexample": ["State 1"], "output": "violated"}
        source = BANKING_JML
        with patch.object(tla_backend, "check_tla", return_value=failed) as check:
            result = tla_backend.generate_and_check(
                source, clarifications=ATOMIC_CLARIFICATIONS)

        self.assertEqual(result["status"], "INVARIANT_VIOLATION")
        self.assertEqual(check.call_count, 1)
        self.assertEqual(result["ir"]["domain"], "bank_account")
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(result["claim"], "BOUNDED_ARCHITECTURE_EVIDENCE")
        self.assertFalse(result["source_refinement_proved"])
        self.assertEqual(result["repair_target"], "validated_ir")
        self.assertFalse(result["generated_tla_repair_allowed"])

    def test_plugin_semantic_consistency_and_render_failures_are_terminal(self):
        ir = SimpleNamespace(
            abstraction="atomic_operations",
            model_dump=lambda: {"domain": "test", "abstraction": "atomic_operations"})
        plugin = SimpleNamespace(name="test")

        with patch("pipeline.domains.router.select_domain", return_value=plugin), \
             patch.object(plugin, "extract", side_effect=tla_backend.UnsupportedJmlSemantics("bad semantics"),
                          create=True):
            semantic = tla_backend.generate_and_check("contract")
        self.assertEqual(semantic["status"], "UNSUPPORTED_BOUNDARY")
        self.assertEqual(semantic["renderer"], "none")

        plugin.extract = lambda *_args: (ir, [{"message": "frame mismatch"}])
        with patch("pipeline.domains.router.select_domain", return_value=plugin):
            inconsistent = tla_backend.generate_and_check("contract")
        self.assertEqual(inconsistent["status"], "CONSISTENCY_FAILED")
        self.assertEqual(inconsistent["ir"]["domain"], "test")

        plugin.extract = lambda *_args: (ir, [])
        plugin.render = lambda _ir: ("not a module", "SPECIFICATION Spec")
        with patch("pipeline.domains.router.select_domain", return_value=plugin), \
             patch.object(tla_backend, "check_tla") as check:
            malformed = tla_backend.generate_and_check("contract")
        self.assertEqual(malformed["status"], "TRANSLATION_ERROR")
        check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
