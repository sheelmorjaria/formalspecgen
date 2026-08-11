import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline import orchestrator
from pipeline.schemas import SpecDraft


BAD = r"""public class Account {
    //@ ensures balance == \old(balance);
    public boolean deposit(long amount) { return false; }
    private /*@ spec_public @*/ long balance;
}"""

GOOD = r"""public class Account {
    //@ ensures \result <==> balance == \old(balance) + amount;
    public boolean deposit(long amount) { return false; }
    private /*@ spec_public @*/ long balance;
}"""


class OrchestratorLintGateTests(unittest.TestCase):
    def test_clean_openjml_check_repairs_blocking_spec_lint(self):
        def clean_check(directory, stub, fallback_name):
            path = Path(directory) / "Account.java"
            path.write_text(stub)
            return 0, "", [], path

        with tempfile.TemporaryDirectory() as directory, \
             patch.object(orchestrator, "_gen", return_value=(SpecDraft(BAD), "model", {})), \
             patch.object(orchestrator, "_repair", return_value=(SpecDraft(GOOD), "model", {})), \
             patch.object(orchestrator, "_check_attempt", side_effect=clean_check):
            result = orchestrator.run("An account", out_dir=directory)
            verdict = __import__("json").loads((Path(directory) / "verdict.json").read_text())

        self.assertEqual([attempt.status for attempt in result.attempts],
                         ["SPEC_LINT_FAILED", "VERIFIED"])
        self.assertEqual(result.final_status, "VERIFIED")
        self.assertEqual(result.pipeline_state, "REVIEW_AND_MEASURE")
        self.assertEqual(result.claim, "STATIC_CHECK")
        self.assertTrue(result.transitions)
        self.assertIn("source_sha256", result.provenance)
        self.assertIn("contract_sha256", verdict["provenance"])
        self.assertFalse(verdict["provenance"]["source_refinement_proved"])


if __name__ == "__main__":
    unittest.main()
