import unittest
from unittest.mock import patch

from pipeline.refine import refine
from pipeline.schemas import SpecDraft


ORIGINAL = """public class C {
    //@ ensures \\result >= 0;
    public int value() { return 0; }
}"""
CHANGED = """public class C {
    //@ ensures \\result > 0;
    public int value() { return 1; }
}"""


class RefineTrustBoundaryTests(unittest.TestCase):
    def test_locked_clause_modification_is_terminal_and_non_applicable(self):
        with patch("pipeline.refine.glm_refine",
                   return_value=(SpecDraft(CHANGED), "model", {})), \
             patch("pipeline.refine._chat_fn"), patch("pipeline.refine.check_stub", return_value=(True, [])):
            result = refine(ORIGINAL, "strengthen it", [r"ensures \\result >= 0;"])
        self.assertEqual(result.status, "TRUST_BOUNDARY_VIOLATION")
        self.assertTrue(result.terminal)
        self.assertEqual(result.new_stub, ORIGINAL)
        self.assertEqual(result.candidate_stub, CHANGED)


if __name__ == "__main__":
    unittest.main()
