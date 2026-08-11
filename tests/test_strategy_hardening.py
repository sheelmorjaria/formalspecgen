import unittest

from pipeline import strategy
from pipeline.schemas import VC


class StrategyHardeningTests(unittest.TestCase):
    def test_resample_and_feedback_budgets_are_independent(self):
        history = [("a", [VC("A.java", 1, "error", detail="one")], "one")]
        decision = strategy.decide(history, False, samples_done=1, feedback_done=0,
                                   resample_budget=2, feedback_budget=1)
        self.assertEqual(decision.action, "sample")
        decision = strategy.decide(history, False, samples_done=2, feedback_done=0,
                                   resample_budget=2, feedback_budget=1)
        self.assertEqual(decision.action, "feedback")

    def test_repeated_candidate_hash_detects_non_adjacent_cycle(self):
        vc = [VC("A.java", 1, "error", detail="different")]
        history = [("first", [VC("A.java", 1, "a", detail="a")], "a"),
                   ("second", [VC("A.java", 2, "b", detail="b")], "b"),
                   ("third", [VC("A.java", 3, "c", detail="c")], "c"),
                   ("first", vc, "d")]
        self.assertIn("candidate hash repeated", strategy.is_stalled(history))

    def test_distinct_failures_do_not_stall_or_imply_ambiguity(self):
        history = [
            (f"candidate-{index}",
             [VC("A.java", index, f"category-{index}", detail=f"detail-{index}")],
             f"tool-{index}")
            for index in range(1, 4)
        ]
        self.assertEqual(strategy.is_stalled(history), "")
        self.assertIsNone(strategy.ambiguity_suspected(history))


if __name__ == "__main__":
    unittest.main()
