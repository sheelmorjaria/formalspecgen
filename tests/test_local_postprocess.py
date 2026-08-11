import unittest

from pipeline.ide import PASS_NAMES, apply_passes


class LocalPostprocessorTests(unittest.TestCase):
    def test_every_declared_pass_is_bundled_and_callable(self):
        report = apply_passes("public class Empty {}")
        self.assertEqual([item["name"] for item in report["passes"]], list(PASS_NAMES))
        self.assertFalse(report["changed"])

    def test_pass_runs_without_formalspecdd_checkout(self):
        source = """public class Shift {
    public int f(int r) {
        while ((1 << r) < 8) { r++; }
        return r;
    }
}"""
        report = apply_passes(source, ["inject_bitshift_bounds"])
        self.assertTrue(report["changed"])
        self.assertIn("loop_invariant r <= 30", report["code"])
        self.assertTrue(report["requires_human_acceptance"])
        self.assertFalse(report["accepted"])
        self.assertEqual(report["claim"], "TRANSFORMATION")


if __name__ == "__main__":
    unittest.main()
