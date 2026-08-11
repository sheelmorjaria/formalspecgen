import unittest

from pipeline.parse_check import parse_check
from pipeline.parse_prusti import parse_prusti_vcs
from pipeline.parse_vcs import parse_vcs


class OpenJmlCheckParserTests(unittest.TestCase):
    def test_parses_windows_and_unix_paths(self):
        diagnostics = parse_check(
            "C:\\runs\\Bank.java:23: error: cannot find symbol\n"
            "/tmp/Bank.java:9: warning: unchecked cast\n")
        self.assertEqual([(item.file, item.line, item.category) for item in diagnostics], [
            (r"C:\runs\Bank.java", 23, "error"),
            ("/tmp/Bank.java", 9, "warning"),
        ])
        self.assertEqual(diagnostics[0].detail, "cannot find symbol")

    def test_ignores_noise_and_only_deduplicates_same_file(self):
        line = "A.java:3: error: bad clause"
        diagnostics = parse_check("banner\n" + line + "\n" + line +
                                  "\nB.java:3: error: bad clause\n  ^")
        self.assertEqual(len(diagnostics), 2)
        self.assertEqual({item.file for item in diagnostics}, {"A.java", "B.java"})


class OpenJmlEscParserTests(unittest.TestCase):
    def test_parses_clause_declaration_and_range_detail(self):
        diagnostics = parse_vcs(
            "Account.java:20: verify: The prover cannot establish an assertion "
            "(Postcondition: Account.java:8:) in method withdraw\n"
            "C:\\runs\\Account.java:31: verify: The prover cannot establish an assertion "
            "(ArithmeticOperationRange) in method deposit: overflow in int sum\n")
        self.assertEqual(diagnostics[0].category, "Postcondition")
        self.assertEqual(diagnostics[0].decl, "Account.java:8:")
        self.assertEqual(diagnostics[0].method, "withdraw")
        self.assertIsNone(diagnostics[0].detail)
        self.assertEqual(diagnostics[1].file, r"C:\runs\Account.java")
        self.assertEqual(diagnostics[1].detail, "overflow in int sum")

    def test_ignores_noise_and_preserves_same_failure_in_different_files(self):
        suffix = ":7: verify: The prover cannot establish an assertion (Precondition) in method run"
        diagnostics = parse_vcs("noise\nA.java" + suffix + "\nA.java" + suffix +
                                "\nB.java" + suffix)
        self.assertEqual(len(diagnostics), 2)
        self.assertEqual([item.file for item in diagnostics], ["A.java", "B.java"])


class PrustiParserTests(unittest.TestCase):
    def test_maps_reviewed_categories_and_windows_locations(self):
        cases = [
            ("postcondition might not hold", "Postcondition"),
            ("precondition might not hold", "Precondition"),
            ("loop invariant is not preserved", "LoopInvariant"),
            ("possible arithmetic overflow", "ArithmeticOperationRange"),
            ("possible arithmetic underflow", "ArithmeticOperationRange"),
            ("index may be out of bounds", "ArrayAccess"),
            ("panic is reachable", "PanicSafety"),
            ("termination measure failed", "Termination"),
            ("unknown verifier failure", "PrustiVerification"),
        ]
        text = "\n".join(
            f"error: [Prusti: verification] {message}\n  --> C:\\src\\lib.rs:{index}:5"
            for index, (message, _category) in enumerate(cases, 1))
        diagnostics = parse_prusti_vcs(text)
        self.assertEqual([item.category for item in diagnostics],
                         [category for _message, category in cases])
        self.assertTrue(all(item.file == r"C:\src\lib.rs" for item in diagnostics))

    def test_requires_paired_error_and_location_and_deduplicates(self):
        paired = "error[E0001]: bounds check failed\n --> src/lib.rs:4:2"
        diagnostics = parse_prusti_vcs(
            " --> orphan.rs:1:1\n" + paired + "\n" + paired +
            "\nerror: message without location")
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0].category, "ArrayAccess")
        self.assertIn("src/lib.rs:4:2", diagnostics[0].raw)


if __name__ == "__main__":
    unittest.main()
