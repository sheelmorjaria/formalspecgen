import unittest

from pipeline.jml_io import extract_jml, normalize_line_clause_continuations, normalize_old_in_requires


class JmlContinuationTests(unittest.TestCase):
    def test_extracts_jml_lines_for_terminal_display(self):
        self.assertEqual(extract_jml("class X {\n  //@ requires x > 0;\n}"),
                         ["//@ requires x > 0;"])

    def test_promotes_multiline_ensures_comments(self):
        source = """public class BankAccount {
    //@ ensures (source.balance == \\old(source.balance) - amount &&
    //          destination.balance == \\old(destination.balance) + amount) ||
    //         (source.balance == \\old(source.balance) &&
    //          destination.balance == \\old(destination.balance));
    public static boolean transfer() { return false; }
}
"""
        normalized = normalize_line_clause_continuations(source)
        self.assertEqual(normalized.count("//@"), 4)
        self.assertNotIn("\n    //          destination", normalized)

    def test_does_not_promote_unrelated_comments(self):
        source = """//@ ensures balance >= 0;
// Human explanation.
public long balance() { return 0; }
"""
        self.assertEqual(normalize_line_clause_continuations(source), source)

    def test_preserves_newline_style(self):
        source = "//@ ensures (a &&\r\n// b);\r\n"
        self.assertEqual(normalize_line_clause_continuations(source),
                         "//@ ensures (a &&\r\n//@ b);\r\n")

    def test_old_is_removed_only_from_requires(self):
        source = "//@ requires amount <= \\old(balance);\n//@ ensures balance == \\old(balance);\n"
        self.assertEqual(normalize_old_in_requires(source),
                         "//@ requires amount <= balance;\n//@ ensures balance == \\old(balance);\n")


if __name__ == "__main__":
    unittest.main()
