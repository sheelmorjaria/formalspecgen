import unittest

from pipeline.spec_lint import lint_spec, blocking_findings


class SpecLintTests(unittest.TestCase):
    def test_boolean_postcondition_must_constrain_result(self):
        source = r"""public class Account {
    //@ ensures balance == \old(balance);
    public boolean transfer() { return false; }
    private /*@ spec_public @*/ long balance;
}"""
        self.assertIn("unconstrained-boolean-result",
                      {warning["code"] for warning in lint_spec(source)})
        self.assertEqual(len(blocking_findings(lint_spec(source))), 1)

    def test_boolean_result_relation_is_accepted(self):
        source = r"""public class Account {
    //@ ensures \result <==> balance > 0;
    public boolean available() { return false; }
    private /*@ spec_public @*/ long balance;
}"""
        self.assertNotIn("unconstrained-boolean-result",
                         {warning["code"] for warning in lint_spec(source)})

    def test_tool_support_advisory_does_not_block_draft(self):
        source = r"""public class Totals {
    //@ requires values != null;
    //@ ensures \result == (\sum int i; 0 <= i && i < values.length; values[i]);
    public int total(int[] values) { return 0; }
}"""
        warnings = lint_spec(source)
        self.assertIn("openjml-unsupported-aggregate", {warning["code"] for warning in warnings})
        self.assertEqual(blocking_findings(warnings), [])

    def test_boolean_false_case_cannot_be_excluded_by_requires(self):
        source = r"""public class Account {
    //@ requires amount > 0;
    //@ requires amount <= balance;
    //@ ensures \result <==> amount <= \old(balance);
    //@ ensures \result ==> balance == \old(balance) - amount;
    //@ ensures !\result ==> balance == \old(balance);
    public boolean withdraw(long amount) { return false; }
    private /*@ spec_public @*/ long balance;
}"""
        warnings = lint_spec(source)
        self.assertIn("boolean-failure-excluded-by-precondition",
                      {warning["code"] for warning in blocking_findings(warnings)})

    def test_exception_case_cannot_contradict_precondition(self):
        source = r"""public class Account {
    //@ requires amount > 0;
    //@ signals (IllegalArgumentException e) amount <= 0;
    //@ ensures \result;
    public boolean deposit(long amount) { return false; }
}"""
        self.assertIn("unreachable-exceptional-behavior",
                      {warning["code"] for warning in blocking_findings(lint_spec(source))})


if __name__ == "__main__":
    unittest.main()
