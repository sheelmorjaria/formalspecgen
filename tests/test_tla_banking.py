import unittest
from unittest.mock import patch

from pipeline import tla_backend


BANKING_JML = r"""
public class Account {
    private long balance;
    //@ requires amount > 0;
    //@ assignable balance;
    //@ ensures \result <==> amount <= 4 - \old(balance);
    //@ ensures \result ==> balance == \old(balance) + amount;
    //@ ensures !\result ==> balance == \old(balance);
    public boolean deposit(long amount) { return false; }
    //@ requires amount > 0;
    //@ assignable balance;
    //@ ensures \result <==> amount <= \old(balance);
    //@ ensures \result ==> balance == \old(balance) - amount;
    //@ ensures !\result ==> balance == \old(balance);
    public boolean withdraw(long amount) { return false; }
    //@ requires from != to;
    //@ requires amount > 0;
    //@ assignable from.balance, to.balance;
    //@ ensures \result <==> (amount <= \old(from.balance) && amount <= 4 - \old(to.balance));
    //@ ensures \result ==> from.balance == \old(from.balance) - amount && to.balance == \old(to.balance) + amount;
    //@ ensures !\result ==> from.balance == \old(from.balance) && to.balance == \old(to.balance);
    public boolean transfer(Account from, Account to, long amount) { return false; }
}
"""

ATOMIC_CLARIFICATIONS = "Operations are linearizable and atomic. Account identity is immutable."


class DeterministicBankingModelTests(unittest.TestCase):
    def test_recognizes_complete_banking_api_only(self):
        source = "class Account { long balance; void deposit(){} void withdraw(){} void transfer(){} }"
        self.assertTrue(tla_backend.detect_banking_boundary(source))
        self.assertFalse(tla_backend.detect_banking_boundary("class Counter { int balance; void add(){} }"))

    def test_template_has_atomic_transfer_and_explicit_invariants(self):
        tla, cfg = tla_backend.banking_model()
        self.assertIn("Transfer(actor, source, destination, amount) ==", tla)
        self.assertIn("![source] = @ - amount", tla)
        self.assertIn("![destination] = @ + amount", tla)
        self.assertIn("INVARIANT BalanceNonNegative", cfg)
        self.assertEqual(tla_backend.lint_tla_model(tla), [])

    def test_banking_route_does_not_call_llm(self):
        checked = {"status": "VERIFIED", "exit_code": 0, "counterexample": [], "output": "ok"}
        source = BANKING_JML
        with patch.object(tla_backend, "check_tla", return_value=checked):
            result = tla_backend.generate_and_check(source, clarifications=ATOMIC_CLARIFICATIONS)
        self.assertEqual(result["model"], "typed-bank_account-ir")
        self.assertEqual(result["renderer"], "bank_account_atomic_operations_v1")
        self.assertEqual(result["ir"]["domain"], "bank_account")
        self.assertEqual(result["status"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()
