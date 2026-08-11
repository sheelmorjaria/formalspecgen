import unittest

from pydantic import ValidationError

from pipeline.tla_ir import (
    BankingOperationIR, BankingTlaModel, TLCConfig, preflight_tla, render_banking_model, render_cfg,
)
from pipeline.transition_ir import MethodTransitionIR


class TypedTlaIrTests(unittest.TestCase):
    def test_schema_rejects_unknown_fields_and_unbounded_amounts(self):
        with self.assertRaises(ValidationError):
            BankingTlaModel(guard="accounts'[a].balance -> MaxBalance")
        with self.assertRaises(ValidationError):
            BankingTlaModel(max_balance=4, amounts=[1, 5])

    def test_schema_rejects_unknown_operations_and_invariants(self):
        with self.assertRaises(ValidationError):
            BankingTlaModel(operations=["deposit", "arbitrary_tla"])
        with self.assertRaises(ValidationError):
            BankingTlaModel(invariants=["balance_non_negative", "raw_expression"])

    def test_schema_rejects_operation_and_transition_order_drift(self):
        operation = BankingOperationIR(
            operation="deposit", guard_ids=[], effect_id="atomic_deposit",
            frame_ids=[], result_constrained=False, failure_preserves_frame=False)
        with self.assertRaisesRegex(ValidationError, "operation_ir must correspond"):
            BankingTlaModel(operation_ir=[operation])

        transition = MethodTransitionIR(
            name="deposit", parameters=[], guards=[], success_effects=[],
            failure_effects=[], frame=[], result_constrained=False)
        with self.assertRaisesRegex(ValidationError, "transitions must correspond"):
            BankingTlaModel(transitions=[transition])

    def test_renderer_owns_tla_and_cfg_syntax(self):
        model = BankingTlaModel(accounts=3, actors=2, max_balance=5, amounts=[1, 2])
        tla, cfg = render_banking_model(model)
        self.assertIn("Accounts == {1, 2, 3}", tla)
        self.assertIn("[balances EXCEPT", tla)
        self.assertIn("![destination] = @ + amount", tla)
        self.assertTrue(tla.rstrip().endswith("===="))
        self.assertNotIn("SPECIFICATION Spec", tla)
        self.assertEqual(preflight_tla(tla), [])
        self.assertIn("SPECIFICATION Spec", cfg)
        self.assertIn("CHECK_DEADLOCK FALSE", cfg)

    def test_cfg_schema_rejects_arbitrary_names(self):
        with self.assertRaises(ValidationError):
            TLCConfig(invariants=["RawUserExpression"])
        cfg = render_cfg(TLCConfig(invariants=["TypeOK"]))
        self.assertEqual(cfg, "SPECIFICATION Spec\nINVARIANT TypeOK\nCHECK_DEADLOCK FALSE")

    def test_preflight_rejects_contamination(self):
        errors = preflight_tla("---- MODULE X ----\npublic class X {}\nSPECIFICATION Spec\n====")
        self.assertTrue(any("public class" in item for item in errors))
        self.assertTrue(any("SPECIFICATION" in item for item in errors))


if __name__ == "__main__":
    unittest.main()
