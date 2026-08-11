import unittest

from pipeline.extract_tla_ir import (
    UnsupportedJmlSemantics, extract_banking_model,
)
from pipeline.tla_ir import render_banking_model
from test_tla_banking import ATOMIC_CLARIFICATIONS, BANKING_JML


class JmlSemanticExtractionTests(unittest.TestCase):
    def test_extracts_reviewed_guards_effects_frames_and_failure(self):
        model, findings = extract_banking_model(BANKING_JML, ATOMIC_CLARIFICATIONS)
        self.assertEqual(findings, [])
        transfer = model.operation_ir[2]
        self.assertEqual(transfer.effect_id, "atomic_transfer")
        self.assertEqual(set(transfer.frame_ids), {"source_balance", "destination_balance"})
        self.assertIn("source_has_funds", transfer.guard_ids)
        self.assertIn("destination_has_capacity", transfer.guard_ids)
        self.assertTrue(transfer.failure_preserves_frame)

    def test_unknown_effect_fails_closed(self):
        changed = BANKING_JML.replace(
            r"balance == \old(balance) + amount",
            r"balance >= \old(balance)", 1)
        with self.assertRaisesRegex(UnsupportedJmlSemantics, "result-guarded postcondition"):
            extract_banking_model(changed, ATOMIC_CLARIFICATIONS)

    def test_missing_frame_is_a_consistency_failure(self):
        changed = BANKING_JML.replace("//@ assignable balance;", "//@ assignable \\nothing;", 1)
        model, findings = extract_banking_model(changed, ATOMIC_CLARIFICATIONS)
        self.assertEqual(model.abstraction, "atomic_operations")
        self.assertTrue(any(item["code"] == "frame_mismatch" and
                            item["operation"] == "deposit" for item in findings))

    def test_missing_failure_preservation_is_detected(self):
        changed = BANKING_JML.replace(
            r"//@ ensures !\result ==> balance == \old(balance);", "", 1)
        _model, findings = extract_banking_model(changed, ATOMIC_CLARIFICATIONS)
        self.assertTrue(any(item["code"] == "failure_changes_state" for item in findings))

    def test_lock_protocol_requires_ordered_immutable_ids(self):
        with self.assertRaisesRegex(UnsupportedJmlSemantics, "ascending immutable"):
            extract_banking_model(BANKING_JML, ATOMIC_CLARIFICATIONS,
                                  abstraction="lock_protocol")

    def test_lock_protocol_renders_intermediate_program_counters(self):
        clarification = (
            "Operations are linearizable. Transfers acquire locks in ascending immutable "
            "account-ID order and hold both through the update. Account identity is immutable.")
        model, findings = extract_banking_model(BANKING_JML, clarification)
        self.assertEqual(findings, [])
        self.assertEqual(model.abstraction, "lock_protocol")
        tla, cfg = render_banking_model(model)
        self.assertIn("AcquireSecond(actor) ==", tla)
        self.assertIn("HaveFirst", tla)
        self.assertIn("INVARIANT OrderedLocking", cfg)
        self.assertNotIn("CHECK_DEADLOCK FALSE", cfg)

    def test_missing_linearization_metadata_fails_closed(self):
        with self.assertRaisesRegex(UnsupportedJmlSemantics, "linearization"):
            extract_banking_model(BANKING_JML, "Balances are bounded.")


if __name__ == "__main__":
    unittest.main()
