import unittest
from unittest.mock import patch

from pipeline import tla_backend
from pipeline.domains.inventory_extract import (
    UnsupportedJmlSemantics, extract_inventory_model, recognizes_inventory,
)
from pipeline.domains import inventory_extract
from pipeline.domains.inventory_render import render_inventory
from pipeline.tla_ir import preflight_tla


INVENTORY_JML = r"""
public class Inventory {
    private long stock;
    private long reserved;
    //@ requires amount > 0;
    //@ assignable stock;
    //@ ensures \result <==> amount <= 4 - \old(stock);
    //@ ensures \result ==> stock == \old(stock) + amount;
    //@ ensures !\result ==> stock == \old(stock);
    public boolean addStock(long amount) { return false; }
    //@ requires amount > 0;
    //@ assignable reserved;
    //@ ensures \result <==> amount <= \old(stock) - \old(reserved);
    //@ ensures \result ==> reserved == \old(reserved) + amount;
    //@ ensures !\result ==> reserved == \old(reserved);
    public boolean reserve(long amount) { return false; }
    //@ requires amount > 0;
    //@ assignable reserved;
    //@ ensures \result <==> amount <= \old(reserved);
    //@ ensures \result ==> reserved == \old(reserved) - amount;
    //@ ensures !\result ==> reserved == \old(reserved);
    public boolean release(long amount) { return false; }
}
"""


class InventoryDomainTests(unittest.TestCase):
    def test_recognizer_requires_complete_inventory_api(self):
        self.assertTrue(recognizes_inventory(INVENTORY_JML))
        self.assertFalse(recognizes_inventory("class Inventory { void reserve() {} }"))

    def test_ast_adapter_maps_all_reviewed_operations(self):
        model, findings = extract_inventory_model(INVENTORY_JML, "", None)
        self.assertEqual(findings, [])
        self.assertEqual([item.effect_id for item in model.operations],
                         ["increase_stock", "reserve_stock", "release_stock"])
        self.assertEqual(model.transitions[1].success_effects[0].target.field, "reserved")

    def test_wrong_effect_fails_closed(self):
        changed = INVENTORY_JML.replace(
            r"stock == \old(stock) + amount", r"stock == \old(stock) - amount", 1)
        with self.assertRaisesRegex(UnsupportedJmlSemantics, "addStock effect"):
            extract_inventory_model(changed, "", None)

    def test_excessive_frame_is_consistency_failure(self):
        changed = INVENTORY_JML.replace("//@ assignable stock;",
                                        "//@ assignable stock, reserved;", 1)
        _model, findings = extract_inventory_model(changed, "", None)
        self.assertTrue(any(item["code"] == "frame_mismatch" for item in findings))

    def test_adapter_reports_unconstrained_boolean_result(self):
        model, _ = extract_inventory_model(INVENTORY_JML, "", None)
        transition = model.transitions[0].model_copy(update={"result_constrained": False})
        _operation, findings = inventory_extract._map_operation(transition)
        self.assertTrue(any(item["code"] == "unconstrained_result" for item in findings))

    def test_renderer_has_inventory_safety_invariant(self):
        model, _ = extract_inventory_model(INVENTORY_JML, "", None)
        tla, cfg = render_inventory(model)
        self.assertEqual(preflight_tla(tla), [])
        self.assertIn("ReservedWithinStock ==", tla)
        self.assertIn("INVARIANT ReservedWithinStock", cfg)
        self.assertEqual(tla_backend.lint_tla_model(tla), [])

    def test_backend_routes_inventory_without_llm(self):
        checked = {"status": "VERIFIED", "exit_code": 0, "counterexample": [], "output": "ok"}
        with patch.object(tla_backend, "check_tla", return_value=checked):
            result = tla_backend.generate_and_check(INVENTORY_JML)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["domain"], "inventory")
        self.assertEqual(result["ir"]["domain"], "inventory")


if __name__ == "__main__":
    unittest.main()
