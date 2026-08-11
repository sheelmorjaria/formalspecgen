import unittest
from unittest.mock import patch

from pipeline import tla_backend
from pipeline.domains.train_crossing_extract import extract_train_crossing_model
from pipeline.domains.train_crossing_render import render_train_crossing
from pipeline.tla_ir import preflight_tla


TRAIN_CROSSING_JML = r"""
public class TrainRoadCrossing {
    private int train_pos;
    private int gate_state;
    private int car_pos;
    //@ requires train_pos == 0;
    //@ assignable train_pos;
    //@ ensures train_pos == 1;
    public void trainApproaches() {}
    //@ requires train_pos == 1;
    //@ requires gate_state == 0;
    //@ requires car_pos == 0;
    //@ assignable gate_state;
    //@ ensures gate_state == 1;
    public void lowerGate() {}
    //@ requires train_pos == 1;
    //@ requires gate_state == 1;
    //@ assignable train_pos;
    //@ ensures train_pos == 2;
    public void trainEnters() {}
    //@ requires train_pos == 2;
    //@ assignable train_pos;
    //@ ensures train_pos == 3;
    public void trainLeaves() {}
    //@ requires train_pos == 3;
    //@ requires gate_state == 1;
    //@ assignable gate_state;
    //@ ensures gate_state == 0;
    public void raiseGate() {}
    //@ requires gate_state == 0;
    //@ requires car_pos == 0;
    //@ assignable car_pos;
    //@ ensures car_pos == 1;
    public void carCrosses() {}
    //@ requires car_pos == 1;
    //@ assignable car_pos;
    //@ ensures car_pos == 0;
    public void carLeaves() {}
}
"""


class TrainCrossingDomainTests(unittest.TestCase):
    def test_safe_contract_maps_without_findings(self):
        model, findings = extract_train_crossing_model(TRAIN_CROSSING_JML, "", None)
        self.assertEqual(findings, [])
        self.assertEqual(model.domain, "train_crossing")
        self.assertEqual(len(model.transitions), 7)

    def test_lower_gate_requires_clear_crossing(self):
        unsafe = TRAIN_CROSSING_JML.replace("    //@ requires car_pos == 0;\n", "", 1)
        _model, findings = extract_train_crossing_model(unsafe, "", None)
        self.assertTrue(any(item["code"] == "missing_guard" and
                            item["operation"] == "lowerGate" for item in findings))

    def test_train_leaves_does_not_raise_gate_implicitly(self):
        model, _ = extract_train_crossing_model(TRAIN_CROSSING_JML, "", None)
        transition = next(item for item in model.transitions if item.name == "trainLeaves")
        self.assertEqual([item.target.field for item in transition.success_effects], ["train_pos"])
        self.assertEqual([item.field for item in transition.frame], ["train_pos"])

    def test_renderer_contains_collision_invariant_and_car_exit(self):
        model, _ = extract_train_crossing_model(TRAIN_CROSSING_JML, "", None)
        tla, cfg = render_train_crossing(model)
        self.assertEqual(preflight_tla(tla), [])
        self.assertIn("SafetyNoCollision == ~(trainPos = 2 /\\ carPos = 1)", tla)
        self.assertIn("CarLeaves ==", tla)
        self.assertIn("/\\ carPos = 0", tla.split("LowerGate ==", 1)[1].split("TrainEnters ==", 1)[0])
        self.assertIn("INVARIANT SafetyNoCollision", cfg)

    def test_backend_routes_train_crossing(self):
        checked = {"status": "VERIFIED", "exit_code": 0, "counterexample": [], "output": "ok"}
        with patch.object(tla_backend, "check_tla", return_value=checked):
            result = tla_backend.generate_and_check(TRAIN_CROSSING_JML)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["domain"], "train_crossing")


if __name__ == "__main__":
    unittest.main()
