# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch

from pipeline import tla_backend
from pipeline.assurance import refinement_gate
from pipeline.domains.traffic_light_controller_extract import (
    UnsupportedJmlSemantics, extract_traffic_light_controller_model,
    diagnose_traffic_light_boundary, recognizes_traffic_light_controller,
)
from pipeline.domains.traffic_light_controller_render import (
    render_traffic_light_controller,
)
from pipeline.tla_ir import preflight_tla
from pipeline.limitations import reviewed_domain_guardrails


TRAFFIC_LIGHT_JML = r"""
public class TrafficLightController {
    private int ns_light;
    private int ew_light;
    //@ public invariant 0 <= ns_light && ns_light <= 2;
    //@ public invariant 0 <= ew_light && ew_light <= 2;
    //@ public invariant !(ns_light == 2 && ew_light == 2);

    //@ ensures ns_light == 0 && ew_light == 0;
    public TrafficLightController() {}

    //@ requires ew_light == 0;
    //@ assignable ns_light;
    //@ ensures ns_light == 2;
    public void turnNsGreen() {}
    //@ requires ns_light == 2;
    //@ assignable ns_light;
    //@ ensures ns_light == 1;
    public void turnNsYellow() {}
    //@ requires ns_light == 1;
    //@ assignable ns_light;
    //@ ensures ns_light == 0;
    public void turnNsRed() {}
    //@ requires ns_light == 0;
    //@ assignable ew_light;
    //@ ensures ew_light == 2;
    public void turnEwGreen() {}
    //@ requires ew_light == 2;
    //@ assignable ew_light;
    //@ ensures ew_light == 1;
    public void turnEwYellow() {}
    //@ requires ew_light == 1;
    //@ assignable ew_light;
    //@ ensures ew_light == 0;
    public void turnEwRed() {}
}
"""


class TrafficLightControllerDomainTests(unittest.TestCase):
    def _architecture(self):
        checked = {"status": "VERIFIED", "exit_code": 0,
                   "counterexample": [], "output": "ok"}
        with patch.object(tla_backend, "check_tla", return_value=checked):
            return tla_backend.generate_and_check(TRAFFIC_LIGHT_JML)

    def test_complete_api_is_recognized(self):
        self.assertTrue(recognizes_traffic_light_controller(TRAFFIC_LIGHT_JML))
        self.assertFalse(recognizes_traffic_light_controller("class X {}"))

    def test_three_action_draft_gets_actionable_boundary_diagnostics(self):
        draft = """class TrafficLightController {
          int nsLight; int ewLight;
          //@ requires nsLight != 2;
          public void setNorthSouthGreen() {}
          //@ requires ewLight != 2;
          public void setEastWestGreen() {}
          public void resetLights() {}
        }"""
        details = diagnose_traffic_light_boundary(draft)
        self.assertTrue(any("missing reviewed operations" in item for item in details))
        self.assertTrue(any("three-action API" in item for item in details))
        self.assertTrue(any("state locations" in item for item in details))
        self.assertTrue(any("weakened" in item for item in details))
        result = tla_backend.generate_and_check(draft)
        self.assertEqual(result["status"], "UNSUPPORTED_BOUNDARY")
        self.assertIn("turnNsGreen", result["message"])

    def test_boolean_six_action_api_is_not_misrecognized_as_reviewed_void_api(self):
        boolean_api = TRAFFIC_LIGHT_JML.replace("public void ", "public boolean ").replace(
            "() {}", "() { return false; }")
        self.assertFalse(recognizes_traffic_light_controller(boolean_api))
        details = diagnose_traffic_light_boundary(boolean_api)
        self.assertTrue(any("must return void" in item for item in details))

    def test_non_traffic_source_has_no_traffic_diagnostics(self):
        self.assertEqual(diagnose_traffic_light_boundary("class Counter {}"), [])
        self.assertEqual(reviewed_domain_guardrails("bounded counter"), "")
        guidance = reviewed_domain_guardrails("Design a traffic-light controller")
        self.assertIn("turnNsYellow", guidance)
        self.assertIn("Do not rename", guidance)

    def test_reviewed_contract_extracts_without_findings(self):
        model, findings = extract_traffic_light_controller_model(
            TRAFFIC_LIGHT_JML, "single-threaded", "atomic_operations")
        self.assertEqual(findings, [])
        self.assertEqual(len(model.transitions), 6)
        self.assertEqual(model.execution_assumption, "single_threaded")

    def test_weakened_green_guard_is_rejected(self):
        weakened = TRAFFIC_LIGHT_JML.replace(
            "//@ requires ew_light == 0;", "//@ requires ew_light != 2;", 1)
        _model, findings = extract_traffic_light_controller_model(weakened, "", None)
        self.assertTrue(any(item["code"] == "guard_mismatch" for item in findings))

    def test_wrong_frame_is_rejected(self):
        unsafe = TRAFFIC_LIGHT_JML.replace(
            "//@ assignable ns_light;", "//@ assignable ns_light, ew_light;", 1)
        _model, findings = extract_traffic_light_controller_model(unsafe, "", None)
        self.assertTrue(any(item["code"] == "frame_mismatch" for item in findings))

    def test_unknown_effect_fails_closed(self):
        unsupported = TRAFFIC_LIGHT_JML.replace(
            "//@ ensures ns_light == 2;", "//@ ensures ns_light == 0;", 1)
        with self.assertRaisesRegex(UnsupportedJmlSemantics, "effect mapping"):
            extract_traffic_light_controller_model(unsupported, "", None)

    def test_constructor_and_abstraction_boundaries_fail_closed(self):
        without_constructor = TRAFFIC_LIGHT_JML.replace(
            "    //@ ensures ns_light == 0 && ew_light == 0;\n"
            "    public TrafficLightController() {}\n", "")
        with self.assertRaisesRegex(UnsupportedJmlSemantics, "constructor contract"):
            extract_traffic_light_controller_model(without_constructor, "", None)
        wrong_init = TRAFFIC_LIGHT_JML.replace(
            "ensures ns_light == 0 && ew_light == 0",
            "ensures ns_light == 1 && ew_light == 0")
        with self.assertRaisesRegex(UnsupportedJmlSemantics, "Constructor must establish"):
            extract_traffic_light_controller_model(wrong_init, "", None)
        with self.assertRaisesRegex(UnsupportedJmlSemantics, "only atomic_operations"):
            extract_traffic_light_controller_model(
                TRAFFIC_LIGHT_JML, "", "lock_protocol")

    def test_incomplete_api_fails_closed_after_constructor_check(self):
        incomplete = TRAFFIC_LIGHT_JML.replace("public void turnEwRed() {}", "")
        with self.assertRaisesRegex(UnsupportedJmlSemantics, "all six"):
            extract_traffic_light_controller_model(incomplete, "", None)

    def test_reversed_equality_guard_is_structurally_supported(self):
        reversed_guard = TRAFFIC_LIGHT_JML.replace(
            "//@ requires ew_light == 0;", "//@ requires 0 == ew_light;", 1)
        _model, findings = extract_traffic_light_controller_model(
            reversed_guard, "", None)
        self.assertEqual(findings, [])

    def test_non_equality_and_non_field_guards_are_rejected(self):
        non_equality = TRAFFIC_LIGHT_JML.replace(
            "//@ requires ew_light == 0;", "//@ requires ew_light < 1;", 1)
        _model, findings = extract_traffic_light_controller_model(non_equality, "", None)
        self.assertTrue(any(item["code"] == "guard_mismatch" for item in findings))
        non_field = TRAFFIC_LIGHT_JML.replace(
            "public void turnNsGreen() {}",
            "public void turnNsGreen(int amount) {}", 1).replace(
                "//@ requires ew_light == 0;", "//@ requires amount == 0;", 1)
        _model, findings = extract_traffic_light_controller_model(non_field, "", None)
        self.assertTrue(any(item["code"] == "guard_mismatch" for item in findings))

    def test_renderer_has_complete_state_and_safety_invariant(self):
        model, _ = extract_traffic_light_controller_model(TRAFFIC_LIGHT_JML, "", None)
        tla, cfg = render_traffic_light_controller(model)
        self.assertEqual(preflight_tla(tla), [])
        self.assertIn("Init == /\\ nsLight = 0 /\\ ewLight = 0", tla)
        self.assertIn("NoSimultaneousGreenLights ==", tla)
        self.assertIn("/\\ UNCHANGED ewLight", tla)
        self.assertIn("INVARIANT NoSimultaneousGreenLights", cfg)
        with self.assertRaisesRegex(UnsupportedJmlSemantics, "Incomplete"):
            render_traffic_light_controller(model.model_copy(update={"operations": []}))

    def test_backend_routes_and_retains_refinement_disclaimer(self):
        checked = {"status": "VERIFIED", "exit_code": 0,
                   "counterexample": [], "output": "ok"}
        with patch.object(tla_backend, "check_tla", return_value=checked):
            result = tla_backend.generate_and_check(TRAFFIC_LIGHT_JML)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["domain"], "traffic_light_controller")
        self.assertFalse(result["source_refinement_proved"])
        self.assertIn("not Java/JML source equivalence", result["disclaimer"])
        self.assertIn("single threaded execution", result["disclaimer"])
        self.assertEqual(result["provenance"]["execution_assumption"], "single_threaded")

    def test_refinement_gate_proves_all_six_method_action_obligations(self):
        result = refinement_gate(
            TRAFFIC_LIGHT_JML, TRAFFIC_LIGHT_JML, self._architecture(),
            esc_verified=True)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertTrue(result["source_refinement_proved"])
        self.assertFalse(result["concurrent_linearizability_proved"])
        methods = [item for item in result["obligations"]
                   if item["kind"] == "method_action"]
        self.assertEqual(len(methods), 6)
        self.assertTrue(all(item["status"] == "PROVED" for item in methods))
        self.assertEqual(result["abstraction_mapping"], {
            "this.ns_light": "nsLight", "this.ew_light": "ewLight"})
        self.assertEqual(len(result["certificate_sha256"]), 64)

    def test_refinement_gate_requires_esc_tlc_domain_and_execution_assumption(self):
        architecture = self._architecture()
        self.assertEqual(refinement_gate(
            TRAFFIC_LIGHT_JML, TRAFFIC_LIGHT_JML, architecture,
            esc_verified=False)["code"], "esc_not_verified")
        failed_tlc = {**architecture, "status": "TLC_FAILED"}
        self.assertEqual(refinement_gate(
            TRAFFIC_LIGHT_JML, TRAFFIC_LIGHT_JML, failed_tlc,
            esc_verified=True)["code"], "tla_not_verified")
        wrong_domain = {**architecture, "domain": "inventory"}
        self.assertEqual(refinement_gate(
            TRAFFIC_LIGHT_JML, TRAFFIC_LIGHT_JML, wrong_domain,
            esc_verified=True)["code"], "unsupported_refinement_domain")
        wrong_execution = {**architecture, "provenance": {
            **architecture["provenance"], "execution_assumption": "concurrent"}}
        self.assertEqual(refinement_gate(
            TRAFFIC_LIGHT_JML, TRAFFIC_LIGHT_JML, wrong_execution,
            esc_verified=True)["code"], "unsupported_execution_model")

    def test_refinement_gate_rejects_contract_drift_and_checked_ir_drift(self):
        architecture = self._architecture()
        changed = TRAFFIC_LIGHT_JML.replace(
            "//@ requires ew_light == 0;", "//@ requires ew_light != 2;", 1)
        self.assertEqual(refinement_gate(
            TRAFFIC_LIGHT_JML, changed, architecture,
            esc_verified=True)["code"], "contract_model_inconsistent")
        changed_ir = {**architecture, "ir": {**architecture["ir"], "operations": []}}
        self.assertEqual(refinement_gate(
            TRAFFIC_LIGHT_JML, TRAFFIC_LIGHT_JML, changed_ir,
            esc_verified=True)["code"], "architecture_ir_mismatch")
        unsupported = TRAFFIC_LIGHT_JML.replace("public void turnEwRed() {}", "")
        self.assertEqual(refinement_gate(
            unsupported, unsupported, architecture,
            esc_verified=True)["code"], "unsupported_jml_semantics")

    def test_refinement_gate_rejects_tla_action_serialization_drift(self):
        architecture = self._architecture()
        architecture["tla"] = architecture["tla"].replace(
            "TurnNsGreen == /\\ ewLight = 0",
            "TurnNsGreen == /\\ ewLight = 1", 1)
        result = refinement_gate(
            TRAFFIC_LIGHT_JML, TRAFFIC_LIGHT_JML, architecture,
            esc_verified=True)
        self.assertEqual(result["code"], "refinement_obligation_failed")
        self.assertTrue(any(item.get("serialized_action_aligned") is False
                            for item in result["obligations"]))

    def test_refinement_gate_fails_closed_on_internal_mapping_defects(self):
        architecture = self._architecture()
        model, _ = extract_traffic_light_controller_model(
            TRAFFIC_LIGHT_JML, "", "atomic_operations")
        with patch(
                "pipeline.domains.traffic_light_controller_extract."
                "extract_traffic_light_controller_model",
                side_effect=[(model, []),
                             (model.model_copy(update={"operations": []}), [])]):
            result = refinement_gate(
                TRAFFIC_LIGHT_JML, TRAFFIC_LIGHT_JML, architecture,
                esc_verified=True)
        self.assertEqual(result["code"], "trusted_contract_changed")

        duplicate_mapping = {
            "this.ns_light": "nsLight", "this.ew_light": "nsLight"}
        with patch("pipeline.domains.traffic_light_controller.ABSTRACTION_MAPPING",
                   duplicate_mapping):
            result = refinement_gate(
                TRAFFIC_LIGHT_JML, TRAFFIC_LIGHT_JML, architecture,
                esc_verified=True)
        self.assertEqual(result["code"], "invalid_abstraction_mapping")

        from pipeline.domains.traffic_light_controller import ACTION_REFINEMENTS
        incomplete_actions = dict(ACTION_REFINEMENTS)
        incomplete_actions.pop("turnEwRed")
        with patch("pipeline.domains.traffic_light_controller.ACTION_REFINEMENTS",
                   incomplete_actions):
            result = refinement_gate(
                TRAFFIC_LIGHT_JML, TRAFFIC_LIGHT_JML, architecture,
                esc_verified=True)
        self.assertEqual(result["code"], "operation_coverage_mismatch")

        duplicate_actions = {name: dict(value)
                             for name, value in ACTION_REFINEMENTS.items()}
        duplicate_actions["turnEwRed"]["action"] = "TurnNsRed"
        with patch("pipeline.domains.traffic_light_controller.ACTION_REFINEMENTS",
                   duplicate_actions):
            result = refinement_gate(
                TRAFFIC_LIGHT_JML, TRAFFIC_LIGHT_JML, architecture,
                esc_verified=True)
        self.assertEqual(result["code"], "duplicate_tla_action")


if __name__ == "__main__":
    unittest.main()
