import json
import unittest
from unittest.mock import patch

from pipeline import system_design
from pipeline.adr import generate_adr
from pipeline.architecture import check_composition, check_stride, lint_architecture, parse_architecture
from pipeline.llm import LLMError


def valid_architecture():
    return {
        "name": "Payments", "description": "Process trusted payments", "invariants": ["funds conserved"],
        "assumptions": ["network is eventually available"],
        "components": [
            {"id": "port", "name": "PaymentPort", "layer": "use_cases", "kind": "interface",
             "responsibilities": ["pay"], "operations": [
                 {"name": "authorize", "parameters": [{"name": "amount", "type": "int"}],
                  "returns": "boolean", "requires": ["amount > 0"],
                  "ensures": ["authorized"], "assignable": ["\\nothing"]}], "dependencies": []},
            {"id": "gateway", "name": "PaymentGateway", "layer": "infrastructure", "kind": "class",
             "responsibilities": ["remote payment"], "operations": [],
             "dependencies": [{"target": "port", "abstraction": True}]},
        ],
        "use_cases": [{"name": "Make Payment", "requires": ["amount > 0"],
                       "ensures": ["authorized"],
                       "steps": [{"component": "port", "operation": "authorize"}]}],
        "data_flows": [],
    }


def design_text(value=None):
    return ("=== ARCHITECTURE ===\n```json\n" + json.dumps(value or valid_architecture()) +
            "\n```\n=== TLA ===\n---- MODULE P ----\n====\n"
            "=== CFG ===\nSPECIFICATION Spec\n=== END ===")


class ArchitectureTests(unittest.TestCase):
    def test_parse_defaults_and_valid_composition(self):
        architecture = parse_architecture(json.dumps(valid_architecture()))
        self.assertEqual(architecture.name, "Payments")
        self.assertEqual(architecture.components[0].operations[0].returns, "boolean")
        self.assertEqual(check_composition(architecture), [])
        self.assertEqual(check_stride(architecture), [])

    def test_linter_reports_solid_composition_stride_cycle_and_source_smells(self):
        data = valid_architecture()
        data["components"] = [
            {"id": "api", "name": "GodApi", "layer": "unknown", "kind": "class",
             "external": True, "trust_zone": "internet",
             "responsibilities": ["a", "b", "c", "d"],
             "operations": [{"name": f"op{i}"} for i in range(8)],
             "dependencies": [{"target": "missing", "abstraction": False},
                              {"target": "core", "abstraction": False}]},
            {"id": "core", "name": "Core", "layer": "entities", "kind": "class",
             "privilege": "admin", "dependencies": [{"target": "infra", "abstraction": False}],
             "operations": []},
            {"id": "infra", "name": "Infra", "layer": "infrastructure", "kind": "class",
             "dependencies": [{"target": "core", "abstraction": False}], "operations": []},
        ]
        data["use_cases"] = [{"name": "Broken", "requires": [], "ensures": ["done"],
                              "steps": [{"component": "core", "operation": "missing"}]}]
        data["data_flows"] = [{"source": "api", "target": "core", "data": "credentials",
                                "classification": "secret", "authenticated": False,
                                "authorized": False, "encrypted": False, "audited": False,
                                "bounded": False}]
        warnings = lint_architecture(parse_architecture(data), {
            "Switch.java": "if (x instanceof A) {} else if (x instanceof B) {}"})
        codes = {item["code"] for item in warnings}
        expected = {"unknown-layer", "single-responsibility", "interface-segregation",
                    "missing-component", "dependency-inversion", "dependency-cycle",
                    "missing-operation", "composition-postcondition", "stride-spoofing",
                    "stride-tampering", "stride-repudiation", "stride-information-disclosure",
                    "stride-denial-of-service", "stride-elevation-of-privilege",
                    "open-closed-type-switch"}
        self.assertTrue(expected <= codes, expected - codes)

    def test_stride_invalid_endpoint_and_verified_sanitizer(self):
        data = valid_architecture()
        data["data_flows"] = [{"source": "missing", "target": "port", "data": "x"}]
        self.assertEqual(check_stride(parse_architecture(data))[0]["code"], "stride-invalid-flow")
        data["components"].append({
            "id": "input", "name": "Input", "layer": "adapters", "kind": "interface",
            "external": True, "trust_zone": "internet", "operations": [{
                "name": "sanitize", "ensures": ["payload validated"]}]})
        data["data_flows"] = [{"source": "input", "target": "port", "data": "payload",
                               "sanitizer_operation": "input.sanitize", "authenticated": True,
                               "audited": True, "bounded": True}]
        self.assertEqual(check_stride(parse_architecture(data)), [])

    def test_adr_records_accepted_and_proposed_decisions(self):
        accepted = generate_adr(valid_architecture(), {"status": "VERIFIED"}, number=7)
        self.assertIn("# ADR-0007: Payments", accepted)
        self.assertIn("Status: Accepted", accepted)
        self.assertIn("funds conserved", accepted)
        broken = valid_architecture(); broken["components"][0]["layer"] = "bad"
        proposed = generate_adr(broken, {"status": "VERIFIED"})
        self.assertIn("Status: Proposed", proposed)
        self.assertIn("Unresolved blocking findings", proposed)

    def test_adr_renders_optional_architecture_evidence(self):
        data = valid_architecture()
        data["name"] = "***"
        data["components"].append({
            "id": "reader", "name": "AccountReader", "layer": "entities",
            "kind": "interface", "operations": [], "dependencies": []})
        data["data_flows"] = [{
            "source": "gateway", "target": "port", "data": "payment",
            "authenticated": True, "authorized": True, "encrypted": True}]
        adr = generate_adr(data, {"status": "VERIFIED"})
        self.assertIn("# ADR-0001: System Architecture", adr)
        self.assertIn("Dependencies cross layers through declared abstractions", adr)
        self.assertIn("Interface Segregation", adr)
        self.assertIn("Architectural safety invariants", adr)
        self.assertIn("STRIDE mitigations", adr)
        self.assertIn("## Assumptions", adr)


class SystemDesignTests(unittest.TestCase):
    def test_parse_design_accepts_fenced_json_and_rejects_bad_sections(self):
        architecture, tla, cfg = system_design.parse_design(design_text())
        self.assertEqual(architecture.name, "Payments")
        self.assertTrue(tla.startswith("---- MODULE"))
        self.assertIn("SPECIFICATION", cfg)
        with self.assertRaisesRegex(ValueError, "section markers"):
            system_design.parse_design("not a design")
        empty = valid_architecture(); empty["components"] = []
        with self.assertRaisesRegex(ValueError, "no components"):
            system_design.parse_design(design_text(empty))

    def test_design_system_verified_parse_retry_api_error_and_stall(self):
        def successful_chat(*_args):
            return design_text(), "model", {}
        with patch.object(system_design, "_chat_fn", return_value=successful_chat), \
             patch.object(system_design, "check_tla", return_value={"status": "VERIFIED"}):
            result = system_design.design_system("payments")
        self.assertEqual(result["status"], "VERIFIED")

        replies = iter([("bad", "m", {}), (design_text(), "m", {})])
        with patch.object(system_design, "_chat_fn", return_value=lambda *_args: next(replies)), \
             patch.object(system_design, "check_tla", return_value={"status": "VERIFIED"}):
            retried = system_design.design_system("payments", max_attempts=2)
        self.assertEqual([item["status"] for item in retried["attempts"]],
                         ["PARSE_ERROR", "VERIFIED"])

        with patch.object(system_design, "_chat_fn",
                          return_value=lambda *_args: (_ for _ in ()).throw(LLMError("NETWORK", "off"))):
            self.assertEqual(system_design.design_system("x")["status"], "API_ERROR")
        with patch.object(system_design, "_chat_fn", return_value=successful_chat), \
             patch.object(system_design, "check_tla", return_value={"status": "TLC_FAILED"}):
            stalled = system_design.design_system("payments", max_attempts=2)
        self.assertEqual(stalled["status"], "STALLED")
        self.assertEqual(len(stalled["attempts"]), 2)

    def test_scaffold_interfaces_runs_check_and_composition_esc(self):
        with patch.object(system_design, "verify_files", side_effect=[(0, ""), (0, "")]) as verify:
            result = system_design.scaffold_interfaces(valid_architecture())
        self.assertEqual(result["status"], "VALIDATED")
        self.assertEqual(result["composition_verification"]["status"], "VERIFIED")
        self.assertIn("PaymentPort.java", result["files"])
        self.assertIn("MakePaymentOrchestrator.java", result["files"])
        self.assertIn("return port.authorize(amount);", result["files"]["MakePaymentOrchestrator.java"])
        self.assertEqual(verify.call_count, 2)

    def test_scaffold_surfaces_check_and_esc_diagnostics(self):
        check = "Port.java:2: error: bad contract"
        with patch.object(system_design, "verify_files", return_value=(1, check)):
            failed = system_design.scaffold_interfaces(valid_architecture())
        self.assertEqual(failed["status"], "CHECK_FAILED")
        self.assertEqual(failed["checks"][0]["diagnostics"][0]["line"], 2)


if __name__ == "__main__":
    unittest.main()
