import unittest

from pipeline.domain_generator import compile_domain_spec, elicit_domain_questions
from pipeline.llm import LLMError
from pipeline.scaffold_domain import scaffold_sources


class DomainGeneratorTests(unittest.TestCase):
    def test_elicitation_preserves_domain_categories(self):
        def chat(_messages, _model, _temperature):
            return ('{"questions":[{"id":"q1","category":"invariant",'
                    '"question":"What must never happen?","required":true}]}', "model", {})
        questions, _, _ = elicit_domain_questions("An elevator", chat)
        self.assertEqual(questions[0]["category"], "invariant")

    def test_valid_json_is_deterministically_serialized_and_scaffolded(self):
        response = {
            "domain_name": "Thermostat", "module_name": "thermostat",
            "state_variables": [
                {"name": "temperature", "type": "int", "bound": [0, 10]},
                {"name": "mode", "type": "int", "bound": [0, 2]},
            ],
            "operations": [{"name": "heat", "guards": ["below_target"],
                            "effect": "increase_temperature", "frame": ["temperature"],
                            "ast_pattern": "temperature == \\old(temperature) + 1"}],
            "tlc_invariants": ["TypeOK"],
        }
        def chat(_messages, _model, _temperature):
            import json
            return json.dumps(response), "model", {"total_tokens": 1}
        spec, yaml_text, _, _ = compile_domain_spec(
            "A thermostat", [], [], chat)
        self.assertIn("domain_name: Thermostat", yaml_text)
        files = scaffold_sources(spec)
        self.assertIn("pipeline/domains/thermostat_extract.py", files)
        self.assertIn("not reviewed", files["pipeline/domains/thermostat_render.py"])

    def test_invalid_model_spec_fails_closed(self):
        def chat(_messages, _model, _temperature):
            return ('{"domain_name":"Bad","module_name":"bad","state_variables":[],'
                    '"operations":[],"tlc_invariants":[]}', "model", {})
        with self.assertRaisesRegex(LLMError, "state_variables"):
            compile_domain_spec("bad domain", [], [], chat)

    def test_required_domain_answer_is_enforced_before_second_llm_call(self):
        calls = 0
        def chat(_messages, _model, _temperature):
            nonlocal calls
            calls += 1
            return "{}", "model", {}
        questions = [{"id": "q1", "category": "bounds", "question": "Upper bound?",
                      "required": True}]
        with self.assertRaisesRegex(ValueError, "required domain clarification"):
            compile_domain_spec("counter", questions, [], chat)
        self.assertEqual(calls, 0)


if __name__ == "__main__":
    unittest.main()
