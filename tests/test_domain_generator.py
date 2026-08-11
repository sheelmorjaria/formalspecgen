import unittest

from pipeline.domain_generator import (
    compile_domain_spec, compile_domain_spec_v2, elicit_domain_questions,
)
from pipeline.llm import LLMError
from pipeline.scaffold_domain import DomainSpec, scaffold_sources


class DomainGeneratorTests(unittest.TestCase):
    @staticmethod
    def v2_value():
        return {
            "schema_version": 2, "review_status": "unreviewed",
            "domain_name": "Switch", "module_name": "switch", "actors": 1,
            "state_variables": [{"kind": "bool", "name": "enabled", "initial": False}],
            "operations": [{"name": "enable", "return_type": "void",
                "failure_semantics": "unavailable", "guards": [],
                "effects": [{"id": "set_enabled", "target": "enabled",
                             "value": {"kind": "boolean", "value": True}}],
                "frame": ["enabled"]}],
            "tlc_invariants": [{"id": "EnabledIsBoolean", "expression": {
                "kind": "or", "left": {"kind": "field", "name": "enabled"},
                "right": {"kind": "eq", "left": {"kind": "field", "name": "enabled"},
                          "right": {"kind": "boolean", "value": False}}}}],
        }

    def test_v2_generation_uses_typed_schema_and_serializes_yaml(self):
        import json
        captured = []
        def chat(messages, _model, _temperature):
            captured.extend(messages)
            return json.dumps(self.v2_value()), "model", {"total_tokens": 1}
        spec, yaml_text, _, _ = compile_domain_spec_v2("A switch", [], [], chat)
        self.assertEqual(spec.schema_version, 2)
        self.assertIn("kind: boolean", yaml_text)
        self.assertIn("Required JSON Schema", captured[1]["content"])
        self.assertIn("typed trees", captured[0]["content"])

    def test_v2_generation_repairs_attempted_self_review_and_enforces_answers(self):
        import json
        reviewed = {**self.v2_value(), "review_status": "reviewed"}
        responses = iter([reviewed, self.v2_value()])
        def chat(_messages, _model, _temperature):
            return json.dumps(next(responses)), "model", {}
        spec, _, _, usage = compile_domain_spec_v2("A switch", [], [], chat)
        self.assertEqual(spec.review_status, "unreviewed")
        self.assertEqual(usage["domain_spec_repair_attempts"], 1)
        question = [{"id": "q", "category": "bounds", "question": "Bound?",
                     "required": True}]
        with self.assertRaisesRegex(ValueError, "required domain clarification"):
            compile_domain_spec_v2("A switch", question, [], chat)

    def test_v2_generation_exhausts_both_validation_and_self_review_repairs(self):
        import json
        invalid_calls = 0
        def invalid(_messages, _model, _temperature):
            nonlocal invalid_calls
            invalid_calls += 1
            return json.dumps({}), "model", {}
        with self.assertRaisesRegex(LLMError, "schema-aware repair was rejected"):
            compile_domain_spec_v2("A switch", [], [], invalid)
        self.assertEqual(invalid_calls, 3)

        reviewed = {**self.v2_value(), "review_status": "reviewed"}
        reviewed_calls = 0
        def self_reviewed(_messages, _model, _temperature):
            nonlocal reviewed_calls
            reviewed_calls += 1
            return json.dumps(reviewed), "model", {}
        with self.assertRaisesRegex(LLMError, "generated V2 candidates cannot assign"):
            compile_domain_spec_v2("A switch", [], [], self_reviewed)
        self.assertEqual(reviewed_calls, 3)

    def test_v2_authoritative_answers_are_in_prompt_and_bounds_conflicts_fail_early(self):
        import json
        captured = []
        def chat(messages, _model, _temperature):
            captured.extend(messages)
            return json.dumps(self.v2_value()), "model", {}
        questions = [{"id": "q", "category": "state", "question": "Initial mode?",
                      "required": True}]
        compile_domain_spec_v2("A switch", questions, [{"id": "q", "answer": "off"}], chat)
        self.assertIn("A: off", captured[1]["content"])
        elevator_questions = [
            {"id": "other", "category": "state", "question": "Door state?", "required": True},
            {"id": "floor1", "category": "bounds", "question": "Floor range?", "required": True},
            {"id": "floor2", "category": "invariant", "question": "Floor invariant?", "required": True},
        ]
        answers = [{"id": "other", "answer": "closed"},
                   {"id": "floor1", "answer": "0-4"},
                   {"id": "floor2", "answer": "1 <= current_floor && current_floor <= 5"}]
        with self.assertRaisesRegex(ValueError, "conflicting elevator floor bounds"):
            compile_domain_spec_v2("An elevator", elevator_questions, answers, chat)

    def test_elicitation_preserves_domain_categories(self):
        captured = []
        def chat(_messages, _model, _temperature):
            captured.extend(_messages)
            return ('{"questions":[{"id":"q1","category":"invariant",'
                    '"question":"What must never happen?","required":true}]}', "model", {})
        questions, _, _ = elicit_domain_questions("An elevator", chat)
        self.assertEqual(questions[0]["category"], "invariant")
        self.assertIn("STATE OBSERVABILITY", captured[0]["content"])
        self.assertIn("arrive/stop/complete", captured[0]["content"])

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

    def test_expression_contamination_gets_one_schema_aware_repair(self):
        rejected = {
            "domain_name": "TrafficLights", "module_name": "traffic_lights",
            "state_variables": [
                {"name": "ns_light", "type": "int", "bound": [0, 3]},
                {"name": "ew_light", "type": "int", "bound": [0, 3]},
            ],
            "operations": [{"name": "changeNorthSouth", "guards": ["ew_light = 0"],
                            "effect": "ns_light = 2", "frame": ["ns_light"],
                            "ast_pattern": "ns_light == 2"}],
            "tlc_invariants": ["NoConflictingGreen"],
        }
        repaired = {
            **rejected,
            "operations": [{"name": "changeNorthSouth", "guards": ["east_west_is_red"],
                            "effect": "set_north_south_green", "frame": ["ns_light"],
                            "ast_pattern": "ns_light == 2"}],
        }
        responses = iter((rejected, repaired))
        prompts = []

        def chat(messages, _model, _temperature):
            import json
            prompts.append(messages)
            return json.dumps(next(responses)), "model", {"total_tokens": 1}

        spec, yaml_text, _, usage = compile_domain_spec("Traffic lights", [], [], chat)
        self.assertEqual(spec.operations[0].guards, ["east_west_is_red"])
        self.assertEqual(spec.operations[0].effect, "set_north_south_green")
        self.assertIn("set_north_south_green", yaml_text)
        self.assertEqual(usage["domain_spec_repair_attempts"], 1)
        self.assertIn("validation_errors", prompts[1][1]["content"])
        self.assertIn("OPERATOR NAMES", prompts[1][0]["content"])

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

    def test_duration_state_requires_observable_entry_and_exit(self):
        from pydantic import ValidationError
        base = {
            "domain_name": "Elevator", "module_name": "elevator",
            "state_variables": [
                {"name": "floor", "type": "int", "bound": [0, 4]},
                {"name": "moving_state", "type": "int", "bound": [0, 2]},
            ],
            "operations": [{"name": "move_up", "guards": ["below_top"],
                            "effect": "increment_floor", "frame": ["floor"],
                            "ast_pattern": "floor == \\old(floor) + 1"}],
            "tlc_invariants": ["DoorsClosedWhileMoving"],
        }
        with self.assertRaisesRegex(ValidationError, "in-transit safety invariants are vacuous"):
            DomainSpec.model_validate(base)

        base["operations"] = [
            {"name": "start_move_up", "guards": ["stopped", "doors_closed", "below_top"],
             "effect": "set_moving_up", "frame": ["moving_state"],
             "ast_pattern": "moving_state == 1"},
            {"name": "arrive_up", "guards": ["moving_up"],
             "effect": "stop_moving_and_increment", "frame": ["floor", "moving_state"],
             "ast_pattern": "floor == \\old(floor) + 1 && moving_state == 0"},
        ]
        spec = DomainSpec.model_validate(base)
        self.assertEqual([item.name for item in spec.operations],
                         ["start_move_up", "arrive_up"])

    def test_elevator_conflicting_floor_ranges_fail_before_llm(self):
        calls = 0
        def chat(_messages, _model, _temperature):
            nonlocal calls
            calls += 1
            return "{}", "model", {}
        questions = [
            {"id": "q1", "category": "bounds", "question": "Valid floors?", "required": True},
            {"id": "q2", "category": "invariant", "question": "Floor invariant?", "required": True},
        ]
        answers = [
            {"id": "q1", "answer": "Use 0-4."},
            {"id": "q2", "answer": "Use 1 <= current_floor && current_floor <= 5."},
        ]
        with self.assertRaisesRegex(ValueError, "conflicting elevator floor bounds.*0..4, 1..5"):
            compile_domain_spec("An elevator", questions, answers, chat)
        self.assertEqual(calls, 0)

    def test_domain_schema_gets_at_most_two_repairs(self):
        calls = 0
        def chat(_messages, _model, _temperature):
            nonlocal calls
            calls += 1
            return ('{"domain_name":"Bad","module_name":"bad","state_variables":[],'
                    '"operations":[],"tlc_invariants":[]}', "model", {})
        with self.assertRaisesRegex(LLMError, "schema-aware repair was rejected"):
            compile_domain_spec("bad domain", [], [], chat)
        self.assertEqual(calls, 3)

    def test_ambiguous_generated_elevator_shape_is_rejected(self):
        from pydantic import ValidationError
        bad = {
            "domain_name": "Elevator", "module_name": "elevator",
            "state_variables": [
                {"name": "current_floor", "type": "int", "bound": [0, 4]},
                {"name": "door_state", "type": "int", "bound": [0, 1]},
                {"name": "moving_state", "type": "int", "bound": [0, 2]},
            ],
            "operations": [
                {"name": "startMoveUp", "guards": ["moving_state", "door_state"],
                 "effect": "set_moving_state", "frame": ["moving_state", "door_state"],
                 "ast_pattern": "moving_state == 1 && door_state == 0"},
                {"name": "arrive", "guards": ["moving_state"],
                 "effect": "set_current_floor", "frame": ["moving_state", "current_floor"],
                 "ast_pattern": "current_floor' = current_floor +/- 1"},
                {"name": "openDoors", "guards": ["moving_state"],
                 "effect": "set_door_state", "frame": ["door_state"],
                 "ast_pattern": "door_state == 1"},
            ],
            "tlc_invariants": ["DoorsClosedWhileMoving"],
        }
        with self.assertRaises(ValidationError):
            DomainSpec.model_validate(bad)

    def test_binary_door_state_requires_close_transition(self):
        from pydantic import ValidationError
        spec = {
            "domain_name": "Door", "module_name": "door",
            "state_variables": [{"name": "door_state", "type": "int", "bound": [0, 1]}],
            "operations": [{"name": "openDoor", "guards": ["door_is_closed"],
                            "effect": "open_door", "frame": ["door_state"],
                            "ast_pattern": "door_state == 1"}],
            "tlc_invariants": ["TypeOK"],
        }
        with self.assertRaisesRegex(ValidationError, "both open and close"):
            DomainSpec.model_validate(spec)

    def test_generic_state_setter_effect_is_rejected(self):
        from pydantic import ValidationError
        spec = {
            "domain_name": "Counter", "module_name": "counter",
            "state_variables": [{"name": "count", "type": "int", "bound": [0, 4]}],
            "operations": [{"name": "increment", "guards": ["below_maximum"],
                            "effect": "set_count", "frame": ["count"],
                            "ast_pattern": "count == \\old(count) + 1"}],
            "tlc_invariants": ["TypeOK"],
        }
        with self.assertRaisesRegex(ValidationError, "concrete transition"):
            DomainSpec.model_validate(spec)

    def test_primed_or_direction_ambiguous_ast_pattern_is_rejected(self):
        from pydantic import ValidationError
        base = {
            "domain_name": "Lift", "module_name": "lift",
            "state_variables": [{"name": "floor", "type": "int", "bound": [0, 4]}],
            "operations": [{"name": "arrive", "guards": ["in_transit"],
                            "effect": "arrive_at_adjacent_floor", "frame": ["floor"],
                            "ast_pattern": "floor' = floor + 1"}],
            "tlc_invariants": ["TypeOK"],
        }
        with self.assertRaisesRegex(ValidationError, "ambiguous/pseudocode"):
            DomainSpec.model_validate(base)
        base["operations"][0]["ast_pattern"] = "floor == \\old(floor) +/- 1"
        with self.assertRaisesRegex(ValidationError, "ambiguous/pseudocode"):
            DomainSpec.model_validate(base)

    def test_binary_door_state_accepts_reviewable_open_and_close_transitions(self):
        spec = {
            "domain_name": "Door", "module_name": "door",
            "state_variables": [{"name": "door_state", "type": "int", "bound": [0, 1]}],
            "operations": [
                {"name": "openDoor", "guards": ["door_is_closed"],
                 "effect": "open_door", "frame": ["door_state"],
                 "ast_pattern": "door_state == 1"},
                {"name": "closeDoor", "guards": ["door_is_open"],
                 "effect": "close_door", "frame": ["door_state"],
                 "ast_pattern": "door_state == 0"},
            ],
            "tlc_invariants": ["TypeOK"],
        }
        self.assertEqual(DomainSpec.model_validate(spec).module_name, "door")


if __name__ == "__main__":
    unittest.main()
