import json
import unittest

import pipeline.domain_generator as domain_generator

from pipeline.domain_generator import (
    _canonical_integer_guard_tree, _complete_literal_bound_guards,
    _dsl_expression, _frame_effect_repair_obligations, _normalize_v2_syntax,
    _reject_initial_values_outside_answered_bounds,
    compile_domain_spec, compile_domain_spec_v2,
    elicit_domain_questions,
)
from pipeline.llm import LLMError
from pipeline.domain_v2 import DomainSpecV2
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

    def test_v2_staged_generation_assembles_exact_operation_fragments(self):
        value = self.v2_value()
        header = {key: item for key, item in value.items()
                  if key not in {"operations", "tlc_invariants"}}
        header["invariant_plans"] = [{
            "id": "EnabledIsBoolean", "clause_names": ["EnabledClause"]}]
        header["operation_plans"] = [{"name": "enable", "frame": ["enabled"],
            "guard_expressions": ["enabled == false"],
            "effect_values": {"enabled": "true"}}]
        calls = []
        compact_invariant = {"id": "EnabledClause",
                             "expression": "enabled == true"}
        compact_operation = {
            "name": "enable", "return_type": "void",
            "failure_semantics": "none",
            "guards": [{"id": "enabled == false", "expression": "enabled == false"}],
            "effects": [{"id": "enabled := true", "target": "enabled", "value": "true"}],
            "frame": ["enabled"], "exception_type": None, "exception_trigger": None}

        def structured_for(_schema, name):
            def chat(_messages, _model, _temperature):
                calls.append(name)
                response = (header if name == "v2_domain_header" else
                            compact_invariant
                            if name == "v2_domain_invariant_clause" else
                            compact_operation)
                return json.dumps(response), "ollama", {"total_tokens": 2}
            chat.structured_for = structured_for
            return chat

        root_chat = structured_for({}, "root")
        progress = []
        spec, _, used, usage = compile_domain_spec_v2(
            "A switch", [], [], root_chat, progress=progress.append)

        self.assertEqual(spec.operations[0].name, "enable")
        self.assertEqual(spec.operations[0].failure_semantics, "unavailable")
        self.assertEqual(spec.operations[0].guards[0].id, "guard_1")
        self.assertEqual(spec.operations[0].effects[0].id, "effect_1")
        self.assertEqual(calls, ["v2_domain_header", "v2_domain_invariant_clause",
                                 "v2_domain_operation"])
        self.assertEqual(used, "ollama")
        self.assertEqual(usage["total_tokens"], 6)
        self.assertEqual(usage["domain_spec_staged_invariants"], 1)
        self.assertEqual(usage["domain_spec_staged_operations"], 1)
        self.assertIn("Generating V2 manifest", progress[0])
        self.assertTrue(any("Generating invariant clause EnabledIsBoolean.EnabledClause" in item
                            for item in progress))
        self.assertTrue(any("Generating operation enable" in item for item in progress))
        self.assertIn("Fragments assembled", progress[-1])

    def test_v2_staged_manifest_preserves_required_complete_lock_protocol(self):
        value = self.v2_value()
        value["actors"] = 2
        value["state_variables"].insert(0, {
            "kind": "int", "name": "lock_state", "bound": [0, 2], "initial": 0})
        header = {key: item for key, item in value.items()
                  if key not in {"operations", "tlc_invariants"}}
        header["concurrency"] = {"mode": "lock_protocol", "lock_variable": "lock_state",
            "lock_states": ["UNLOCKED", "LOCKED_A", "LOCKED_B"],
            "unlocked_value": 0, "actor_lock_values": [1, 2],
            "linearization_points": {"enable": "effect_commit"}}
        header["invariant_plans"] = [{
            "id": "EnabledIsBoolean", "clause_names": ["EnabledClause"]}]
        header["operation_plans"] = [{"name": "enable", "frame": ["enabled"],
            "guard_expressions": ["enabled == false"],
            "effect_values": {"enabled": "true"}}]
        invariant = {"id": "EnabledClause", "expression": "enabled == true"}
        operation = {"name": "enable", "return_type": "void",
            "failure_semantics": "unavailable",
            "guards": [{"id": "disabled", "expression": "enabled == false"}],
            "effects": [{"id": "set", "target": "enabled", "value": "true"}],
            "frame": ["enabled"], "exception_type": None, "exception_trigger": None}

        def structured_for(_schema, name):
            def chat(*_args):
                response = (header if name == "v2_domain_header" else invariant
                            if name == "v2_domain_invariant_clause" else operation)
                return json.dumps(response), "ollama", {}
            chat.structured_for = structured_for
            return chat

        spec, *_ = compile_domain_spec_v2(
            "A lock_protocol switch", [], [], structured_for({}, "root"))
        self.assertEqual(spec.concurrency.mode, "lock_protocol")
        self.assertEqual(spec.concurrency.linearization_points, {"enable": "effect_commit"})

    def test_v2_staged_manifest_rejects_required_null_lock_protocol(self):
        value = self.v2_value()
        header = {key: item for key, item in value.items()
                  if key not in {"operations", "tlc_invariants"}}
        header["concurrency"] = None
        header["invariant_plans"] = [{
            "id": "EnabledIsBoolean", "clause_names": ["EnabledClause"]}]
        header["operation_plans"] = [{"name": "enable", "frame": ["enabled"],
            "guard_expressions": [], "effect_values": {"enabled": "true"}}]

        def structured_for(_schema, _name):
            def chat(*_args):
                return json.dumps(header), "ollama", {}
            chat.structured_for = structured_for
            return chat

        with self.assertRaisesRegex(LLMError, "concurrency null"):
            compile_domain_spec_v2(
                "A lock_protocol switch", [], [], structured_for({}, "root"))

    def test_v2_staged_generation_rejects_misnamed_operation(self):
        value = self.v2_value()
        header = {key: item for key, item in value.items()
                  if key not in {"operations", "tlc_invariants"}}
        header["invariant_plans"] = [{
            "id": "EnabledIsBoolean", "clause_names": ["EnabledClause"]}]
        header["operation_plans"] = [{"name": "enable", "frame": ["enabled"],
            "guard_expressions": [], "effect_values": {"enabled": "true"}}]
        wrong = {**value["operations"][0], "name": "disable"}
        wrong["effects"][0]["value"] = "true"
        compact_invariant = {"id": "EnabledClause", "expression": "enabled == true"}

        def structured_for(_schema, name):
            def chat(_messages, _model, _temperature):
                response = (header if name == "v2_domain_header" else
                            compact_invariant
                            if name == "v2_domain_invariant_clause" else wrong)
                return json.dumps(response), "m", {}
            chat.structured_for = structured_for
            return chat

        with self.assertRaisesRegex(LLMError, "staged candidate generation failed closed"):
            compile_domain_spec_v2("A switch", [], [], structured_for({}, "root"))

    def test_v2_staged_manifest_canonicalizes_frame_from_effect_targets(self):
        value = self.v2_value()
        header = {key: item for key, item in value.items()
                  if key not in {"operations", "tlc_invariants"}}
        header["invariant_plans"] = [{
            "id": "EnabledIsBoolean", "clause_names": ["EnabledClause"]}]
        valid_plan = {"name": "enable", "frame": ["enabled"],
                      "guard_expressions": [], "effect_values": {"enabled": "true"}}
        invalid_header = {**header, "operation_plans": [{
            **valid_plan, "frame": ["enabled", "enabled"]}]}
        header_responses = [invalid_header]
        invariant = {"id": "EnabledClause", "expression": "enabled == true"}
        operation = {
            "name": "enable", "return_type": "void", "failure_semantics": "none",
            "guards": [], "effects": [{"id": "set", "target": "enabled",
                                          "value": "true"}],
            "frame": ["enabled"], "exception_type": None, "exception_trigger": None}

        def structured_for(_schema, name):
            def chat(_messages, _model, _temperature):
                response = (header_responses.pop(0) if name == "v2_domain_header" else
                            invariant if name == "v2_domain_invariant_clause" else operation)
                return json.dumps(response), "ollama", {}
            chat.structured_for = structured_for
            return chat

        progress = []
        spec, *_ = compile_domain_spec_v2(
            "A switch", [], [], structured_for({}, "root"), progress=progress.append)
        self.assertEqual(spec.operations[0].frame, ["enabled"])
        self.assertFalse(any("Repairing V2 manifest" in message for message in progress))

    def test_compact_v2_expression_parser_is_strict_and_preserves_precedence(self):
        expression = _dsl_expression(
            "pc0 == 3 ==> (fork0 == 1 && fork1 == 1)", {"pc0", "fork0", "fork1"})
        self.assertEqual(expression["kind"], "implies")
        self.assertEqual(expression["right"]["kind"], "and")
        with self.assertRaisesRegex(ValueError, "unknown identifier"):
            _dsl_expression("missing == 1", {"pc0"})
        with self.assertRaisesRegex(ValueError, "unsupported V2 expression construct"):
            _dsl_expression("pc0 * 2", {"pc0"})
        self.assertEqual(_dsl_expression("!(pc0 == 0) || true", {"pc0"})["kind"], "or")
        self.assertEqual(_dsl_expression("pc0 + 1", {"pc0"})["kind"], "add")
        self.assertEqual(_dsl_expression("msg_channel == -1", {"msg_channel"}), {
            "kind": "eq",
            "left": {"kind": "field", "name": "msg_channel"},
            "right": {"kind": "integer", "value": -1},
        })
        with self.assertRaisesRegex(ValueError, "unsupported V2 expression construct"):
            _dsl_expression("-pc0", {"pc0"})
        with self.assertRaisesRegex(ValueError, "unsupported V2 expression construct"):
            _dsl_expression("other.pc0 == 0", {"pc0"})

    def test_staged_helpers_cover_usage_and_exception_trigger(self):
        self.assertEqual(domain_generator._merge_usage(
            {"total_tokens": 2, "model": "old"},
            {"total_tokens": 3, "model": "new"}),
            {"total_tokens": 5, "model": "new"})
        operation = domain_generator._OperationDsl.model_validate({
            "name": "fail", "return_type": "void", "failure_semantics": "exception",
            "guards": [], "effects": [{
                "id": "set_enabled", "target": "enabled", "value": "true"}],
            "frame": ["enabled"], "exception_type": "IllegalStateException",
            "exception_trigger": "enabled == true"})
        lowered = domain_generator._operation_from_dsl(operation, {"enabled"})
        self.assertEqual(lowered.exception_trigger.kind, "eq")

    def test_staged_manifest_repairs_bad_dsl_before_fragments(self):
        value = self.v2_value()
        good = {key: item for key, item in value.items()
                if key not in {"operations", "tlc_invariants"}}
        good["invariant_plans"] = [{
            "id": "EnabledIsBoolean", "clause_names": ["EnabledClause"]}]
        good["operation_plans"] = [{"name": "enable", "frame": ["enabled"],
            "guard_expressions": [], "effect_values": {"enabled": "true"}}]
        bad = json.loads(json.dumps(good))
        bad["operation_plans"][0]["effect_values"]["enabled"] = "integer(value=1)"
        responses = {
            "v2_domain_header": [bad, good],
            "v2_domain_invariant_clause": [{
                "id": "EnabledClause", "expression": "enabled == true"}],
            "v2_domain_operation": [{
                "name": "enable", "return_type": "void", "failure_semantics": "unavailable",
                "guards": [], "effects": [{
                    "id": "set", "target": "enabled", "value": "true"}],
                "frame": ["enabled"], "exception_type": None, "exception_trigger": None}],
        }
        progress = []
        def structured_for(_schema, name):
            def chat(*_args):
                return json.dumps(responses[name].pop(0)), "m", {}
            chat.structured_for = structured_for
            return chat
        spec, *_ = compile_domain_spec_v2(
            "A switch", [], [], structured_for({}, "root"), progress=progress.append)
        self.assertEqual(spec.operations[0].name, "enable")
        self.assertTrue(any("Repairing V2 manifest" in item for item in progress))

    def test_staged_operation_local_repair_succeeds(self):
        value = self.v2_value()
        header = {key: item for key, item in value.items()
                  if key not in {"operations", "tlc_invariants"}}
        header["invariant_plans"] = [{
            "id": "EnabledIsBoolean", "clause_names": ["EnabledClause"]}]
        header["operation_plans"] = [{"name": "enable", "frame": ["enabled"],
            "guard_expressions": [], "effect_values": {"enabled": "true"}}]
        wrong = {"name": "enable", "return_type": "void",
            "failure_semantics": "unavailable", "guards": [],
            "effects": [{"id": "set", "target": "enabled", "value": "false"}],
            "frame": ["enabled"], "exception_type": None, "exception_trigger": None}
        right = {**wrong, "effects": [{
            "id": "set", "target": "enabled", "value": "true"}]}
        responses = {"v2_domain_header": [header],
            "v2_domain_invariant_clause": [{
                "id": "x", "expression": "enabled == true"}],
            "v2_domain_operation": [wrong, right]}
        progress = []
        def structured_for(_schema, name):
            def chat(*_args):
                return json.dumps(responses[name].pop(0)), "m", {}
            chat.structured_for = structured_for
            return chat
        spec, *_ = compile_domain_spec_v2(
            "A switch", [], [], structured_for({}, "root"), progress=progress.append)
        self.assertTrue(spec.operations[0].effects[0].value.value)
        self.assertTrue(any("Repairing operation enable" in item for item in progress))

    def test_staged_manifest_repair_exhaustion_and_duplicate_plan_reject(self):
        def broken_structured_for(_schema, _name):
            def chat(*_args):
                return "{}", "m", {}
            chat.structured_for = broken_structured_for
            return chat
        with self.assertRaisesRegex(LLMError, "manifest failed local repair"):
            compile_domain_spec_v2("A switch", [], [], broken_structured_for({}, "root"))

        value = self.v2_value()
        header = {key: item for key, item in value.items()
                  if key not in {"operations", "tlc_invariants"}}
        plan = {"name": "enable", "frame": ["enabled"],
                "guard_expressions": [], "effect_values": {"enabled": "true"}}
        header["invariant_plans"] = [{
            "id": "EnabledIsBoolean", "clause_names": ["a", "a"]}]
        header["operation_plans"] = [plan]
        def duplicate_structured_for(_schema, name):
            def chat(*_args):
                return json.dumps(header), "m", {}
            chat.structured_for = duplicate_structured_for
            return chat
        with self.assertRaisesRegex(LLMError, "invalid version, review status"):
            compile_domain_spec_v2("A switch", [], [], duplicate_structured_for({}, "root"))

    def test_staged_multi_clause_assembly_and_invalid_plan_frame(self):
        value = self.v2_value()
        header = {key: item for key, item in value.items()
                  if key not in {"operations", "tlc_invariants"}}
        header["invariant_plans"] = [{
            "id": "EnabledIsBoolean", "clause_names": ["one", "two"]}]
        header["operation_plans"] = [{"name": "enable", "frame": ["enabled"],
            "guard_expressions": [], "effect_values": {"enabled": "true"}}]
        responses = {"v2_domain_header": [header],
            "v2_domain_invariant_clause": [
                {"id": "one", "expression": "enabled == true"},
                {"id": "two", "expression": "enabled == false"}],
            "v2_domain_operation": [{
                "name": "enable", "return_type": "void", "failure_semantics": "unavailable",
                "guards": [], "effects": [{
                    "id": "set", "target": "enabled", "value": "true"}],
                "frame": ["enabled"], "exception_type": None, "exception_trigger": None}]}
        def structured_for(_schema, name):
            def chat(*_args):
                return json.dumps(responses[name].pop(0)), "m", {}
            chat.structured_for = structured_for
            return chat
        spec, *_ = compile_domain_spec_v2("A switch", [], [], structured_for({}, "root"))
        self.assertEqual(spec.tlc_invariants[0].expression.kind, "and")

        header["invariant_plans"] = [{"id": "EnabledIsBoolean", "clause_names": ["one"]}]
        header["operation_plans"][0]["frame"] = ["missing"]
        header["operation_plans"][0]["effect_values"] = {"missing": "true"}
        responses = {"v2_domain_header": [header, header, header],
            "v2_domain_invariant_clause": [{"id": "one", "expression": "enabled == true"}]}
        with self.assertRaisesRegex(LLMError, "has invalid frame"):
            compile_domain_spec_v2("A switch", [], [], structured_for({}, "root"))

    def test_staged_void_skip_failure_alias_is_canonicalized(self):
        value = self.v2_value()
        header = {key: item for key, item in value.items()
                  if key not in {"operations", "tlc_invariants"}}
        header["invariant_plans"] = [{
            "id": "EnabledIsBoolean", "clause_names": ["EnabledClause"]}]
        header["operation_plans"] = [{"name": "enable", "frame": ["enabled"],
            "guard_expressions": [], "effect_values": {"enabled": "true"}}]
        responses = {
            "v2_domain_header": header,
            "v2_domain_invariant_clause": {
                "id": "EnabledClause", "expression": "enabled == true"},
            "v2_domain_operation": {
                "name": "enable", "return_type": "void", "failure_semantics": "skip",
                "guards": [], "effects": [{
                    "id": "set_enabled", "target": "enabled", "value": "true"}],
                "frame": ["enabled"], "exception_type": None, "exception_trigger": None},
        }
        def structured_for(_schema, name):
            def chat(*_args):
                return json.dumps(responses[name]), "m", {}
            chat.structured_for = structured_for
            return chat
        spec, *_ = compile_domain_spec_v2(
            "A switch", [], [], structured_for({}, "root"))
        self.assertEqual(spec.operations[0].failure_semantics, "unavailable")

    def test_staged_operation_frame_must_match_manifest_plan(self):
        value = self.v2_value()
        value["state_variables"].append({
            "kind": "bool", "name": "secondary", "initial": False})
        header = {key: item for key, item in value.items()
                  if key not in {"operations", "tlc_invariants"}}
        header["invariant_plans"] = [{
            "id": "EnabledIsBoolean", "clause_names": ["EnabledClause"]}]
        header["operation_plans"] = [{"name": "enable", "frame": ["enabled"],
            "guard_expressions": [], "effect_values": {"enabled": "true"}}]
        responses = {
            "v2_domain_header": header,
            "v2_domain_invariant_clause": {
                "id": "EnabledClause", "expression": "enabled == true"},
            "v2_domain_operation": {
                "name": "enable", "return_type": "void",
                "failure_semantics": "unavailable", "guards": [],
                "effects": [{"id": "wrong", "target": "secondary", "value": "true"}],
                "frame": ["secondary"], "exception_type": None, "exception_trigger": None},
        }
        def structured_for(_schema, name):
            def chat(*_args):
                return json.dumps(responses[name]), "m", {}
            chat.structured_for = structured_for
            return chat
        with self.assertRaisesRegex(LLMError, "does not match required exact frame"):
            compile_domain_spec_v2("A switch", [], [], structured_for({}, "root"))

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

    def test_v2_generation_overlays_partial_repair_fragment(self):
        rejected = self.v2_value()
        rejected.pop("tlc_invariants")
        invariant = self.v2_value()["tlc_invariants"]
        responses = iter((rejected, {"tlc_invariants": invariant}))

        def chat(_messages, _model, _temperature):
            return json.dumps(next(responses)), "model", {}

        spec, _, _, usage = compile_domain_spec_v2("A switch", [], [], chat)

        self.assertEqual(spec.domain_name, "Switch")
        self.assertEqual(spec.tlc_invariants[0].id, "EnabledIsBoolean")
        self.assertEqual(usage["domain_spec_repair_attempts"], 1)
        self.assertIn("partial repair fragment", {
            change["from"] for change in usage["domain_spec_normalizations"]})

    def test_v2_generation_repairs_semantically_unrelated_domain(self):
        import json
        unrelated = {**self.v2_value(), "domain_name": "BankAccount",
                     "module_name": "account_module"}
        smart_lock = self.v2_value()
        smart_lock["domain_name"] = "SmartLock"
        smart_lock["module_name"] = "smart_lock"
        responses = iter((unrelated, smart_lock))
        captured = []
        def chat(messages, _model, _temperature):
            captured.append(messages)
            return json.dumps(next(responses)), "model", {}

        spec, _, _, usage = compile_domain_spec_v2(
            "A smart lock that locks only when the door is closed", [], [], chat)
        self.assertEqual(spec.module_name, "smart_lock")
        self.assertEqual(usage["domain_spec_repair_attempts"], 1)
        self.assertIn("not anchored to the authoritative idea", captured[1][1]["content"])
        self.assertIn('"required_identity_tokens": ["closed", "door", "lock",',
                      captured[1][1]["content"])

    def test_v2_generation_repairs_ambiguous_multiple_json_fences(self):
        import json
        malformed = ('```json\n{"questions":[]}\n```\n'
                     '```json\n{"also":"wrong candidate shape"}\n```')
        responses = iter((malformed, json.dumps(self.v2_value())))
        captured = []
        def chat(messages, _model, _temperature):
            captured.append(messages)
            return next(responses), "model", {}

        spec, _, _, usage = compile_domain_spec_v2("A switch", [], [], chat)
        self.assertEqual(spec.module_name, "switch")
        self.assertEqual(usage["domain_spec_repair_attempts"], 1)
        self.assertIn("multiple JSON fences", captured[1][1]["content"])

    def test_v2_generation_exhausts_malformed_candidate_json_as_domain_error(self):
        calls = 0
        def chat(_messages, _model, _temperature):
            nonlocal calls
            calls += 1
            return "not JSON", "model", {}
        with self.assertRaises(LLMError) as raised:
            compile_domain_spec_v2("A switch", [], [], chat)
        self.assertEqual(raised.exception.code, "INVALID_DOMAIN_SPEC_V2")
        self.assertIn("schema-aware repair was rejected", str(raised.exception))
        self.assertEqual(calls, 3)

    def test_v2_generation_normalizes_only_safe_representation_drift(self):
        import json
        value = self.v2_value()
        value["module_name"] = "Smart-LockController"
        value["operations"][0]["effects"][0]["target"] = {
            "kind": "field", "name": "enabled"}
        calls = 0
        def chat(_messages, _model, _temperature):
            nonlocal calls
            calls += 1
            return json.dumps(value), "model", {}
        spec, _, _, usage = compile_domain_spec_v2("A smart lock", [], [], chat)
        self.assertEqual(calls, 1)
        self.assertEqual(spec.module_name, "smart_lock_controller")
        self.assertEqual(spec.operations[0].effects[0].target, "enabled")
        self.assertEqual(len(usage["domain_spec_normalizations"]), 2)

        ambiguous = {"kind": "field", "name": "enabled", "receiver": "other"}
        normalized, changes = _normalize_v2_syntax({
            "operations": [{"effects": [{"target": ambiguous}]}]})
        self.assertEqual(normalized["operations"][0]["effects"][0]["target"], ambiguous)
        self.assertEqual(changes, [])
        self.assertEqual(_normalize_v2_syntax([]), ([], []))
        malformed = {"operations": [None, {"effects": [None]}]}
        self.assertEqual(_normalize_v2_syntax(malformed), (malformed, []))

        wrapped, changes = _normalize_v2_syntax({"candidate": self.v2_value()})
        self.assertEqual(wrapped["domain_name"], "Switch")
        self.assertEqual(changes, [
            {"path": "$", "from": "candidate wrapper", "to": "candidate object"}])
        ambiguous_wrapper = {"candidate": self.v2_value(), "confidence": 1}
        self.assertEqual(_normalize_v2_syntax(ambiguous_wrapper),
                         (ambiguous_wrapper, []))

    def test_v2_generation_accepts_exact_candidate_wrapper_without_repair(self):
        import json
        calls = 0
        def chat(_messages, _model, _temperature):
            nonlocal calls
            calls += 1
            return json.dumps({"candidate": self.v2_value()}), "model", {}
        spec, _, _, usage = compile_domain_spec_v2("A switch", [], [], chat)
        self.assertEqual(calls, 1)
        self.assertEqual(spec.module_name, "switch")
        self.assertEqual(usage["domain_spec_normalizations"][0]["from"],
                         "candidate wrapper")

    def test_v2_generation_normalizes_exact_top_level_aliases(self):
        import json
        value = self.v2_value()
        value["name"] = value.pop("domain_name")
        value["state"] = value.pop("state_variables")
        value["invariants"] = value.pop("tlc_invariants")
        value.pop("module_name")
        calls = 0
        def chat(_messages, _model, _temperature):
            nonlocal calls
            calls += 1
            return json.dumps(value), "model", {}
        spec, _, _, usage = compile_domain_spec_v2("A switch", [], [], chat)
        self.assertEqual(calls, 1)
        self.assertEqual(spec.domain_name, "Switch")
        self.assertEqual(spec.module_name, "switch")
        paths = {change["path"] for change in usage["domain_spec_normalizations"]}
        self.assertEqual(paths, {"name", "state", "invariants", "module_name"})

        collision = {"name": "Wrong", "domain_name": "Right"}
        normalized, changes = _normalize_v2_syntax(collision)
        self.assertEqual(normalized["name"], "Wrong")
        self.assertEqual(normalized["domain_name"], "Right")
        self.assertEqual(normalized["module_name"], "right")
        self.assertNotIn("name", {change["path"] for change in changes})
        invalid_name, changes = _normalize_v2_syntax({"domain_name": "!!!"})
        self.assertNotIn("module_name", invalid_name)
        self.assertEqual(changes, [])

    def test_v2_normalizes_pascal_name_state_type_and_safety_invariant_alias(self):
        value = self.v2_value()
        value["domain_name"] = "atm_controller"
        value["state_variables"][0]["type"] = value["state_variables"][0].pop("kind")
        value["safety_invariants"] = value.pop("tlc_invariants")
        value.pop("module_name")
        normalized, changes = _normalize_v2_syntax(value)
        self.assertEqual(normalized["domain_name"], "AtmController")
        self.assertEqual(normalized["module_name"], "atm_controller")
        self.assertEqual(normalized["state_variables"][0]["kind"], "bool")
        self.assertIn("tlc_invariants", normalized)
        self.assertNotIn("safety_invariants", normalized)
        paths = {change["path"] for change in changes}
        self.assertTrue({"domain_name", "module_name", "state_variables.0.type",
                         "safety_invariants"}.issubset(paths))

        unknown = {"state_variables": [{"type": "integer", "name": "cash"}]}
        self.assertEqual(_normalize_v2_syntax(unknown), (unknown, []))
        conflicting = {"state_variables": [{"kind": "bool", "type": "int",
                                               "name": "enabled"}]}
        self.assertEqual(_normalize_v2_syntax(conflicting), (conflicting, []))

    def test_v2_normalizes_unambiguous_legacy_collection_shape(self):
        value = self.v2_value()
        value["variables"] = value.pop("state_variables")
        value["transitions"] = value.pop("operations")
        value["actors"] = ["reader_0", "reader_1", "writer"]
        value["initial_state"] = {"enabled": False}
        value["tlc_invariants"][0]["name"] = value["tlc_invariants"][0].pop("id")

        normalized, changes = _normalize_v2_syntax(value)

        self.assertEqual(normalized["actors"], 3)
        self.assertIn("state_variables", normalized)
        self.assertIn("operations", normalized)
        self.assertNotIn("initial_state", normalized)
        self.assertEqual(normalized["tlc_invariants"][0]["id"], "EnabledIsBoolean")
        paths = {change["path"] for change in changes}
        self.assertTrue({"variables", "transitions", "actors", "initial_state",
                         "tlc_invariants.0.name"}.issubset(paths))

    def test_v2_does_not_normalize_ambiguous_legacy_values(self):
        value = self.v2_value()
        value["actors"] = ["same", "same"]
        value["initial_state"] = {"enabled": True}
        value["tlc_invariants"][0]["name"] = "ConflictingName"

        normalized, changes = _normalize_v2_syntax(value)

        self.assertEqual(normalized["actors"], ["same", "same"])
        self.assertEqual(normalized["initial_state"], {"enabled": True})
        self.assertEqual(normalized["tlc_invariants"][0]["id"], "EnabledIsBoolean")
        self.assertEqual(normalized["tlc_invariants"][0]["name"], "ConflictingName")
        self.assertNotIn("actors", {change["path"] for change in changes})
        self.assertNotIn("initial_state", {change["path"] for change in changes})

    def test_v2_normalizes_unambiguous_actor_counts_and_partial_initial_map(self):
        for actors in ("3", {"count": 3}):
            value = self.v2_value()
            value["actors"] = actors
            value["state_variables"].append({
                "kind": "int", "name": "phase", "bound": [0, 2], "initial": 0})
            value["initial_state"] = {"enabled": False}

            normalized, changes = _normalize_v2_syntax(value)

            self.assertEqual(normalized["actors"], 3)
            self.assertNotIn("initial_state", normalized)
            self.assertIn("actors", {change["path"] for change in changes})

        unknown = self.v2_value()
        unknown["initial_state"] = {"missing": False}
        normalized, _ = _normalize_v2_syntax(unknown)
        self.assertIn("initial_state", normalized)

    def test_authoritative_explicit_range_accepts_contained_initial_value(self):
        questions = [
            {"id": "initial", "category": "state",
             "question": "What is the initial value?", "required": True},
            {"id": "bounds", "category": "bounds",
             "question": "What is the finite bound?", "required": True},
        ]
        _reject_initial_values_outside_answered_bounds(questions, {
            "initial": "account_balance = 4",
            "bounds": "account_balance is bounded in [0, 5]",
        })

    def test_frame_effect_repair_obligations_are_diagnostic_not_transformative(self):
        malformed = {"operations": [{
            "name": "deposit", "frame": ["account_balance", "atm_cash"],
            "effects": [{"id": "credit", "target": "account_balance",
                         "value": {"kind": "integer", "value": 1}}],
        }]}
        before = json.dumps(malformed, sort_keys=True)
        obligations = _frame_effect_repair_obligations(malformed)
        self.assertEqual(obligations[0]["operation"], "deposit")
        self.assertEqual(obligations[0]["current_effect_targets"], ["account_balance"])
        self.assertEqual(json.dumps(malformed, sort_keys=True), before)
        self.assertEqual(_frame_effect_repair_obligations([]), [])
        self.assertEqual(_frame_effect_repair_obligations({"operations": [None]}), [])

    def test_v2_wire_format_teaches_simultaneous_multi_field_effects(self):
        from pipeline.domain_generator import DOMAIN_SPEC_V2_WIRE_FORMAT
        self.assertIn('"target":"first_field"', DOMAIN_SPEC_V2_WIRE_FORMAT)
        self.assertIn('"target":"second_field"', DOMAIN_SPEC_V2_WIRE_FORMAT)
        self.assertIn('"frame":["first_field","second_field"]',
                      DOMAIN_SPEC_V2_WIRE_FORMAT)

    def test_literal_arithmetic_effects_gain_deterministic_bound_guards(self):
        value = self.v2_value()
        value["state_variables"] = [{
            "kind": "int", "name": "balance", "bound": [0, 5], "initial": 2}]
        value["operations"] = [{
            "name": "Deposit", "return_type": "void", "failure_semantics": "unavailable",
            "guards": [], "effects": [{"id": "increment", "target": "balance",
                "value": {"kind": "add", "left": {"kind": "field", "name": "balance"},
                          "right": {"kind": "integer", "value": 1}}}],
            "frame": ["balance"], "exception_type": None, "exception_trigger": None}]
        value["tlc_invariants"] = [{"id": "NonNegative", "expression": {
            "kind": "gte", "left": {"kind": "field", "name": "balance"},
            "right": {"kind": "integer", "value": 0}}}]
        completed, changes = _complete_literal_bound_guards(DomainSpecV2.model_validate(value))
        guard = completed.operations[0].guards[0]
        self.assertEqual(guard.id, "balance_within_upper_bound")
        self.assertEqual(guard.expression.kind, "lte")
        self.assertEqual(guard.expression.right.value, 4)
        self.assertEqual(len(changes), 1)
        unchanged, second_changes = _complete_literal_bound_guards(completed)
        self.assertEqual(unchanged, completed)
        self.assertEqual(second_changes, [])

        decrement = value.copy()
        decrement = json.loads(json.dumps(value))
        decrement["operations"][0]["name"] = "Withdraw"
        decrement["operations"][0]["effects"][0]["value"]["kind"] = "sub"
        decrement["operations"][0]["effects"][0]["id"] = "balance_within_lower_bound"
        lowered, lower_changes = _complete_literal_bound_guards(
            DomainSpecV2.model_validate(decrement))
        lower_guard = lowered.operations[0].guards[0]
        self.assertEqual(lower_guard.id, "balance_within_lower_bound_2")
        self.assertEqual(lower_guard.expression.kind, "gte")
        self.assertEqual(lower_guard.expression.right.value, 1)
        self.assertEqual(len(lower_changes), 1)

        unrelated = json.loads(json.dumps(value))
        unrelated["operations"][0]["effects"][0]["value"] = {
            "kind": "integer", "value": 3}
        untouched, no_changes = _complete_literal_bound_guards(
            DomainSpecV2.model_validate(unrelated))
        self.assertFalse(untouched.operations[0].guards)
        self.assertEqual(no_changes, [])

        equivalent = json.loads(json.dumps(value))
        equivalent["operations"][0]["guards"] = [{"id": "room", "expression": {
            "kind": "lt", "left": {"kind": "field", "name": "balance"},
            "right": {"kind": "integer", "value": 5}}}]
        preserved, no_changes = _complete_literal_bound_guards(
            DomainSpecV2.model_validate(equivalent))
        self.assertEqual(len(preserved.operations[0].guards), 1)
        self.assertEqual(no_changes, [])
        self.assertEqual(
            _canonical_integer_guard_tree(equivalent["operations"][0]["guards"][0]["expression"]),
            _canonical_integer_guard_tree({"kind": "lte",
                "left": {"kind": "field", "name": "balance"},
                "right": {"kind": "integer", "value": 4}}))
        nonlinear = json.loads(json.dumps(value))
        nonlinear["operations"][0]["effects"][0]["value"]["left"] = {
            "kind": "integer", "value": 1}
        untouched, no_changes = _complete_literal_bound_guards(
            DomainSpecV2.model_validate(nonlinear))
        self.assertFalse(untouched.operations[0].guards)
        self.assertEqual(no_changes, [])

    def test_exhausted_frame_effect_repair_reports_exact_surface(self):
        value = self.v2_value()
        value["state_variables"].append({
            "kind": "bool", "name": "secondary", "initial": False})
        value["operations"][0]["frame"] = ["enabled", "secondary"]
        def chat(_messages, _model, _temperature):
            return json.dumps(value), "model", {}
        with self.assertRaises(LLMError) as raised:
            compile_domain_spec_v2("A switch", [], [], chat)
        message = str(raised.exception)
        self.assertIn("frame/effect details", message)
        self.assertIn('"current_frame":["enabled","secondary"]', message)
        self.assertIn('"current_effect_targets":["enabled"]', message)

        incomplete = {"operations": [{"name": "x", "frame": "enabled", "effects": []}]}
        self.assertEqual(_frame_effect_repair_obligations(incomplete), [])

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

        atm_questions = [
            {"id": "initial", "category": "state",
             "question": "What are the initial account and ATM cash values?", "required": True},
            {"id": "bounds", "category": "bounds",
             "question": "What are the upper bounds?", "required": True},
        ]
        atm_answers = [
            {"id": "initial", "answer": "account_balance = 1000, atm_cash = 500"},
            {"id": "bounds", "answer": (
                "upper bound for account_balance is 5, and upper bound for atm_cash is 5")},
        ]
        with self.assertRaisesRegex(
                ValueError, "account_balance initial 1000 is outside 0..5"):
            compile_domain_spec_v2("An ATM", atm_questions, atm_answers, chat)
        self.assertEqual(len(captured), 2, "contradiction must fail before another LLM call")

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
        self.assertIn("initial value of every state variable", captured[0]["content"])
        self.assertIn("environment-controlled physical state", captured[0]["content"])

    def test_domain_elicitation_repairs_empty_json_response(self):
        responses = iter(("", '{"questions":[]}'))
        calls = []
        def chat(messages, _model, _temperature):
            calls.append(messages)
            return next(responses), "model", {}
        questions, _, usage = elicit_domain_questions("A smart lock", chat)
        self.assertEqual(questions, [])
        self.assertEqual(usage["elicitation_json_repair_attempts"], 1)
        self.assertEqual(len(calls), 2)

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
