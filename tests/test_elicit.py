import unittest

from pipeline.elicit import _extract_json, augment_spec, extract_ambiguities, normalize_questions
from pipeline.llm import LLMError


class ElicitationTests(unittest.TestCase):
    def test_extracts_and_normalizes_model_questions(self):
        def chat(messages, model, temperature):
            self.assertIn("Requirement:\nA counter", messages[1]["content"])
            self.assertEqual(temperature, 0.0)
            return ('```json\n{"questions":['
                    '{"id":"balance limit","category":"bounds","question":"Maximum?"},'
                    '{"id":"duplicate","category":"bounds","question":"Maximum?"}]}```',
                    "test-model", {"total_tokens": 12})

        questions, model, usage = extract_ambiguities("A counter", chat)
        self.assertEqual(questions, [{"id": "balancelimit", "category": "bounds",
                                      "question": "Maximum?", "required": True}])
        self.assertEqual(model, "test-model")
        self.assertEqual(usage["total_tokens"], 12)

    def test_augment_marks_human_answers_authoritative(self):
        questions = [{"id": "q1", "category": "failure", "question": "On failure?",
                      "required": True}]
        enriched = augment_spec("Withdraw funds.", questions,
                                [{"id": "q1", "answer": "Return false."}])
        self.assertIn("Clarifications (human-provided and authoritative):", enriched)
        self.assertIn("Q: On failure?\n  A: Return false.", enriched)

    def test_required_answer_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "required clarification unanswered"):
            augment_spec("Withdraw funds.",
                         [{"id": "q1", "question": "On failure?", "required": True}], [])

    def test_invalid_json_fails_closed(self):
        calls = 0
        def chat(_messages, _model, _temperature):
            nonlocal calls
            calls += 1
            return "not json", "test-model", {}

        with self.assertRaises(LLMError) as raised:
            extract_ambiguities("A counter", chat)
        self.assertEqual(raised.exception.code, "INVALID_ELICITATION_JSON")
        self.assertEqual(calls, 3)

    def test_invalid_question_json_is_repaired_with_bounded_retry(self):
        responses = iter(("", '{"questions":[]}'))
        captured = []
        def chat(messages, _model, _temperature):
            captured.append(messages)
            return next(responses), "test-model", {"total_tokens": 2}

        questions, model, usage = extract_ambiguities("A counter", chat)
        self.assertEqual(questions, [])
        self.assertEqual(model, "test-model")
        self.assertEqual(usage["elicitation_json_repair_attempts"], 1)
        self.assertIn("Return the corrected JSON object only", captured[1][1]["content"])

    def test_accepts_one_json_value_with_surrounding_model_commentary(self):
        value = _extract_json(
            'Here is the ambiguity analysis:\n{"questions":[]}\nNo further questions.')
        self.assertEqual(value, {"questions": []})
        self.assertEqual(_extract_json(
            '{"questions":[]}\nCommentary containing {not another JSON value}.'),
            {"questions": []})

    def test_malformed_object_fragment_is_not_accepted_as_partial_json(self):
        with self.assertRaises(LLMError):
            _extract_json("Commentary followed by {not valid JSON}")

    def test_rejects_multiple_json_values_or_fences_as_ambiguous(self):
        for response in (
                '{"questions":[]}\n{"questions":[{"question":"Again?"}]}',
                '```json\n{"questions":[]}\n```\n```json\n{"questions":[]}\n```'):
            with self.subTest(response=response), self.assertRaises(LLMError) as raised:
                _extract_json(response)
            self.assertEqual(raised.exception.code, "INVALID_ELICITATION_JSON")

    def test_caps_questions(self):
        questions = normalize_questions([{"question": f"Question {index}"}
                                         for index in range(20)])
        self.assertEqual(len(questions), 8)


if __name__ == "__main__":
    unittest.main()
