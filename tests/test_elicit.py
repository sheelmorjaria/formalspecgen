import unittest

from pipeline.elicit import augment_spec, extract_ambiguities, normalize_questions
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
        def chat(_messages, _model, _temperature):
            return "not json", "test-model", {}

        with self.assertRaises(LLMError) as raised:
            extract_ambiguities("A counter", chat)
        self.assertEqual(raised.exception.code, "INVALID_ELICITATION_JSON")

    def test_caps_questions(self):
        questions = normalize_questions([{"question": f"Question {index}"}
                                         for index in range(20)])
        self.assertEqual(len(questions), 8)


if __name__ == "__main__":
    unittest.main()
