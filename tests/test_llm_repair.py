import unittest

from pipeline.llm import SYSTEM, glm_repair_spec


class LlmRepairPromptTests(unittest.TestCase):
    def test_system_prompt_contains_complete_boolean_transition_example(self):
        self.assertIn("\\result <==> amount <= 9000L - \\old(balance)", SYSTEM)
        self.assertIn("!\\result ==> balance == \\old(balance)", SYSTEM)

    def test_boolean_lint_adds_targeted_contract_pattern(self):
        captured = {}

        def chat(messages, model, temperature):
            captured["prompt"] = messages[1]["content"]
            return (r'''```java
public class Account {
    //@ ensures \result;
    public boolean deposit() { return false; }
}
```
```json
{"assumptions":[],"missing_info_questions":[]}
```''', "model", {})

        glm_repair_spec("public class Account {}",
                        "[unconstrained-boolean-result] deposit", "Account", chat_fn=chat)
        self.assertIn("MANDATORY BOOLEAN-RESULT REPAIR", captured["prompt"])
        self.assertIn("insufficient funds, overflow", captured["prompt"])
        self.assertIn("!\\result ==> UNCHANGED_STATE", captured["prompt"])

    def test_unrelated_compiler_error_does_not_add_boolean_template(self):
        captured = {}

        def chat(messages, model, temperature):
            captured["prompt"] = messages[1]["content"]
            return ("```java\npublic class A {}\n```\n```json\n{}\n```", "model", {})

        glm_repair_spec("public class A {}", "missing semicolon", "A", chat_fn=chat)
        self.assertNotIn("MANDATORY BOOLEAN-RESULT REPAIR", captured["prompt"])


if __name__ == "__main__":
    unittest.main()
