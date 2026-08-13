import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from pipeline import llm


class Response:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.value).encode("utf-8")


def completion(content="answer", *, model="served-model", finish="stop", usage=None):
    return Response({"choices": [{"message": {"content": content}, "finish_reason": finish}],
                     "model": model, "usage": usage or {"total_tokens": 3}})


class LlmTransportTests(unittest.TestCase):
    def test_post_chat_builds_openai_compatible_request(self):
        with patch.object(llm.urllib.request, "urlopen", return_value=completion()) as opened:
            content, model, usage = llm._post_chat(
                "https://provider/v1", "secret", [{"role": "user", "content": "hello"}],
                "requested", 0.25, 17, {"thinking": {"type": "disabled"}})
        self.assertEqual((content, model, usage["total_tokens"]), ("answer", "served-model", 3))
        request = opened.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(request.full_url, "https://provider/v1/chat/completions")
        self.assertEqual(body["max_tokens"], llm.config.LLM_MAX_TOKENS)
        self.assertEqual(body["thinking"], {"type": "disabled"})
        self.assertEqual(request.headers["Authorization"], "Bearer secret")
        self.assertEqual(opened.call_args.kwargs["timeout"], 17)

    def test_empty_content_is_retried_then_succeeds(self):
        empty = completion("", finish="length")
        with patch.object(llm.urllib.request, "urlopen",
                          side_effect=[empty, completion("recovered")]) as opened:
            value = llm._post_chat("http://local", "k", [], "m", 0, 1)
        self.assertEqual(value[0], "recovered")
        self.assertEqual(opened.call_count, 2)

    def test_four_empty_responses_fail_closed(self):
        with patch.object(llm.urllib.request, "urlopen",
                          side_effect=[completion("", finish="length") for _ in range(4)]):
            with self.assertRaises(llm.LLMError) as raised:
                llm._post_chat("http://local", "k", [], "m", 0, 1)
        self.assertEqual(raised.exception.code, "EMPTY_CONTENT")
        self.assertIn("finish_reason='length'", raised.exception.message)
        self.assertIsNone(raised.exception.http_status)

    def test_http_json_error_preserves_provider_code_and_status(self):
        error = urllib.error.HTTPError(
            "https://provider", 429, "Too Many Requests", {},
            io.BytesIO(b'{"error":{"code":"rate_limit","message":"slow down"}}'))
        with patch.object(llm.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(llm.LLMError) as raised:
                llm._post_chat("https://provider", "k", [], "m", 0, 1)
        self.assertEqual(raised.exception.code, "rate_limit")
        self.assertEqual(raised.exception.message, "slow down")
        self.assertEqual(raised.exception.http_status, 429)

    def test_unparseable_http_error_uses_status_code(self):
        error = urllib.error.HTTPError(
            "https://provider", 502, "Bad Gateway", {}, io.BytesIO(b"not-json"))
        with patch.object(llm.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(llm.LLMError) as raised:
                llm._post_chat("https://provider", "k", [], "m", 0, 1)
        self.assertEqual(raised.exception.code, "502")
        self.assertEqual(raised.exception.http_status, 502)

    def test_network_errors_are_normalized(self):
        for error in (urllib.error.URLError("offline"), TimeoutError("late"), OSError("reset")):
            with self.subTest(error=type(error).__name__), \
                 patch.object(llm.urllib.request, "urlopen", side_effect=error):
                with self.assertRaises(llm.LLMError) as raised:
                    llm._post_chat("https://provider", "k", [], "m", 0, 9)
                self.assertEqual(raised.exception.code, "NETWORK")
                self.assertIn("after 9s", raised.exception.message)

    def test_provider_wrappers_select_models_and_glm_thinking(self):
        with patch.object(llm, "_post_chat", return_value=("x", "m", {})) as post, \
             patch.object(llm.config, "GLM_THINKING", "disabled"):
            llm._glm_chat([], None, 0.1)
            self.assertEqual(post.call_args.args[-1], {"thinking": {"type": "disabled"}})
        with patch.object(llm, "_post_chat", return_value=("x", "m", {})) as post, \
             patch.object(llm.config, "GLM_THINKING", "enabled"):
            llm._glm_chat([], "custom", 0.1)
            self.assertIsNone(post.call_args.args[-1])
            self.assertEqual(post.call_args.args[3], "custom")
        with patch.object(llm, "_post_chat", return_value=("x", "m", {})) as post:
            llm._openai_chat([], None, 0)
            self.assertEqual(post.call_args.args[3], llm.config.OPENAI_MODEL)
            llm._ollama_chat([], None, 0)
            self.assertEqual(post.call_args.args[3], llm.config.OLLAMA_MODEL)

    def test_provider_router_is_explicit_and_defaults_to_glm(self):
        self.assertIs(llm._chat_fn("openai"), llm._openai_chat)
        self.assertIs(llm._chat_fn("ollama"), llm._ollama_chat)
        self.assertIs(llm._chat_fn("unknown"), llm._glm_chat)

    def test_ollama_structured_router_sends_json_schema(self):
        schema = {"type": "object", "required": ["schema_version"]}
        chat = llm._chat_fn("ollama", json_schema=schema)
        with patch.object(llm, "_post_chat", return_value=("{}", "m", {})) as post:
            self.assertEqual(chat([], None, 0), ("{}", "m", {}))
        extra = post.call_args.args[-1]
        self.assertEqual(extra["response_format"]["type"], "json_schema")
        self.assertTrue(extra["response_format"]["json_schema"]["strict"])
        self.assertEqual(extra["response_format"]["json_schema"]["schema"], schema)
        self.assertFalse(extra["think"])
        nested = chat.structured_for({"type": "string"}, "fragment")
        with patch.object(llm, "_post_chat", return_value=("x", "m", {})) as post:
            nested([], None, 0)
        self.assertEqual(
            post.call_args.args[-1]["response_format"]["json_schema"]["name"], "fragment")


class LlmAdapterTests(unittest.TestCase):
    def test_strip_fence_and_balanced_json_parser(self):
        self.assertEqual(llm.strip_fence("```java\nclass A {}\n```"), "class A {}\n")
        self.assertEqual(llm.strip_fence("plain"), "plain")
        value = llm._first_json_object('prefix {"text":"} escaped \\\" ok","x":1} suffix')
        self.assertEqual(value["x"], 1)
        self.assertEqual(llm._first_json_object("no object"), {})
        self.assertEqual(llm._first_json_object("{broken}"), {})

    def test_parse_draft_handles_fenced_and_unfenced_metadata(self):
        fenced = llm._parse_draft(
            '```java\npublic class A {}\n```\n```json\n'
            '{"assumptions":["a"],"missing_info_questions":["q"]}\n```')
        self.assertEqual(fenced.stub, "public class A {}")
        self.assertEqual(fenced.assumptions, ["a"])
        self.assertEqual(fenced.missing_info, ["q"])
        plain = llm._parse_draft('public class B {}\n{"assumptions":["b"]}')
        self.assertIn("public class B", plain.stub)
        self.assertEqual(plain.assumptions, ["b"])

    def test_generate_spec_separates_authoritative_clarifications(self):
        captured = {}
        def chat(messages, model, temperature):
            captured["messages"] = messages
            return "```java\npublic class C {}\n```\n```json\n{}\n```", "m", {}
        llm.glm_generate_spec(
            "Original\nClarifications (human-provided and authoritative):\nBound is 4",
            chat_fn=chat)
        prompt = captured["messages"][1]["content"]
        self.assertIn("Original requirement:\nOriginal", prompt)
        self.assertIn("resolve conflicts in their favor", prompt)

    def test_generate_spec_without_clarifications_and_refine_context(self):
        prompts = []
        def chat(messages, model, temperature):
            prompts.append(messages[1]["content"])
            return "```java\npublic class C {}\n```\n```json\n{}\n```", "m", {}
        llm.glm_generate_spec("Simple", chat_fn=chat)
        llm.glm_refine("public class C {}", "add bound", ["ensures true"],
                       nl="Simple", chat_fn=chat)
        self.assertIn("Original requirement:\nSimple", prompts[0])
        self.assertIn("LOCKED clauses", prompts[1])
        self.assertIn("ensures true", prompts[1])

    def test_invariant_suggestion_filters_output_and_rejects_invalid(self):
        def valid(*_args):
            return "prose\n//@ loop_invariant 0 <= i;\n//@ decreases n - i;", "m", {}
        suggestion, _, _ = llm.suggest_loop_invariant("while", "while (i<n)", chat_fn=valid)
        self.assertNotIn("prose", suggestion)
        self.assertIn("decreases", suggestion)
        def invalid(*_args):
            return "//@ decreases n;", "m", {}
        with self.assertRaisesRegex(llm.LLMError, "loop invariant"):
            llm.suggest_loop_invariant("while", "while (true)", chat_fn=invalid)

    def test_rac_and_vc_adapters_strip_fences(self):
        def chat(*_args):
            return "```java\npublic class TestC {}\n```", "m", {"total_tokens": 1}
        code, _, _ = llm.generate_rac_tests("class C{}", "C", "overflow", chat_fn=chat)
        self.assertEqual(code, "public class TestC {}")
        explanation, _, _ = llm.explain_vc_with_llm("Overflow", "sum", chat_fn=chat)
        self.assertEqual(explanation, "public class TestC {}")

    def test_judge_handles_empty_error_invalid_score_and_success(self):
        self.assertEqual(llm.glm_judge("g", "", "n")["verdict"], "wrong")
        with patch.object(llm, "_glm_chat", side_effect=llm.LLMError("NETWORK", "down")):
            failed = llm.glm_judge("g", "candidate", "n")
        self.assertEqual(failed["verdict"], "error")
        with patch.object(llm, "_glm_chat", return_value=(
                '```json\n{"score":"bad","verdict":"partial","missing":["x"]}\n```', "m", {})):
            invalid = llm.glm_judge("g", "candidate", "n")
        self.assertEqual(invalid["score"], 0.0)
        with patch.object(llm, "_glm_chat", return_value=(
                '{"score":0.75,"verdict":"partial","extra_or_wrong":["y"]}', "m", {})):
            judged = llm.glm_judge("g", "candidate", "n")
        self.assertEqual(judged["score"], 0.75)
        self.assertEqual(judged["extra_or_wrong"], ["y"])


if __name__ == "__main__":
    unittest.main()
