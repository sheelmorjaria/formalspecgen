import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import WebSocketDisconnect

import server
from pipeline.jml_to_dafny import UnsupportedBoundary
from pipeline.schemas import RefineResult


class FakeWebSocket:
    def __init__(self, messages):
        self.messages = list(messages)
        self.sent = []
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def receive_json(self):
        if not self.messages:
            raise WebSocketDisconnect()
        return self.messages.pop(0)

    async def send_json(self, value):
        self.sent.append(value)


async def immediate(function, *args, **kwargs):
    return function(*args, **kwargs)


class ServerWebSocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_event_runner_tolerates_idle_worker_interval(self):
        socket = FakeWebSocket([])
        class FakeTask:
            checks = 0

            def done(self):
                self.checks += 1
                return self.checks > 1

            def __await__(self):
                async def result():
                    return "done"
                return result().__await__()

        class FakeQueue:
            async def get(self):
                return None

            def put_nowait(self, _event):
                pass

            def empty(self):
                return True

        def fake_create_task(coroutine):
            coroutine.close()
            return FakeTask()

        async def timeout(awaitable, **_kwargs):
            awaitable.close()
            raise server.asyncio.TimeoutError

        with patch.object(server.asyncio, "Queue", return_value=FakeQueue()), \
             patch.object(server.asyncio, "create_task", side_effect=fake_create_task), \
             patch.object(server.asyncio, "wait_for", side_effect=timeout):
            result = await server._run_with_events(socket, lambda on_event=None: "unused")
        self.assertEqual(result, "done")
        self.assertEqual(socket.sent, [])

    async def test_capabilities_lints_discovery_and_unknown_action(self):
        socket = FakeWebSocket([
            {"action": "capabilities"},
            {"action": "lint", "code": "public class C {}"},
            {"action": "rust_lint", "code": "fn f() {}"},
            {"action": "discover_passes", "code": "1 << shift"},
            {"action": "not_a_real_action"},
        ])
        with patch.object(server, "lint_spec", return_value=[{"code": "jml"}]), \
             patch.object(server, "lint_rust", return_value=[{"code": "rust"}]), \
             patch.object(server, "discover_passes", return_value=[{"name": "bounds"}]):
            await server.verify_socket(socket)
        self.assertTrue(socket.accepted)
        self.assertEqual([item["type"] for item in socket.sent], [
            "capabilities", "lint_result", "rust_lint_result", "pass_suggestions", "error"])
        self.assertIn("bank_account", socket.sent[0]["tla_domains"])
        self.assertEqual(socket.sent[-1]["message"], "unknown action: not_a_real_action")

    async def test_assurance_plan_and_verdict_are_structured(self):
        socket = FakeWebSocket([
            {"action": "assurance_plan", "assurance_level": "standard"},
            {"action": "assurance_verdict", "assurance_level": "lightweight",
             "gate_statuses": {"javac": "PASS", "spec_lint": "PASS",
                               "rac_junit": "TESTS_PASSED"}},
        ])
        await server.verify_socket(socket)
        self.assertEqual(socket.sent[0]["type"], "assurance_plan")
        self.assertTrue(any(gate["name"] == "openjml_esc" and not gate["required"]
                            for gate in socket.sent[0]["gates"]))
        self.assertEqual(socket.sent[1]["final_status"], "COMPILED_LINTED")
        self.assertEqual(socket.sent[1]["final_claim_type"], "RUNTIME_SAMPLE")

    async def test_native_implementation_synthesis_action(self):
        socket = FakeWebSocket([{
            "action": "implementation_synthesize", "code": "public class C {}",
            "provider": "ollama", "max_attempts": 2,
        }])
        native = {"final_status": "VERIFIED", "implementation_code": "public class C {}",
                  "native_synthesis": True, "external_handoff_used": False}
        with patch.object(server.asyncio, "to_thread", new=immediate), \
             patch.object(server, "synthesize_implementation", return_value=native) as synthesize:
            await server.verify_socket(socket)
        self.assertEqual(socket.sent[-1]["type"], "implementation_result")
        self.assertEqual(socket.sent[-1]["status"], "VERIFIED")
        synthesize.assert_called_once()

    async def test_required_input_and_missing_session_failures(self):
        socket = FakeWebSocket([
            {"action": "elicit_ambiguities", "nl_text": ""},
            {"action": "draft_spec", "nl_text": ""},
            {"action": "draft_rust", "nl_text": ""},
            {"action": "verify", "code": ""},
            {"action": "refine", "code": "", "instruction": ""},
            {"action": "implementation_handoff", "code": ""},
            {"action": "architecture_lint"},
            {"action": "architecture_scaffold"},
            {"action": "composition_check"},
            {"action": "architecture_adr"},
            {"action": "architecture_rac"},
            {"action": "refactor_impact"},
        ])
        await server.verify_socket(socket)
        self.assertEqual(len(socket.sent), 12)
        self.assertTrue(all(item["type"] == "error" for item in socket.sent))
        self.assertIn("trusted JML scaffold", socket.sent[5]["message"])
        self.assertEqual(socket.sent[-1]["message"], "no architecture is available")

    async def test_mocked_worker_actions_emit_structured_terminal_results(self):
        domain_spec = SimpleNamespace(model_dump=lambda mode=None: {
            "domain_name": "Counter", "module_name": "counter"})
        dafny = SimpleNamespace(
            status="VERIFIED", exit_code=0, output="ok",
            translation=SimpleNamespace(boundary="recursive_helper", dafny_code="function f(): int",
                                        rewrites=["pure helper"]))
        socket = FakeWebSocket([
            {"action": "elicit_ambiguities", "nl_text": "counter"},
            {"action": "elicit_domain_questions", "idea": "counter"},
            {"action": "compile_domain_spec", "idea": "counter"},
            {"action": "augment_requirements", "nl_text": "counter"},
            {"action": "postprocess_preview", "code": "C"},
            {"action": "route_backend", "code": "C"},
            {"action": "translate_dafny", "code": "C"},
            {"action": "rust_postprocess_preview", "code": "fn f(){}"},
            {"action": "rust_check", "code": "fn f(){}"},
            {"action": "rust_verify", "code": "fn f(){}"},
            {"action": "suggest_invariant", "code": "C", "loop_line": "while"},
            {"action": "rac_evidence", "code": "C"},
            {"action": "translate_tla", "code": "C"},
            {"action": "implementation_handoff", "code": "public class C {}"},
            {"action": "explain_vc", "category": "Overflow", "detail": "sum"},
        ])
        patches = [
            patch.object(server.asyncio, "to_thread", new=immediate),
            patch.object(server, "extract_ambiguities", return_value=([], "m", {})),
            patch.object(server, "elicit_domain_questions", return_value=([], "m", {})),
            patch.object(server, "compile_domain_spec", return_value=(domain_spec, "yaml", "m", {})),
            patch.object(server, "scaffold_sources", return_value={"x.py": "source"}),
            patch.object(server, "registration_lines", return_value={"import": "i", "plugin": "p"}),
            patch.object(server, "augment_spec", return_value="enriched"),
            patch.object(server, "apply_passes", return_value={"code": "P"}),
            patch.object(server, "route_backend", return_value={"backend": "jml"}),
            patch.object(server, "translate_and_verify", return_value=dafny),
            patch.object(server, "apply_rust_passes", return_value={"code": "R"}),
            patch.object(server, "check_rust_syntax", return_value={"status": "CHECKED"}),
            patch.object(server, "verify_prusti", return_value={"status": "VERIFIED", "vcs": []}),
            patch.object(server, "suggest_loop_invariant", return_value=("//@ loop_invariant true;", "m", {})),
            patch.object(server, "collect_rac_evidence", return_value={"status": "NO_RUNTIME_FAILURE_FOUND"}),
            patch.object(server, "generate_and_check_tla", return_value={"status": "VERIFIED", "claim": "BOUNDED_ARCHITECTURE_EVIDENCE"}),
            patch.object(server, "handoff", return_value={"ok": True, "dd_verdict": {"final_status": "VERIFIED"}}),
            patch.object(server, "explain_vc_with_llm", return_value=("explanation", "m", {})),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        await server.verify_socket(socket)
        types = [item["type"] for item in socket.sent]
        for expected in ("ambiguities", "domain_questions", "domain_spec_result",
                         "requirements_augmented", "postprocess_result", "backend_route",
                         "dafny_result", "rust_postprocess_result", "rust_check_result",
                         "rust_verify_result", "invariant_suggestion", "rac_result", "tla_result",
                         "implementation_result", "llm_vc_explanation"):
            self.assertIn(expected, types)
        implementation = next(item for item in socket.sent if item["type"] == "implementation_result")
        self.assertEqual(implementation["status"], "VERIFIED")

    async def test_protocol_exception_is_returned_as_error_event(self):
        socket = FakeWebSocket([{"action": "elicit_domain_questions", "idea": "bad"}])
        with patch.object(server.asyncio, "to_thread", new=immediate), \
             patch.object(server, "elicit_domain_questions", side_effect=ValueError("invalid domain")):
            await server.verify_socket(socket)
        self.assertEqual(socket.sent[-1], {"type": "error", "message": "invalid domain"})

    async def test_refinement_prusti_diagnostic_and_design_without_artifact(self):
        socket = FakeWebSocket([
            {"action": "refine", "code": "public class C {}", "instruction": "add a bound"},
            {"action": "rust_verify", "code": "fn f() {}"},
            {"action": "architecture_design", "requirement": "incomplete design"},
        ])
        refinement = RefineResult(
            instruction="add a bound", new_stub="public class C {}", check_ok=True,
            status="VALIDATED_CANDIDATE")
        with patch.object(server.asyncio, "to_thread", new=immediate), \
             patch.object(server, "refine", return_value=refinement), \
             patch.object(server, "verify_prusti", return_value={
                 "status": "VERIFY_FAILED", "vcs": [{"category": "Postcondition",
                     "line": 2, "detail": "not established", "raw": "raw"}]}), \
             patch.object(server, "explain_vc", return_value={"explanation": "explain", "advice": "fix"}), \
             patch.object(server, "design_system", return_value={"status": "PARSE_ERROR"}):
            await server.verify_socket(socket)
        types = [item["type"] for item in socket.sent]
        self.assertIn("refine_result", types)
        self.assertIn("vc_failure", types)
        self.assertIn("rust_verify_result", types)
        self.assertIn("architecture_result", types)

    async def test_architecture_session_workflow_and_rust_diagnostics(self):
        architecture = {
            "name": "Bank", "components": [], "dependencies": [], "use_cases": [],
            "data_flows": [], "invariants": []}
        socket = FakeWebSocket([
            {"action": "draft_rust", "nl_text": "counter"},
            {"action": "architecture_design", "requirement": "bank"},
            {"action": "architecture_lint"},
            {"action": "architecture_scaffold"},
            {"action": "composition_check"},
            {"action": "architecture_adr", "number": 4},
            {"action": "architecture_rac"},
            {"action": "refactor_impact", "before_files": {}, "after_files": {}},
            {"action": "translate_dafny", "code": "unsupported"},
        ])
        parsed = SimpleNamespace(to_dict=lambda: architecture)
        patches = [
            patch.object(server.asyncio, "to_thread", new=immediate),
            patch.object(server, "draft_rust", return_value={
                "status": "VERIFY_FAILED", "warnings": [{"code": "lint"}],
                "proof": {"vcs": [{"category": "Postcondition", "line": 3,
                                     "detail": "not proved"}]}}),
            patch.object(server, "design_system", return_value={
                "status": "VERIFIED", "architecture": architecture}),
            patch.object(server, "parse_architecture", return_value=parsed),
            patch.object(server, "lint_architecture", return_value=[]),
            patch.object(server, "scaffold_interfaces", return_value={
                "status": "VERIFIED", "files": {"BankOrchestrator.java": "class B {}"}}),
            patch.object(server, "check_composition", return_value=[]),
            patch.object(server, "generate_adr", return_value="# ADR 4"),
            patch.object(server, "collect_integration_evidence", return_value={"status": "TESTS_PASSED"}),
            patch.object(server, "analyze_refactor", return_value={"status": "UNCHANGED"}),
            patch.object(server, "translate_and_verify", side_effect=UnsupportedBoundary("unknown")),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        await server.verify_socket(socket)
        types = [item["type"] for item in socket.sent]
        for expected in ("rust_draft_result", "architecture_result",
                         "architecture_lint_result", "architecture_scaffold_result",
                         "composition_result", "architecture_adr_result",
                         "architecture_rac_result", "refactor_impact_result", "dafny_result"):
            self.assertIn(expected, types)
        rust_result = next(item for item in socket.sent if item["type"] == "rust_draft_result")
        self.assertEqual(len(rust_result["rust_warnings"]), 2)
        dafny_result = next(item for item in socket.sent if item["type"] == "dafny_result")
        self.assertEqual(dafny_result["status"], "UNSUPPORTED_BOUNDARY")

    async def test_verify_and_draft_actions_delegate_to_event_runner(self):
        socket = FakeWebSocket([
            {"action": "draft_spec", "nl_text": "counter"},
            {"action": "verify", "code": "class C {}", "mode": "check"},
            {"action": "verify", "code": "class C {}", "mode": "esc"},
            {"action": "verify", "code": "class C {}", "mode": "auto"},
        ])
        calls = []

        async def runner(websocket, function, *args, **kwargs):
            calls.append((function, args, kwargs))
            await websocket.send_json({"type": "delegated"})

        with patch.object(server, "_run_with_events", side_effect=runner):
            await server.verify_socket(socket)
        self.assertEqual(len(calls), 4)
        self.assertIs(calls[0][0], server.orchestrator.run)
        self.assertEqual(calls[1][1][-1], "check")
        self.assertEqual(calls[2][1][-1], "esc")
        self.assertIs(calls[3][0], server._verify_source_auto)

    async def test_kani_action_returns_bounded_evidence(self):
        socket = FakeWebSocket([
            {"action": "kani_verify", "code": "#[kani::proof] fn proof() {}"},
            {"action": "draft_acsl", "nl_text": "increment", "provider": "ollama"},
            {"action": "framac_verify", "code": "/*@ assigns \\nothing; */ int f(void){return 0;}"},
        ])
        with patch.object(server.asyncio, "to_thread", new=immediate), \
             patch.object(server, "verify_kani", return_value={
                 "status": "VERIFIED", "claim": "BOUNDED_RUST_EVIDENCE",
                 "bounded": True, "harnesses": ["proof"]}), \
             patch.object(server, "draft_acsl", return_value={"status": "DRAFTED", "code": "int f(void);"}), \
             patch.object(server, "verify_framac", return_value={"status": "VERIFIED", "claim": "DEDUCTIVE_PROOF"}):
            await server.verify_socket(socket)
        result = next(item for item in socket.sent if item["type"] == "kani_result")
        self.assertEqual(result["claim"], "BOUNDED_RUST_EVIDENCE")
        self.assertTrue(any(item["type"] == "acsl_draft_result" for item in socket.sent))
        self.assertTrue(any(item["type"] == "framac_result" for item in socket.sent))


if __name__ == "__main__":
    unittest.main()
