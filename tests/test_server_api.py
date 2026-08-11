import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from fastapi.responses import HTMLResponse

import server


class ServerApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async def immediate(function, *args, **kwargs):
            return function(*args, **kwargs)
        self.blocking = patch.object(server, "_run_blocking", side_effect=immediate)
        self.blocking.start()

    async def asyncTearDown(self):
        self.blocking.stop()

    async def request(self, method, path, **kwargs):
        transport = httpx.ASGITransport(app=server.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.request(method, path, **kwargs)

    async def test_index_serves_frontend(self):
        with patch.object(server, "FileResponse",
                          return_value=HTMLResponse("<html>FormalSpecGen</html>")):
            response = await self.request("GET", "/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])

    async def test_generate_spec_rejects_empty_requirement(self):
        response = await self.request("POST", "/generate_spec", json={"nl": "   "})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "nl is empty")

    async def test_generate_spec_serializes_orchestrator_result(self):
        source = "public class Counter { //@ invariant true;\n }"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Counter.java"
            path.write_text(source, encoding="utf-8")
            result = SimpleNamespace(
                stub_path=str(path), final_status="VERIFIED", stop_reason="check clean",
                assumptions=["bounded"], missing_info=[], attempts=[SimpleNamespace(
                    n=1, status="VERIFIED", exit_code=0, vcs=[], note="sample")],
                model="mock-model", duration_s=0.04,
                tokens={"input": 1, "output": 2, "total": 3})
            with patch.object(server.orchestrator, "run", return_value=result) as run:
                response = await self.request("POST", "/generate_spec", json={
                    "nl": "A bounded counter", "provider": "ollama",
                    "fallback_provider": "openai"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "VERIFIED")
        self.assertEqual(response.json()["java_stub"], source)
        run.assert_called_once_with("A bounded counter", provider="ollama",
                                    fallback_provider="openai")

    async def test_generate_spec_surfaces_pipeline_error(self):
        with patch.object(server.orchestrator, "run", side_effect=RuntimeError("offline")):
            response = await self.request("POST", "/generate_spec", json={"nl": "counter"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"error": "offline"})

    async def test_validate_reports_success_and_diagnostics(self):
        source = "public class Counter {}"
        with patch.object(server, "verify", return_value=(0, "checked")) as verify:
            response = await self.request("POST", "/validate", json={"java_stub": source})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "VERIFIED")
        self.assertEqual(response.json()["errors"], [])
        self.assertTrue(verify.call_args.args[0].name.endswith("Counter.java"))
        self.assertEqual(verify.call_args.kwargs["mode"], "check")

    async def test_validate_rejects_empty_source(self):
        response = await self.request("POST", "/validate", json={"java_stub": ""})
        self.assertEqual(response.status_code, 400)

    async def test_refine_serializes_preview_without_applying_it(self):
        refined = SimpleNamespace(
            new_stub="public class C {}", check_ok=True, check_errors=[], diff="diff",
            conflicts=[], assumptions=[], missing_info=[], model="mock", error=None,
            duration_s=0.1)
        with patch.object(server, "refine", return_value=refined) as refine:
            response = await self.request("POST", "/refine", json={
                "current_stub": "public class C{}", "instruction": "format",
                "locked_clauses": ["ensures true"], "nl": "C"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["check_ok"])
        refine.assert_called_once_with("public class C{}", "format", ["ensures true"], "C")

    async def test_refine_rejects_missing_instruction(self):
        response = await self.request("POST", "/refine", json={
            "current_stub": "public class C{}", "instruction": ""})
        self.assertEqual(response.status_code, 400)

    async def test_refine_surfaces_worker_error(self):
        with patch.object(server, "refine", side_effect=RuntimeError("repair unavailable")):
            response = await self.request("POST", "/refine", json={
                "current_stub": "public class C{}", "instruction": "repair"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"], "repair unavailable")

    async def test_handoff_derives_intent_and_returns_result(self):
        source = "public class C {}"
        with patch.object(server, "discover_passes", return_value=[{"name": "inject_pure"}]), \
             patch.object(server, "route_backend", return_value={"backend": "jml"}), \
             patch.object(server, "handoff", return_value={"ok": True}) as handoff:
            response = await self.request("POST", "/handoff", json={"java_stub": source, "run": False})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})
        handoff.assert_called_once_with(source, run_dd=False,
                                        expected_passes=["inject_pure"], backend="jml")

    async def test_native_implementation_endpoint_and_failures(self):
        source = "public class C {}"
        native = {"final_status": "VERIFIED", "native_synthesis": True}
        with patch.object(server, "synthesize_implementation", return_value=native) as synthesize:
            response = await self.request("POST", "/implement", json={
                "java_stub": source, "provider": "ollama", "max_attempts": 2,
                "accepted_passes": ["inject_pure"]})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["native_synthesis"])
        self.assertEqual(synthesize.call_args.args[0], source)
        self.assertEqual(synthesize.call_args.args[1], "ollama")

        response = await self.request("POST", "/implement", json={"java_stub": ""})
        self.assertEqual(response.status_code, 400)
        with patch.object(server, "synthesize_implementation", side_effect=RuntimeError("offline")):
            response = await self.request("POST", "/implement", json={"java_stub": source})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"], "offline")

    async def test_handoff_rejects_empty_source(self):
        response = await self.request("POST", "/handoff", json={"java_stub": ""})
        self.assertEqual(response.status_code, 400)

    async def test_handoff_explicit_intent_and_worker_error(self):
        source = "public class C {}"
        with patch.object(server, "handoff", return_value={"ok": True}) as handoff:
            response = await self.request("POST", "/handoff", json={
                "java_stub": source, "expected_passes": ["inject_pure"],
                "backend": "dafny", "run": True})
        self.assertEqual(response.status_code, 200)
        handoff.assert_called_once_with(source, run_dd=True,
                                        expected_passes=["inject_pure"], backend="dafny")
        with patch.object(server, "handoff", side_effect=RuntimeError("DD failed")):
            response = await self.request("POST", "/handoff", json={
                "java_stub": source, "expected_passes": [], "backend": "jml"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"], "DD failed")


if __name__ == "__main__":
    unittest.main()
