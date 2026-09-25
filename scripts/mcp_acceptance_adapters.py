# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Reviewed real-transport fixtures for completed MCP workflows."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import sys
import tempfile
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

import mcp_server


def _sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@contextmanager
def _fixture_provider() -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length) or b"{}")
            content = json.dumps({
                "overview": "Fixture provider overview.",
                "invariant_prose": {},
            })
            response = json.dumps({
                "model": request.get("model", "fsg-doc-fixture"),
                "choices": [{
                    "message": {"content": content},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/v1"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


async def _call_tool(
        workspace: Path, tool_name: str, calls: list[dict],
        *, environment: dict[str, str] | None = None,
        timeout_s: float = 45) -> tuple[object, object, dict, list[dict]]:
    child_environment = dict(os.environ)
    child_environment.update(environment or {})
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(mcp_server.__file__).resolve())],
        cwd=str(workspace), env=child_environment)
    with anyio.fail_after(timeout_s):
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                tools = await session.list_tools()
                tool = next(item for item in tools.tools if item.name == tool_name)
                results = []
                for arguments in calls:
                    response = await session.call_tool(tool_name, arguments)
                    if response.isError or not isinstance(
                            response.structuredContent, dict):
                        raise RuntimeError(f"{tool_name} MCP transport call failed")
                    results.append(response.structuredContent)
    return initialized, tools, tool.inputSchema, results


async def _inspect_observation() -> dict:
    with tempfile.TemporaryDirectory(prefix="formalspecgen-mcp-transport-") as directory:
        workspace = Path(directory)
        (workspace / "Probe.java").write_text(
            "public class Probe { public int value() { return 1; } }\n",
            encoding="utf-8")
        initialized, tools, schema, results = await _call_tool(
            workspace, "inspect_code", [{"source": "Probe.java"}])
    result = results[0]
    semantic_result = {
        key: result.get(key) for key in (
            "status", "claim", "scope", "parser_mode", "source_sha256",
            "class", "metrics", "findings")}
    return _observation(initialized, tools, schema, semantic_result, result)


async def _document_observation() -> dict:
    source = """public class Inventory {
    private int stock = 5;
    public void reserve() { if (stock > 0) { stock = stock - 1; } }
    public void restock() { if (stock < 5) { stock = stock + 1; } }
}
"""
    with tempfile.TemporaryDirectory(prefix="formalspecgen-mcp-doc-transport-") as directory:
        workspace = Path(directory)
        (workspace / "Inventory.java").write_text(source, encoding="utf-8")
        with _fixture_provider() as endpoint:
            environment = {
                "GLM_BASE_URL": endpoint,
                "OPENAI_BASE_URL": endpoint,
                "OLLAMA_BASE_URL": endpoint,
                "GLM_MODEL": "fsg-doc-fixture",
                "OPENAI_MODEL": "fsg-doc-fixture",
                "OLLAMA_MODEL": "fsg-doc-fixture",
            }
            calls = [{
                "source": "Inventory.java", "out": "docs/deterministic.md",
                "project_root": "deterministic", "no_llm": True,
                "result_export": "results/deterministic.json",
            }]
            for provider in ("glm", "openai", "ollama"):
                calls.append({
                    "source": "Inventory.java",
                    "out": f"docs/{provider}.md",
                    "project_root": provider,
                    "provider": provider,
                    "model": "fsg-doc-fixture",
                    "result_export": f"results/{provider}.json",
                })
            initialized, tools, schema, results = await _call_tool(
                workspace, "document_code", calls, environment=environment)
    if [item.get("status") for item in results] != ["DOCUMENTED"] * 4:
        raise RuntimeError("document_code transport variants did not complete")
    semantic_result = [{
        "status": item.get("status"),
        "claim": item.get("claim"),
        "narrative_source": item.get("narrative_source"),
        "provider": ((item.get("provider") or {}).get("provider")),
        "fallback": ((item.get("provider") or {}).get("fallback")),
        "publication_status": ((item.get("publication") or {}).get("status")),
    } for item in results]
    return _observation(initialized, tools, schema, semantic_result, results[-1])


async def _verify_observation() -> dict:
    fixtures = {
        "Proven.java": (
            "public class Proven {\n"
            "  //@ ensures \\result == 1;\n"
            "  public static int value() { return 1; }\n}\n"),
        "Proven.jml": (
            "public class Proven {\n"
            "  //@ ensures \\result == 1;\n"
            "  public static int value() { return 1; }\n}\n"),
        "Broken.java": (
            "public class Broken {\n"
            "  //@ ensures \\result == 1;\n"
            "  public static int value() { return 2; }\n}\n"),
        "Checked.rs": "pub fn value() -> i32 { 1 }\n",
        "Prusti.rs": (
            "use prusti_contracts::*;\n"
            "#[ensures(result == 1)]\n"
            "pub fn value() -> i32 { 1 }\n"),
        "BrokenPrusti.rs": (
            "use prusti_contracts::*;\n"
            "#[ensures(result == 1)]\n"
            "pub fn value() -> i32 { 2 }\n"),
        "Kani.rs": (
            "pub fn value() -> i32 { 1 }\n"
            "#[kani::proof]\nfn proof_value() { assert!(value() == 1); }\n"),
        "BrokenKani.rs": (
            "#[kani::proof]\nfn proof_value() { assert!(false); }\n"),
        "proof.c": (
            "/*@ assigns \\nothing; ensures \\result == 1; */\n"
            "int value(void) { return 1; }\n"),
        "broken.c": (
            "/*@ assigns \\nothing; ensures \\result == 1; */\n"
            "int value(void) { return 2; }\n"),
        "proof.cpp": "int main() { return 0; }\n",
        "broken.cpp": "#include <cassert>\nint main() { assert(false); }\n",
    }
    calls = [
        {"source": "Proven.java", "mode": "parse"},
        {"source": "Proven.java", "mode": "check"},
        {"source": "Proven.java", "mode": "esc"},
        {"source": "Proven.java", "mode": "check",
         "result_export": "verify/java-check.json"},
        {"source": "Proven.jml", "mode": "esc"},
        {"source": "Checked.rs", "mode": "parse"},
        {"source": "Checked.rs", "mode": "check"},
        {"source": "Prusti.rs", "mode": "esc", "backend": "prusti"},
        {"source": "Kani.rs", "mode": "esc", "backend": "kani"},
        {"source": "proof.c", "mode": "esc"},
        {"source": "proof.cpp", "mode": "esc"},
        {"source": "proof.c", "mode": "parse"},
        {"source": "proof.c", "mode": "check"},
        {"source": "proof.cpp", "mode": "parse"},
        {"source": "proof.cpp", "mode": "check"},
        {"source": "proof.c", "mode": "parse",
         "result_export": "verify/c-parse.json"},
        {"source": "proof.c", "mode": "check",
         "result_export": "verify/c-check.json"},
        {"source": "proof.cpp", "mode": "parse",
         "result_export": "verify/cpp-parse.json"},
        {"source": "proof.cpp", "mode": "check",
         "result_export": "verify/cpp-check.json"},
        {"source": "Broken.java", "mode": "esc"},
        {"source": "BrokenPrusti.rs", "mode": "esc", "backend": "prusti"},
        {"source": "BrokenKani.rs", "mode": "esc", "backend": "kani"},
        {"source": "broken.c", "mode": "esc"},
        {"source": "broken.cpp", "mode": "esc"},
    ]
    with tempfile.TemporaryDirectory(prefix="formalspecgen-mcp-verify-") as directory:
        workspace = Path(directory)
        for name, source in fixtures.items():
            (workspace / name).write_text(source, encoding="utf-8")
        initialized, tools, schema, results = await _call_tool(
            workspace, "verify_code", calls, timeout_s=300)
        export_root = workspace / ".formalspecgen/mcp-output/verify"
        expected_exports = {
            "java-check.json", "c-parse.json", "c-check.json",
            "cpp-parse.json", "cpp-check.json",
        }
        published_exports = (
            {item.name for item in export_root.iterdir()}
            if export_root.is_dir() else set())
    expected = [
        "VERIFIED", "VERIFIED", "VERIFIED", "VERIFIED", "VERIFIED",
        "PARSED", "RUST_CHECKED", "VERIFIED", "VERIFIED", "VERIFIED",
        "VERIFIED", "UNSUPPORTED_MODE", "UNSUPPORTED_MODE",
        "UNSUPPORTED_MODE", "UNSUPPORTED_MODE", "UNSUPPORTED_MODE",
        "UNSUPPORTED_MODE", "UNSUPPORTED_MODE", "UNSUPPORTED_MODE",
        "VERIFY_FAILED", "VERIFY_FAILED", "VERIFY_FAILED", "VERIFY_FAILED",
        "VERIFY_FAILED",
    ]
    statuses = [item.get("status") for item in results]
    if statuses != expected:
        diagnostics = [{
            "status": item.get("status"),
            "execution_status": (item.get("execution") or {}).get("status"),
            "resource_events": (item.get("execution") or {}).get("resource_events"),
            "message": item.get("message"),
            "execution_output_head": str(
                (item.get("execution") or {}).get("output") or "")[:12000],
            "output_tail": str(item.get("output") or "")[-12000:],
        } for item in results]
        raise RuntimeError(
            "verify_code transport variants failed: "
            f"{statuses!r}; diagnostics={diagnostics!r}")
    expected_claims = [
        "NO_PROOF", "STATIC_CHECK", "DEDUCTIVE_PROOF", "STATIC_CHECK",
        "DEDUCTIVE_PROOF", "NO_PROOF", "STATIC_CHECK", "DEDUCTIVE_PROOF",
        "BOUNDED_EVIDENCE", "DEDUCTIVE_PROOF", "BOUNDED_CPP_PROOF",
        "NO_PROOF", "NO_PROOF", "NO_PROOF", "NO_PROOF", "NO_PROOF",
        "NO_PROOF", "NO_PROOF", "NO_PROOF", "NO_PROOF", "NO_PROOF",
        "NO_PROOF", "NO_PROOF", "NO_PROOF",
    ]
    actual_claims = [item.get("claim") for item in results]
    if actual_claims != expected_claims:
        raise RuntimeError(
            "verify_code transport claim limits changed: "
            f"actual={actual_claims!r}; expected={expected_claims!r}")
    if [bool(item.get("request_satisfied")) for item in results] != (
            [True] * 11 + [False] * 13):
        raise RuntimeError("verify_code transport satisfaction decisions changed")
    executed = (*range(11), *range(19, 24))
    if any((results[index].get("execution") or {}).get(
            "policy_compliance") != "ENFORCED" for index in executed):
        raise RuntimeError("an executing verification route was not isolated")
    if any((item.get("evidence") or {}).get(
            "publication_status") != "COMMITTED" for item in results):
        raise RuntimeError("a verification route lacked committed evidence")
    if not expected_exports <= published_exports:
        raise RuntimeError(
            "verify_code controlled result exports were not published: "
            f"missing={sorted(expected_exports - published_exports)!r}")
    semantic_result = [{
        "status": item.get("status"),
        "claim": item.get("claim"),
        "request_satisfied": item.get("request_satisfied"),
        "backend": ((item.get("workflow_result") or {}).get("request") or {}).get(
            "effective_backend"),
        "policy": ((item.get("execution") or {}).get("policy_compliance")),
        "receipt": ((item.get("evidence") or {}).get("publication_status")),
    } for item in results]
    observation = _observation(
        initialized, tools, schema, semantic_result, results[-1])
    observation["variants"] = [
        "java-parse", "java-check", "java-esc", "java-export", "jml-esc",
        "rust-parse", "rust-check", "rust-prusti", "rust-kani", "c-framac",
        "cpp-esbmc", "c-parse-unsupported", "c-check-unsupported",
        "cpp-parse-unsupported", "cpp-check-unsupported",
        "c-parse-unsupported-export", "c-check-unsupported-export",
        "cpp-parse-unsupported-export", "cpp-check-unsupported-export",
        "java-negative", "rust-prusti-negative", "rust-kani-negative",
        "c-framac-negative", "cpp-esbmc-negative",
    ]
    observation["semantic_results"] = semantic_result
    return observation


def _observation(
        initialized: object, tools: object, schema: dict,
        semantic_result: object, last_result: dict) -> dict:
    return {
        "transport": "mcp-stdio-subprocess",
        "mcp_sdk_version": importlib.metadata.version("mcp"),
        "server": initialized.serverInfo.model_dump(mode="json"),
        "discovered_tools": sorted(item.name for item in tools.tools),
        "input_schema": schema,
        "schema_sha256": _sha256(schema),
        "result_sha256": _sha256(semantic_result),
        "result_status": last_result.get("status"),
    }


_ADAPTERS = {
    "inspect": _inspect_observation,
    "document-code": _document_observation,
    "verify": _verify_observation,
}


def collect_transport_observation(command: str) -> dict:
    try:
        adapter = _ADAPTERS[command]
    except KeyError as exc:
        raise ValueError(f"no reviewed MCP acceptance adapter for {command}") from exc
    return anyio.run(adapter)


async def _schema_observation(tool_name: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="formalspecgen-mcp-schema-") as directory:
        initialized, tools, schema, results = await _call_tool(
            Path(directory), tool_name, [])
    return _observation(initialized, tools, schema, [], results[-1] if results else {})


def collect_tool_schema(tool_name: str) -> dict:
    """Observe discovery through real stdio without executing the workflow."""
    return anyio.run(_schema_observation, tool_name)
