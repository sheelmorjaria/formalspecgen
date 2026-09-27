# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Reviewed real-transport fixtures for completed MCP workflows."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import subprocess
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
from pipeline.approval_service import record_human_decision


def _sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _publication_status(value: object) -> str | None:
    """Normalize publication fields from successful and rejected results."""
    if isinstance(value, dict):
        status = value.get("status")
        return status if isinstance(status, str) else None
    return value if isinstance(value, str) else None


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
    for name in (
            "FORMALSPECGEN_ACCEPTANCE_REVIEWER_GNUPGHOME",
            "FORMALSPECGEN_ACCEPTANCE_REVIEWER_KEY"):
        child_environment.pop(name, None)
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


async def _call_refactor_signing(
        workspace: Path, arguments: dict, *, timeout_s: float = 180
        ) -> tuple[object, object, dict, list[dict]]:
    """Exercise request, out-of-band human approval, and protected completion."""
    child_environment = dict(os.environ)
    reviewer_home = child_environment.pop(
        "FORMALSPECGEN_ACCEPTANCE_REVIEWER_GNUPGHOME", "")
    reviewer_key = child_environment.pop(
        "FORMALSPECGEN_ACCEPTANCE_REVIEWER_KEY", "")
    approval_root = child_environment.get("FORMALSPECGEN_APPROVAL_ROOT", "")
    if not reviewer_home or not reviewer_key or not approval_root:
        raise RuntimeError("approval acceptance is not provisioned")
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(mcp_server.__file__).resolve())],
        cwd=str(workspace), env=child_environment)
    with anyio.fail_after(timeout_s):
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                tools = await session.list_tools()
                schemas = {item.name: item.inputSchema for item in tools.tools}
                response = await session.call_tool("verify_refactor", arguments)
                if response.isError or not isinstance(response.structuredContent, dict):
                    raise RuntimeError("signed verify_refactor request failed")
                requested = response.structuredContent
                request_id = (requested.get("approval") or {}).get("request_id")
                if not request_id:
                    raise RuntimeError("signed refactor returned no approval identity")
                await anyio.to_thread.run_sync(
                    lambda: record_human_decision(
                        Path(approval_root), request_id, decision="approve",
                        signing_key=reviewer_key, gpg_home=Path(reviewer_home)))
                pending_response = await session.call_tool(
                    "get_approval_request", {"request_id": request_id})
                completed_response = await session.call_tool(
                    "complete_refactor_signing", {"request_id": request_id})
                if pending_response.isError or completed_response.isError or not isinstance(
                        completed_response.structuredContent, dict):
                    raise RuntimeError("approval completion MCP call failed")
                pending = pending_response.structuredContent
                completed = completed_response.structuredContent
                signature = Path((completed.get("signature") or {}).get("path", ""))
                artifact = Path(
                    workspace / ".formalspecgen/mcp-output/refactor/signed.json")
                verified = subprocess.run([
                    "gpg", "--homedir", child_environment[
                        "FORMALSPECGEN_APPROVAL_GNUPGHOME"],
                    "--batch", "--verify", str(signature), str(artifact),
                ], capture_output=True, text=True, check=False)
                if verified.returncode != 0:
                    raise RuntimeError("independent signature verification failed")
                serialized = json.dumps(completed, sort_keys=True).lower()
                if "private key" in serialized or "private_key_material" in serialized:
                    raise RuntimeError("MCP response exposed private-key material")
    return initialized, tools, schemas["verify_refactor"], [
        requested, pending, completed]


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


async def _analyze_codebase_observation() -> dict:
    fixtures = {
        "mixed/Counter.java": (
            "public class Counter { private int value; "
            "public void inc() { if (value < 3) value = value + 1; } }\n"),
        "mixed/Meter.c": "struct Meter { int value; };\n",
        "mixed/Gauge.cpp": "class Gauge { int level; };\n",
        "mixed/Sensor.rs": "struct Sensor { value: i32, }\n",
        "unsupported/readme.py": "print('not an admitted source dialect')\n",
    }
    calls = [
        {"target_dir": "mixed", "out_dir": "analysis/mixed",
         "project_root": "projects/mixed",
         "result_export": "results/mixed.json"},
        {"target_dir": "unsupported", "out_dir": "analysis/unsupported",
         "project_root": "projects/unsupported"},
        {"target_dir": "missing", "out_dir": "analysis/missing",
         "project_root": "projects/missing",
         "result_export": "results/missing.json"},
        {"target_dir": "../outside", "out_dir": "analysis/denied",
         "project_root": "projects/denied",
         "result_export": "results/denied.json"},
        {"target_dir": "mixed", "out_dir": "analysis/mixed",
         "project_root": "projects/mixed",
         "result_export": "results/collision.json"},
    ]
    with tempfile.TemporaryDirectory(
            prefix="formalspecgen-mcp-analysis-") as directory:
        workspace = Path(directory)
        for name, content in fixtures.items():
            path = workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        initialized, tools, schema, results = await _call_tool(
            workspace, "analyze_codebase", calls, timeout_s=120)
        output_root = workspace / ".formalspecgen/mcp-output"
        published = output_root / "analysis/mixed/extracted_architecture.json"
        export = output_root / "results/mixed.json"
        if not published.is_file() or not export.is_file():
            raise RuntimeError("analysis artifacts or controlled export were not published")
        negative_exports = [
            output_root / name for name in (
                "results/missing.json", "results/denied.json",
                "results/collision.json")]
        if any(not path.is_file() for path in negative_exports):
            raise RuntimeError("negative analysis outcomes lacked controlled exports")
        manifest = results[0].get("publication", {}).get("artifacts", {})
        for metadata in manifest.values():
            path = Path(str(metadata.get("path", "")))
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != \
                    metadata.get("sha256"):
                raise RuntimeError("analysis publication digest does not match its bytes")

    expected = ["EXTRACTED", "EXTRACTED", "FAIL", "FAIL", "FAIL"]
    if [item.get("status") for item in results] != expected:
        raise RuntimeError("analyze_codebase transport outcomes changed")
    if results[0].get("claim") != "UNREVIEWED_EXTRACTION_CANDIDATE" or \
            results[0].get("request_satisfied") is not True:
        raise RuntimeError("successful analysis overstated or lost its extraction claim")
    if results[1].get("components") != [] or \
            results[1].get("claim") != "UNREVIEWED_EXTRACTION_CANDIDATE":
        raise RuntimeError("unsupported inputs were not handled as an empty proposal")
    if results[2].get("code") not in {"input_unavailable", "CODEBASE_ANALYSIS_FAILED"}:
        raise RuntimeError("missing analysis input returned an unexpected boundary")
    if results[3].get("code") != "path_outside_workspace":
        raise RuntimeError("analysis input escaped the workspace boundary")
    if results[4].get("code") != "OUTPUT_ALREADY_EXISTS":
        raise RuntimeError("analysis publication did not enforce no-replace behavior")
    if any((results[index].get("result_export") or {}).get("status") != "COMMITTED"
           for index in (2, 3, 4)):
        raise RuntimeError("negative analysis result export was not committed")
    semantic = [{
        "status": item.get("status"), "claim": item.get("claim"),
        "request_satisfied": item.get("request_satisfied"),
        "input_manifest": (item.get("input_snapshot") or {}).get(
            "manifest_sha256"),
        "publication": (item.get("publication") or {}).get("status"),
        "code": item.get("code"),
    } for item in results]
    observation = _observation(
        initialized, tools, schema, semantic, results[-1])
    observation["variants"] = [
        "polyglot-success-export", "unsupported-input", "missing-input",
        "denied-path", "publication-collision", "negative-result-export"]
    observation["semantic_results"] = semantic
    return observation


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


async def _verify_refactor_observation() -> dict:
    fixtures = {
        "java/base/Account.java": (
            "public class Account {\n"
            "  //@ ensures \\result == 1;\n"
            "  public int value() { int x = 1; return x; }\n}\n"),
        "java/good/Account.java": (
            "public class Account {\n"
            "  //@ ensures \\result == 1;\n"
            "  public int value() { return 1; }\n}\n"),
        "java/bad/Account.java": (
            "public class Account {\n"
            "  //@ ensures \\result == 1;\n"
            "  public int value() { return 2; }\n}\n"),
        "java/mutated/Account.java": (
            "public class Account {\n"
            "  //@ ensures \\result == 2;\n"
            "  public int value() { return 2; }\n}\n"),
        "java/multi-base/Service.java": (
            "public class Service {\n"
            "  //@ ensures \\result == 1;\n"
            "  public int value() { return 1; }\n}\n"),
        "java/multi/Service.java": (
            "public class Service {\n"
            "  //@ ensures \\result == 1;\n"
            "  public int value() { return Helper.value(); }\n}\n"),
        "java/multi/Helper.java": (
            "public class Helper {\n"
            "  //@ ensures \\result == 1;\n"
            "  public static int value() { return 1; }\n}\n"),
        "rust/base.rs": (
            "use prusti_contracts::*;\n#[ensures(result == 1)]\n"
            "pub fn value() -> i32 { let x = 1; x }\n"),
        "rust/good.rs": (
            "use prusti_contracts::*;\n#[ensures(result == 1)]\n"
            "pub fn value() -> i32 { 1 }\n"),
        "rust/bad.rs": (
            "use prusti_contracts::*;\n#[ensures(result == 1)]\n"
            "pub fn value() -> i32 { 2 }\n"),
        "c/base.c": (
            "/*@ assigns \\nothing; ensures \\result == 1; */\n"
            "int value(void) { int x = 1; return x; }\n"),
        "c/good.c": (
            "/*@ assigns \\nothing; ensures \\result == 1; */\n"
            "int value(void) { return 1; }\n"),
        "c/bad.c": (
            "/*@ assigns \\nothing; ensures \\result == 1; */\n"
            "int value(void) { return 2; }\n"),
        "cpp/base.cpp": (
            "#include <cassert>\nclass Counter { public: void check() {\n"
            "  int x = 1; assert(x == 1);\n} };\n"),
        "cpp/good.cpp": (
            "#include <cassert>\nclass Counter { public: void check() {\n"
            "  int x = 1; x += 0; assert(x == 1);\n} };\n"),
        "cpp/bad.cpp": (
            "#include <cassert>\nclass Counter { public: void check() {\n"
            "  int x = 1; x = 2; assert(x == 1);\n} };\n"),
    }
    calls = [
        {"baseline": "java/base/Account.java",
         "refactored": "java/good/Account.java"},
        {"baseline": "java/base/Account.java",
         "refactored": "java/bad/Account.java",
         "result_export": "refactor/java-negative.json"},
        {"baseline": "java/base/Account.java",
         "refactored": "java/mutated/Account.java",
         "result_export": "refactor/java-surface-rejected.json"},
        {"baseline": "java/multi-base/Service.java",
         "refactored": "java/multi"},
        {"baseline": "rust/base.rs", "refactored": "rust/good.rs"},
        {"baseline": "rust/base.rs", "refactored": "rust/bad.rs",
         "result_export": "refactor/rust-negative.json"},
        {"baseline": "c/base.c", "refactored": "c/good.c"},
        {"baseline": "c/base.c", "refactored": "c/bad.c",
         "result_export": "refactor/c-negative.json"},
        {"baseline": "cpp/base.cpp", "refactored": "cpp/good.cpp"},
        {"baseline": "cpp/base.cpp", "refactored": "cpp/bad.cpp",
         "result_export": "refactor/cpp-negative.json"},
    ]
    with tempfile.TemporaryDirectory(prefix="formalspecgen-mcp-refactor-") as directory:
        workspace = Path(directory)
        for name, source in fixtures.items():
            path = workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
        initialized, tools, schema, results = await _call_tool(
            workspace, "verify_refactor", calls, timeout_s=360)
        signed_transport = await _call_refactor_signing(
            workspace, {
                "baseline": "java/base/Account.java",
                "refactored": "java/good/Account.java",
                "result_export": "refactor/signed.json",
                "signing_intent": True,
            }, timeout_s=360)
        signing_results = signed_transport[3]
        exports = [
            workspace / ".formalspecgen/mcp-output" / name
            for name in (
                "refactor/java-negative.json",
                "refactor/java-surface-rejected.json",
                "refactor/rust-negative.json",
                "refactor/c-negative.json",
                "refactor/cpp-negative.json",
            )
        ]
        if missing := [str(path) for path in exports if not path.is_file()]:
            raise RuntimeError(
                "negative refactor result exports were not published: "
                + ", ".join(missing))
    expected_statuses = [
        "VERIFIED", "FAIL", "FAIL", "VERIFIED", "VERIFIED", "FAIL",
        "VERIFIED", "FAIL", "VERIFIED", "FAIL",
    ]
    statuses = [item.get("status") for item in results]
    if statuses != expected_statuses:
        raise RuntimeError(
            "verify_refactor transport variants failed: "
            f"actual={statuses!r}; expected={expected_statuses!r}")
    expected_claims = [
        "REFACTOR_CONTRACT_PRESERVED", "NO_PROOF", "NO_PROOF",
        "MULTIFILE_REFACTOR_CONTRACT_PRESERVED",
        "REFACTOR_CONTRACT_PRESERVED", "NO_PROOF",
        "REFACTOR_CONTRACT_PRESERVED", "NO_PROOF",
        "BOUNDED_REFACTOR_CONTRACT_PRESERVED", "NO_PROOF",
    ]
    if [item.get("claim") for item in results] != expected_claims:
        raise RuntimeError("verify_refactor transport claim limits changed")
    if any((item.get("evidence") or {}).get("publication_status") != "COMMITTED"
           for item in results):
        raise RuntimeError("an unsigned refactor route lacked committed evidence")
    observations = [
        observation
        for item in results
        for stage in (item.get("verification_stages") or [])
        for observation in (stage.get("execution_stages") or [])
    ]
    if not observations or any(
            observation.get("policy_compliance") != "ENFORCED"
            for observation in observations):
        raise RuntimeError(
            "a refactor verification stage lacked enforced execution policy")
    if [item.get("status") for item in signing_results] != [
            "APPROVAL_REQUIRED", "DECISION_RECORDED", "SIGNED"]:
        raise RuntimeError("authenticated signing continuation did not complete")
    if signing_results[-1].get("claim") != "REFACTOR_CONTRACT_PRESERVED" or \
            not signing_results[-1].get("request_satisfied") or \
            signing_results[-1].get("verification", {}).get(
                "claim_upgraded_by_signing") is not False:
        raise RuntimeError("signing changed the verification claim or did not complete")
    if signing_results[-1].get("approval", {}).get("private_key_exposed") is not False:
        raise RuntimeError("signing response did not preserve the key boundary")
    semantic_result = [{
        "status": item.get("status"), "claim": item.get("claim"),
        "request_satisfied": item.get("request_satisfied"),
        "receipt": (item.get("evidence") or {}).get("publication_status"),
        "stages": len(item.get("verification_stages") or []),
    } for item in results]
    semantic_result.extend({
        "status": item.get("status"), "claim": item.get("claim"),
        "request_satisfied": item.get("request_satisfied"),
        "approval": (item.get("approval") or {}).get("status"),
    } for item in signing_results)
    observation = _observation(
        initialized, tools, schema, semantic_result, signing_results[-1])
    observation["variants"] = [
        "java-single-success", "java-single-failure-export",
        "java-surface-rejection-export", "java-multifile-success",
        "rust-success", "rust-failure-export",
        "c-success", "c-failure-export", "cpp-success", "cpp-failure-export",
        "signing-request", "human-approval-observed", "protected-signing-complete",
    ]
    observation["semantic_results"] = semantic_result
    return observation


async def _apply_refactor_observation() -> dict:
    from pipeline.java_inspection import inspect_java_file

    long_body = "\n".join(
        f"    int unused{index} = {index};" for index in range(61))
    facade_fields = "\n".join(f"  private int f{index};" for index in range(10))
    facade_methods = "\n".join(
        (("  //@ ensures \\result == x;\n" if index == 0 else "") +
         f"  public int m{index}(int x) {{ return x; }}")
        for index in range(15))
    fixtures = {
        "java/extract/LongCounter.java": (
            "public class LongCounter {\n"
            "  //@ ensures \\result == 1;\n"
            "  public int value() {\n" + long_body +
            "\n    return 1;\n  }\n}\n"),
        "jml/extract/LongSpec.jml": (
            "public class LongSpec {\n"
            "  //@ ensures \\result == 1;\n"
            "  public int value() {\n" + long_body +
            "\n    return 1;\n  }\n}\n"),
        "java/factory/Creator.java": (
            "public class Creator {\n"
            "  //@ requires kind != null;\n"
            "  //@ ensures \\result != null;\n"
            "  public Product create(String kind) {\n"
            "    if (kind.equals(\"alpha\")) return new Alpha();\n"
            "    else return new Beta();\n  }\n}\n"),
        "java/factory/Product.java": "public interface Product {}\n",
        "java/factory/Alpha.java": "public class Alpha implements Product {}\n",
        "java/factory/Beta.java": "public class Beta implements Product {}\n",
        "java/state/Legacy.java": (
            "public class Legacy {\n  private int state;\n"
            "  //@ ensures true;\n"
            "  public int run() {\n"
            "    if (state == 0) { return 1; }\n"
            "    if (state == 1) { return 2; }\n    return 0;\n  }\n"
            "  public int other() {\n"
            "    if (state == 0) { return 3; }\n"
            "    if (state == 1) { return 4; }\n    return 0;\n  }\n}\n"),
        "java/decorator/Example.java": (
            "public class Example implements Service {\n"
            "  private final Service delegate;\n"
            "  public Example(Service delegate) { this.delegate = delegate; }\n"
            "  //@ ensures true;\n"
            "  public void run() { Logger.info(\"run\"); delegate.run(); }\n"
            "  public void reset() { Metrics.increment(\"reset\"); delegate.reset(); }\n"
            "}\n"),
        "java/decorator/Service.java": (
            "public interface Service { void run(); void reset(); }\n"),
        "java/decorator/Logger.java": (
            "public final class Logger { public static void info(String value) {} }\n"),
        "java/decorator/Metrics.java": (
            "public final class Metrics { public static void increment(String value) {} }\n"),
        "java/facade/Legacy.java": (
            "public class Legacy {\n" + facade_fields + "\n" +
            facade_methods + "\n}\n"),
        "java/null/OrderService.java": (
            "public class OrderService {\n"
            "  private /*@ nullable @*/ Logger logger;\n"
            "  //@ requires logger != null;\n"
            "  public OrderService(Logger logger) { this.logger = logger; }\n"
            "  //@ ensures true;\n"
            "  public void first() {\n"
            "    //@ assume this.logger != null;\n"
            "    if (logger != null) { logger.log(); }\n  }\n"
            "  public void second() {\n"
            "    //@ assume this.logger != null;\n"
            "    if (logger != null) { logger.log(); }\n  }\n}\n"),
        "java/null/Logger.java": "public interface Logger { void log(); }\n",
        "java/strategy/PricingService.java": (
            "public class PricingService {\n"
            "  private /*@ spec_public @*/ int price;\n"
            "  //@ requires customerType == 1 || customerType == 2;\n"
            "  //@ ensures price >= 0;\n"
            "  public void calculatePrice(int customerType) {\n"
            "    if (customerType == 1) { price = 100; // Standard\n"
            "    } else if (customerType == 2) { price = 80; // Premium\n"
            "    }\n  }\n}\n"),
        "rust/extract/value.rs": (
            "use prusti_contracts::*;\n"
            "#[ensures(result == 1)]\n"
            "pub fn value() -> i32 { 1 }\n"),
        "rust/strategy/meter.rs": (
            "use prusti_contracts::*;\n\n"
            "pub struct Meter { pub price: i32 }\n\n"
            "impl Meter {\n"
            "  #[ensures(self.price >= 100)]\n"
            "  pub fn set_price(&mut self, kind: i32) {\n"
            "    match kind {\n      1 => self.price = 100,\n"
            "      2 => self.price = 250,\n      _ => self.price = 100,\n"
            "    }\n  }\n}\n"),
        "c/add.c": (
            "/*@ requires value >= 0 && value < 100; assigns \\nothing; "
            "ensures \\result == value + 1; */\n"
            "int add_one(int value) { return value + 1; }\n"),
        "cpp/Counter.cpp": (
            "#include <cassert>\nclass Counter { public:\n"
            "  int count = 0;\n"
            "  void add(int value) { assert(value >= 0); count += value; }\n"
            "};\n"),
    }
    with tempfile.TemporaryDirectory(
            prefix="formalspecgen-mcp-apply-refactor-") as directory:
        workspace = Path(directory)
        for name, source in fixtures.items():
            path = workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
        java_calls = [
            ("java/extract/LongCounter.java", "extract-method", "value",
             "java-extract-method", "candidates/java-extract/LongCounter.java"),
            ("jml/extract/LongSpec.jml", "extract-method", "value",
             "jml-extract-method", "candidates/jml-extract/LongSpec.jml"),
            ("java/factory/Creator.java", "factory-method", "create",
             "java-factory-method", "candidates/java-factory"),
            ("java/state/Legacy.java", "state", "run",
             "java-state", "candidates/java-state"),
            ("java/decorator/Example.java", "decorator", "run",
             "java-decorator", "candidates/java-decorator"),
            ("java/facade/Legacy.java", "facade", "m0",
             "java-facade", "candidates/java-facade"),
            ("java/null/OrderService.java", "null-object", "first",
             "java-null-object", "candidates/java-null-object"),
            ("java/strategy/PricingService.java", "strategy", "calculatePrice",
             "java-strategy", "candidates/java-strategy"),
        ]
        calls = []
        variants = []
        expected_claims = []
        for source, pattern, method, variant, out in java_calls:
            inspection_path = str(Path(source).parent / "inspection.json")
            (workspace / inspection_path).write_text(
                json.dumps(inspect_java_file(workspace / source)), encoding="utf-8")
            calls.append({
                "source": source, "inspection": inspection_path,
                "pattern": pattern, "method": method, "out": out,
            })
            variants.append(variant)
            expected_claims.append(
                "REFACTOR_CONTRACT_PRESERVED" if pattern == "extract-method"
                else "MULTIFILE_REFACTOR_CONTRACT_PRESERVED")
        calls.extend([
            {"source": "rust/extract/value.rs", "pattern": "extract-method",
             "method": "value", "out": "candidates/rust-extract/value.rs"},
            {"source": "rust/strategy/meter.rs", "pattern": "strategy",
             "method": "set_price", "out": "candidates/rust-strategy/meter.rs"},
            {"source": "c/add.c", "pattern": "extract-method", "method": "add_one",
             "out": "candidates/c/add.c"},
            {"source": "cpp/Counter.cpp", "pattern": "extract-method",
             "method": "add", "out": "candidates/cpp/Counter.cpp"},
            {"source": "c/add.c", "pattern": "extract-method",
             "method": "missing", "out": "candidates/c/missing.c",
             "result_export": "results/rejected.json"},
        ])
        variants.extend([
            "rust-extract-method", "rust-strategy", "c-extract-method",
            "cpp-extract-method", "negative-transform-export",
        ])
        expected_claims.extend([
            "REFACTOR_CONTRACT_PRESERVED", "REFACTOR_CONTRACT_PRESERVED",
            "REFACTOR_CONTRACT_PRESERVED", "BOUNDED_REFACTOR_CONTRACT_PRESERVED",
        ])
        initialized, tools, schema, results = await _call_tool(
            workspace, "apply_refactor", calls, timeout_s=600)
        expected = ["VERIFIED"] * len(expected_claims) + ["FAIL"]
        if [item.get("status") for item in results] != expected:
            raise RuntimeError("apply_refactor transport variants did not complete")
        for item, expected_claim in zip(results[:-1], expected_claims):
            if item.get("request_satisfied") is not True or \
                    item.get("claim") != expected_claim:
                raise RuntimeError("apply_refactor returned an unexpected claim")
            if (item.get("candidate_publication") or {}).get("status") != "COMMITTED":
                raise RuntimeError("apply_refactor candidate was not committed")
            if (item.get("evidence") or {}).get("publication_status") != "COMMITTED":
                raise RuntimeError("apply_refactor evidence was not committed")
            observations = [
                observation
                for stage in item.get("verification_stages") or []
                for observation in stage.get("execution_stages") or []
            ]
            if not observations or any(
                    value.get("policy_compliance") != "ENFORCED"
                    for value in observations):
                raise RuntimeError("apply_refactor execution was not strictly enforced")
            manifest = {
                value["path"]: value["sha256"]
                for value in item.get("candidate_manifest") or []
            }
            published = (item.get("candidate_publication") or {}).get("artifacts") or {}
            published_by_name = {
                Path(metadata["path"]).name: metadata
                for metadata in published.values()
            }
            if set(manifest) != set(published_by_name):
                raise RuntimeError("published candidate set differs from verified manifest")
            for name, digest in manifest.items():
                metadata = published_by_name[name]
                candidate = Path(metadata["path"])
                if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest or \
                        metadata.get("sha256") != digest:
                    raise RuntimeError("published candidate bytes differ from verification")
        if (results[-1].get("result_export") or {}).get("status") != "COMMITTED":
            raise RuntimeError("negative apply_refactor result was not exported")
    semantic_result = [{
        "status": item.get("status"), "claim": item.get("claim"),
        "request_satisfied": item.get("request_satisfied"),
        "language": ((item.get("workflow_result") or {}).get("request") or {}).get(
            "language"),
        "receipt": ((item.get("evidence") or {}).get("publication_status")),
        "candidate": _publication_status(item.get("candidate_publication")),
        "observations_enforced": all(
            observation.get("policy_compliance") == "ENFORCED"
            for stage in item.get("verification_stages") or []
            for observation in stage.get("execution_stages") or []),
    } for item in results]
    observation = _observation(
        initialized, tools, schema, semantic_result, results[-1])
    observation["variants"] = variants
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
    "analyze-codebase": _analyze_codebase_observation,
    "verify": _verify_observation,
    "verify-refactor": _verify_refactor_observation,
    "apply-refactor": _apply_refactor_observation,
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
