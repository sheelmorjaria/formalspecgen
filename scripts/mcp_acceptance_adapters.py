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
        "mixed/Basket.java": (
            "import java.util.List;\n"
            "public class Basket { private List<Integer> items; }\n"),
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
        output_root = workspace / "controlled-analysis-output"
        initialized, tools, schema, results = await _call_tool(
            workspace, "analyze_codebase", calls,
            environment={
                "FORMALSPECGEN_MCP_OUTPUT_ROOT": str(output_root),
            }, timeout_s=120)
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
        manifest_by_path = {
            Path(str(metadata.get("path", ""))): metadata
            for metadata in manifest.values()
        }
        for metadata in manifest.values():
            path = Path(str(metadata.get("path", "")))
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != \
                    metadata.get("sha256"):
                raise RuntimeError("analysis publication digest does not match its bytes")
        architecture = Path(str(results[0].get("architecture", "")))
        domains = [Path(str(value)) for value in results[0].get("domains", [])]
        if architecture != published or architecture not in manifest_by_path or \
                not domains or any(path not in manifest_by_path for path in domains):
            raise RuntimeError(
                "analysis result references do not resolve through publication metadata")
        exported = json.loads(export.read_text(encoding="utf-8"))
        if exported.get("architecture") != str(architecture) or \
                exported.get("domains") != [str(path) for path in domains]:
            raise RuntimeError("analysis export retained non-published references")
        architecture_payload = json.loads(
            architecture.read_text(encoding="utf-8"))
        embedded_warnings = architecture_payload.get("warnings", [])
        if embedded_warnings != results[0].get("warnings") or \
                not embedded_warnings:
            raise RuntimeError("analysis embedded diagnostics diverged from its result")
        if any("formalspecgen-analysis-" in str(item.get("file", ""))
               or not Path(str(item.get("file", ""))).is_file()
               for item in embedded_warnings):
            raise RuntimeError("analysis diagnostics retained private snapshot paths")

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


async def _traceability_observation() -> dict:
    """Observe all arguments, both domain formats, and negative exports."""
    try:
        from scripts.generate_pages_companions import _GuideLinks
    except ModuleNotFoundError:
        # The acceptance runner is also invoked directly from scripts/.
        from generate_pages_companions import _GuideLinks
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root / "domains/v2/bounded_counter.json").read_text())
    guide = _GuideLinks()
    guide.feed((root / "site/index.html").read_text())
    example = json.loads(guide.examples["traceability"])
    with tempfile.TemporaryDirectory(prefix="formalspecgen-traceability-acceptance-") as directory:
        workspace = Path(directory)
        (workspace / "domain.json").write_text(json.dumps(fixture))
        fixture["review_status"] = "unreviewed"
        fixture.pop("accepted_candidate_sha256")
        fixture.pop("accepted_evidence_sha256")
        import yaml
        (workspace / "domain.yaml").write_text(yaml.safe_dump(fixture))
        (workspace / "requirements.req").write_text(
            "REQ-001: value must not exceed 5.\nREQ-002: latency must not exceed 10.\n")
        for subdir, content in (("a", "int other = 0;\n"), ("b", "int value = 5;\n")):
            folder = workspace / "src" / subdir
            folder.mkdir(parents=True)
            (folder / "Counter.java").write_text(content)
        (workspace / "empty").mkdir()
        (workspace / "bad.json").write_text("{}")
        (workspace / "bad.req").write_text("no requirement identifiers")
        base = {"domain": "domain.yaml", "source": "src", "requirements": "requirements.req"}
        calls = [
            example,
            {**base, "domain": "domain.json", "source": "src/b/Counter.java",
             "out": "single.txt", "result_export": "results/single.data"},
            {**base, "source": "empty", "out": "empty.md"},
            {**base, "domain": "absent.json", "out": "missing.md"},
            {**base, "domain": "../outside.json", "out": "denied.md"},
            {**base, "domain": "bad.json", "out": "bad-domain.md"},
            {**base, "requirements": "bad.req", "out": "bad-req.md"},
            {**base, "out": example["out"], "result_export": "collision.json"},
            {**base, "out": "new.md", "result_export": "collision.json"},
            {**base, "out": "../escape.md"},
        ]
        output = workspace / "configured-output"
        initialized, tools, schema, results = await _call_tool(
            workspace, "generate_traceability_matrix", calls,
            environment={"FORMALSPECGEN_MCP_OUTPUT_ROOT": str(output)}, timeout_s=120)
        if [item.get("request_satisfied") for item in results] != [True]*3 + [False]*7:
            raise RuntimeError(f"traceability transport outcomes changed: {results}")
        if any(item.get("claim") != "NO_PROOF" for item in results):
            raise RuntimeError("traceability matching acquired a proof claim")
        for index, result in enumerate(results):
            for stage in ("publication", "result_export"):
                for metadata in result.get(stage, {}).get("artifacts", {}).values():
                    path = Path(metadata["path"])
                    if output not in path.parents or hashlib.sha256(path.read_bytes()).hexdigest() != metadata["sha256"]:
                        raise RuntimeError("traceability publication identity mismatch")
            if index < 3:
                matrix = Path(result["matrix_file"])
                if matrix != Path(next(iter(result["publication"]["artifacts"].values()))["path"]):
                    raise RuntimeError("traceability returned an unpublished reference")
                exported = json.loads(Path(next(iter(result["result_export"]["artifacts"].values()))["path"]).read_text())
                if exported["rows"] != result["rows"] or exported["matrix_file"] != str(matrix):
                    raise RuntimeError("traceability sidecar references differ")
                manifest = result["input_snapshot"]["files"]
                for row in result["rows"]:
                    if row["source"]:
                        metadata = next(item for item in manifest if item["role"] == "source" and item["path"] == row["source"])
                        if row["source_sha256"] != metadata["sha256"]:
                            raise RuntimeError("source reference lost its captured identity")
                if result["rows"][1]["status"] != "UNMAPPED":
                    raise RuntimeError("unmapped requirement disappeared")
            elif index < 8 and result.get("result_export", {}).get("status") != "COMMITTED":
                raise RuntimeError("negative traceability export missing")
        if results[0]["rows"][0]["source"] != "b/Counter.java":
            raise RuntimeError("duplicate source basenames are ambiguous")
        if json.loads((output / "collision.json").read_text())["request_satisfied"]:
            raise RuntimeError("existing negative export was replaced")
        semantic = [{
            "status": item["status"], "claim": item["claim"],
            "request_satisfied": item["request_satisfied"],
            "coverage": item.get("coverage"), "code": item.get("code"),
            "input_manifest": item.get("input_snapshot", {}).get("manifest_sha256"),
        } for item in results]
    observation = _observation(initialized, tools, schema, semantic, results[-1])
    observation["semantic_results"] = semantic
    observation["variants"] = [
        "candidate-domain", "reviewed-domain", "source-file", "source-directory",
        "default-sidecar", "explicit-export", "unmapped-requirements",
        "duplicate-filenames", "missing-input", "malformed-input", "denied-path",
        "publication-collision", "negative-export", "configured-output-root"]
    return observation


async def _evidence_observation() -> dict:
    """Exercise read-only evidence consumption, not formal verification.

    The ledgers are synthetic fixtures. Record actual transport/CLI results and
    compare captured identities with fixture bytes before discarding the workspace.
    """
    from pipeline.evidence_consumer import EVIDENCE_BUDGET
    from pipeline.lifecycle import EvidenceClaim, PipelineState, RunLedger

    with tempfile.TemporaryDirectory(prefix="formalspecgen-evidence-acceptance-") as directory:
        workspace = Path(directory)

        def ledger(name: str, *, rejected: bool = False, padding: int = 0,
                   stages: int = 1) -> Path:
            run = RunLedger(workspace / name)
            for index in range(stages):
                run.record(PipelineState.PROOF, "REJECTED" if rejected else "VERIFIED",
                           claim=EvidenceClaim.NO_PROOF if rejected else EvidenceClaim.DEDUCTIVE_PROOF,
                           evidence={"fixture": "synthetic; no verifier executed",
                                     "padding": "x" * padding if index == 0 else ""})
            return run.commit({"final_status": "REJECTED" if rejected else "VERIFIED",
                               "claim": "NO_PROOF" if rejected else "DEDUCTIVE_PROOF",
                               "claim_limits": {"synthetic_fixture": True}})

        good = ledger("valid")
        digest = hashlib.sha256(good.read_bytes()).hexdigest()
        comparison = ledger("comparison", rejected=True, stages=2)
        comparison_digest = hashlib.sha256(comparison.read_bytes()).hexdigest()
        large_left = ledger("large-left", padding=4 * 1024 * 1024)
        large_right = ledger("large-right", padding=4 * 1024 * 1024)
        many_left = ledger("many-left", stages=127)
        many_right = ledger("many-right", stages=127)
        tampered = ledger("tampered")
        (tampered.parent / "run.json").write_text("tampered", encoding="utf-8")
        missing = ledger("missing-artifact")
        (missing.parent / "run.json").unlink()
        linked = ledger("linked-artifact")
        (linked.parent / "run.json").unlink()
        (linked.parent / "run.json").symlink_to(good.parent / "run.json")
        (workspace / "linked.json").symlink_to(good)
        malformed = workspace / "malformed.json"
        malformed.write_text("not json", encoding="utf-8")
        oversized = workspace / "oversized.json"
        oversized.write_bytes(b" " * (EVIDENCE_BUDGET["max_input_bytes"] + 1))
        too_many = workspace / "too-many.json"
        manifest = json.loads(good.read_bytes())
        manifest["artifacts"] = manifest["artifacts"][:1] * EVIDENCE_BUDGET["max_input_files"]
        too_many.write_text(json.dumps(manifest), encoding="utf-8")
        traversal = workspace / "traversal.json"
        manifest["artifacts"] = [{"path": "../outside.json", "size": 0, "sha256": "0" * 64}]
        traversal.write_text(json.dumps(manifest), encoding="utf-8")
        source = workspace / "Counter.java"
        source.write_bytes(b"class Counter {}\r\n")
        changed_source = workspace / "Changed.java"
        changed_source.write_text("class Changed {}", encoding="utf-8")
        source_link = workspace / "source-link.java"
        source_link.symlink_to(source)

        def source_ledger(name: str, *, conflict: bool = False, extra_stages: int = 0) -> Path:
            from pipeline.workflow_contracts import VerificationWorkflowRequest
            request = VerificationWorkflowRequest(str(source)).as_dict()
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            stages = [{"snapshot_files": [{"path": source.name, "sha256": digest, "size": source.stat().st_size}],
                       "fixture": "synthetic; no verifier executed"}]
            run = RunLedger(workspace / name)
            run.record(PipelineState.PROOF, "FAIL", claim=EvidenceClaim.NO_PROOF,
                details={"workflow_request": request}, evidence={"source_path": str(source),
                "source_sha256": digest, "execution_stages": stages})
            for _ in range(extra_stages):
                run.record(PipelineState.CHEAP_GATES, "FAIL", claim=EvidenceClaim.NO_PROOF)
            return run.commit({"final_status": "FAIL", "claim": "NO_PROOF", "workflow_request": request,
                "source_sha256": "0" * 64 if conflict else digest, "execution_stages": stages,
                "claim_policy_version": "verification-policy-v1"})

        bound = source_ledger("source-bound")
        conflicting = source_ledger("source-conflicting", conflict=True)
        full = source_ledger("source-full", extra_stages=253)

        cases = [
            ("validate", {"manifest": str(good)}, "EVIDENCE_VALID", None),
            ("explain", {"manifest": str(good), "operation": "explain", "expected_sha256": digest}, "EVIDENCE_VALID", None),
            ("digest-match", {"manifest": str(good), "expected_sha256": digest}, "EVIDENCE_VALID", None),
            ("digest-mismatch", {"manifest": str(good), "expected_sha256": "0" * 64}, "EVIDENCE_INVALID", "MANIFEST_DIGEST_MISMATCH"),
            ("tampered", {"manifest": str(tampered)}, "EVIDENCE_INVALID", None),
            ("missing-artifact", {"manifest": str(missing)}, "EVIDENCE_INCOMPLETE", "INVALID_INPUT"),
            ("missing-manifest", {"manifest": str(workspace / "absent.json")}, "EVIDENCE_INCOMPLETE", "INVALID_INPUT"),
            ("malformed", {"manifest": str(malformed)}, "EVIDENCE_INVALID", "INVALID_INPUT"),
            ("denied-path", {"manifest": "../outside.json"}, "EVIDENCE_INVALID", "PATH_OUTSIDE_WORKSPACE"),
            ("symlink-manifest", {"manifest": str(workspace / "linked.json")}, "EVIDENCE_INVALID", "INVALID_INPUT"),
            ("symlink-artifact", {"manifest": str(linked)}, "EVIDENCE_INVALID", "INVALID_INPUT"),
            ("byte-limit", {"manifest": str(oversized)}, "EVIDENCE_INVALID", "INPUT_LIMIT_EXCEEDED"),
            ("file-limit", {"manifest": str(too_many)}, "EVIDENCE_INVALID", "INPUT_LIMIT_EXCEEDED"),
            ("inventory-path", {"manifest": str(traversal)}, "EVIDENCE_INVALID", "INVALID_INVENTORY"),
            ("invalid-operation", {"manifest": str(good), "operation": "sign"}, "EVIDENCE_INVALID", "INVALID_REQUEST"),
            ("invalid-digest", {"manifest": str(good), "expected_sha256": "invalid"}, "EVIDENCE_INVALID", "INVALID_REQUEST"),
            ("diff-changed", {"manifest": str(good), "operation": "diff", "expected_sha256": digest,
                "comparison_manifest": str(comparison), "comparison_expected_sha256": comparison_digest}, "EVIDENCE_COMPARED", None),
            ("diff-identical", {"manifest": str(good), "operation": "diff", "comparison_manifest": str(good)}, "EVIDENCE_COMPARED", None),
            ("diff-reverse", {"manifest": str(comparison), "operation": "diff", "comparison_manifest": str(good)}, "EVIDENCE_COMPARED", None),
            ("diff-digest-mismatch", {"manifest": str(good), "operation": "diff", "comparison_manifest": str(comparison),
                "comparison_expected_sha256": "0" * 64}, "EVIDENCE_COMPARISON_REJECTED", "COMPARISON_EVIDENCE_REJECTED"),
            ("diff-tampered", {"manifest": str(good), "operation": "diff", "comparison_manifest": str(tampered)}, "EVIDENCE_COMPARISON_REJECTED", "COMPARISON_EVIDENCE_REJECTED"),
            ("diff-missing", {"manifest": str(good), "operation": "diff", "comparison_manifest": str(workspace / "absent.json")}, "EVIDENCE_COMPARISON_REJECTED", "COMPARISON_EVIDENCE_REJECTED"),
            ("diff-denied", {"manifest": str(good), "operation": "diff", "comparison_manifest": "../outside.json"}, "EVIDENCE_COMPARISON_REJECTED", "COMPARISON_EVIDENCE_REJECTED"),
            ("diff-baseline-invalid", {"manifest": str(tampered), "operation": "diff", "comparison_manifest": str(good)}, "EVIDENCE_COMPARISON_REJECTED", "BASELINE_EVIDENCE_REJECTED"),
            ("diff-aggregate-bytes", {"manifest": str(large_left), "operation": "diff", "comparison_manifest": str(large_right)}, "EVIDENCE_COMPARISON_REJECTED", "COMPARISON_EVIDENCE_REJECTED"),
            ("diff-aggregate-files", {"manifest": str(many_left), "operation": "diff", "comparison_manifest": str(many_right)}, "EVIDENCE_COMPARISON_REJECTED", "COMPARISON_EVIDENCE_REJECTED"),
            ("diff-invalid-options", {"manifest": str(good), "operation": "diff"}, "EVIDENCE_INVALID", "INVALID_REQUEST"),
            ("source-match", {"manifest": str(bound), "source": str(source)}, "EVIDENCE_SOURCE_MATCH", None),
            ("source-explain", {"manifest": str(bound), "source": str(source), "operation": "explain"}, "EVIDENCE_SOURCE_MATCH", None),
            ("source-changed", {"manifest": str(bound), "source": str(changed_source)}, "EVIDENCE_SOURCE_CHANGED", None),
            ("source-unsupported", {"manifest": str(good), "source": str(source)}, "EVIDENCE_SOURCE_CHECK_REJECTED", "UNSUPPORTED_SOURCE_BINDING"),
            ("source-conflict", {"manifest": str(conflicting), "source": str(source)}, "EVIDENCE_SOURCE_CHECK_REJECTED", "INCONSISTENT_SOURCE_BINDING"),
            ("source-missing", {"manifest": str(bound), "source": str(workspace / "absent.java")}, "EVIDENCE_SOURCE_CHECK_REJECTED", "INVALID_INPUT"),
            ("source-denied", {"manifest": str(bound), "source": "../outside.java"}, "EVIDENCE_SOURCE_CHECK_REJECTED", "PATH_OUTSIDE_WORKSPACE"),
            ("source-link", {"manifest": str(bound), "source": str(source_link)}, "EVIDENCE_SOURCE_CHECK_REJECTED", "INVALID_INPUT"),
            ("source-byte-limit", {"manifest": str(bound), "source": str(oversized)}, "EVIDENCE_SOURCE_CHECK_REJECTED", "INPUT_LIMIT_EXCEEDED"),
            ("source-file-limit", {"manifest": str(full), "source": str(source)}, "EVIDENCE_SOURCE_CHECK_REJECTED", "INPUT_LIMIT_EXCEEDED"),
            ("source-invalid-options", {"manifest": str(good), "operation": "diff", "comparison_manifest": str(good), "source": str(source)}, "EVIDENCE_INVALID", "INVALID_REQUEST"),
            ("source-invalid-receipt", {"manifest": str(tampered), "source": str(source)}, "EVIDENCE_INVALID", None),
        ]

        def workspace_identity() -> dict:
            return {str(path.relative_to(workspace)): (
                {"link": os.readlink(path)} if path.is_symlink() else
                {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
                for path in workspace.rglob("*") if path.is_symlink() or path.is_file()}

        before = workspace_identity()
        initialized, tools, schema, results = await _call_tool(
            workspace, "inspect_evidence", [case[1] for case in cases])
        if set(schema["properties"]) != {"manifest", "operation", "expected_sha256", "comparison_manifest",
                                         "comparison_expected_sha256", "source"} or schema["required"] != ["manifest"]:
            raise RuntimeError("evidence discovery schema changed")
        comparisons = []
        validated = []
        validated_sources = []
        for (variant, arguments, status, code), result in zip(cases, results):
            if result.get("status") != status or result.get("claim") != "NO_PROOF" or \
                    result.get("request_satisfied") is not (status in {"EVIDENCE_VALID", "EVIDENCE_COMPARED", "EVIDENCE_SOURCE_MATCH"}):
                raise RuntimeError(f"unexpected evidence outcome: {variant}: {result}")
            if code and result.get("code") != code:
                raise RuntimeError(f"evidence rejection changed: {variant}")
            if code != "INVALID_REQUEST":
                dimensions = ("authenticity", "assurance") if "source" in arguments else ("authenticity", "applicability", "assurance")
                if any(result.get(dimension, {}).get("status") != "NOT_ASSESSED" for dimension in dimensions):
                    raise RuntimeError("integrity inspection strengthened an unassessed claim")
                if result["mcp_admission"]["granted_effects"] != ["workspace_read"]:
                    raise RuntimeError("evidence inspection gained non-read authority")
            if status == "EVIDENCE_VALID":
                if result["manifest_sha256"] != digest or result["integrity"]["status"] != "VALID":
                    raise RuntimeError("manifest identity or integrity mismatch")
                if result["request"]["manifest"] != str(good):
                    raise RuntimeError("evidence result refers to a different manifest")
                inventory = json.loads(good.read_bytes())["artifacts"]
                if result["captured_inputs"] != inventory:
                    raise RuntimeError("captured evidence inventory differs from fixture")
                for artifact in inventory:
                    content = (good.parent / artifact["path"]).read_bytes()
                    if len(content) != artifact["size"] or hashlib.sha256(content).hexdigest() != artifact["sha256"]:
                        raise RuntimeError("captured artifact differs from actual bytes")
                validated.append({"variant": variant, "manifest_sha256": digest,
                                  "artifacts": inventory})
            if variant == "explain" and result["explanation"]["recorded_claim"] != "DEDUCTIVE_PROOF":
                raise RuntimeError("explanation lost the recorded (not independently proved) claim")
            if variant == "tampered" and result["integrity"]["status"] != "INVALID":
                raise RuntimeError("tampering was not detected")
            if status == "EVIDENCE_COMPARED":
                for side, path in (("baseline", arguments["manifest"]), ("comparison", arguments["comparison_manifest"])):
                    actual_manifest = Path(path).read_bytes()
                    inventory = json.loads(actual_manifest)["artifacts"]
                    captured = result[side]
                    if not captured["request_satisfied"] or captured["manifest_sha256"] != hashlib.sha256(actual_manifest).hexdigest() \
                            or captured["captured_inputs"] != inventory:
                        raise RuntimeError("diff snapshot identity mismatch")
                    for artifact in inventory:
                        content = (Path(path).parent / artifact["path"]).read_bytes()
                        if len(content) != artifact["size"] or hashlib.sha256(content).hexdigest() != artifact["sha256"]:
                            raise RuntimeError("diff captured artifact differs from actual bytes")
                    validated.append({"variant": variant, "side": side,
                                      "manifest_sha256": captured["manifest_sha256"], "artifacts": inventory})
                changes = result["differences"]
                if variant == "diff-identical" and (not changes["manifest_bytes_equal"] or changes["recorded_terminal_changes"]):
                    raise RuntimeError("identical evidence acquired differences")
                if variant in {"diff-changed", "diff-reverse"}:
                    field = "artifacts_added" if variant == "diff-changed" else "artifacts_removed"
                    if [item["path"] for item in changes[field]] != ["002-proof.json"] or \
                            {item["field"] for item in changes["recorded_terminal_changes"]} != {"claim", "final_status"}:
                        raise RuntimeError("diff omitted recorded claim or inventory changes")
            if status == "EVIDENCE_COMPARISON_REJECTED":
                if "differences" in result or (variant != "diff-baseline-invalid" and not result["baseline"]["request_satisfied"]):
                    raise RuntimeError("rejected diff erased baseline or claimed a comparison")
                if variant in {"diff-aggregate-bytes", "diff-aggregate-files"} and result["comparison"].get("code") != "INPUT_LIMIT_EXCEEDED":
                    raise RuntimeError("diff did not enforce its aggregate budget")
            if status in {"EVIDENCE_SOURCE_MATCH", "EVIDENCE_SOURCE_CHANGED"}:
                content = Path(arguments["source"]).read_bytes()
                actual = result["source_binding"]["captured"]
                if actual["sha256"] != hashlib.sha256(content).hexdigest() or actual["size"] != len(content):
                    raise RuntimeError("source capture digest disagrees with actual bytes")
                if result["manifest_sha256"] != hashlib.sha256(bound.read_bytes()).hexdigest() or not result["integrity"]["valid"]:
                    raise RuntimeError("source check lost the captured receipt identity")
                applicability = result["applicability"]
                if applicability["full_applicability_established"] is not False or applicability["status"] != (
                        "SOURCE_MATCH_ONLY" if status == "EVIDENCE_SOURCE_MATCH" else "SOURCE_CHANGED"):
                    raise RuntimeError("source match was promoted to full applicability")
                if result["recorded_terminal"]["final_status"] != "FAIL":
                    raise RuntimeError("source match changed the recorded failed verification")
                validated_sources.append({"variant": variant, **actual})
            if status == "EVIDENCE_SOURCE_CHECK_REJECTED" and not result["integrity"].get("valid"):
                raise RuntimeError("source rejection erased valid receipt integrity")

            # CLI has explicit local path authority, unlike workspace-scoped MCP.
            # Compare common path semantics, not the intentionally MCP-only denial.
            if variant in {"denied-path", "invalid-operation", "diff-denied", "source-denied"}:
                continue
            command = [sys.executable, "-m", "pipeline.cli", "evidence",
                       arguments.get("operation", "validate"), arguments["manifest"]]
            if "expected_sha256" in arguments:
                command += ["--expected-sha256", arguments["expected_sha256"]]
            if "comparison_manifest" in arguments:
                command += ["--comparison-manifest", arguments["comparison_manifest"]]
            if "comparison_expected_sha256" in arguments:
                command += ["--comparison-expected-sha256", arguments["comparison_expected_sha256"]]
            if "source" in arguments:
                command += ["--source", arguments["source"]]
            command += ["--json"] if variant == "explain" else ["--json", "-"]
            process = await anyio.to_thread.run_sync(lambda: subprocess.run(
                command, cwd=workspace, text=True, capture_output=True, timeout=30, check=False))
            envelope = json.loads(process.stdout)
            expected = {key: value for key, value in result.items() if key != "mcp_admission"}
            if envelope.get("schema") != "formalspecgen-cli-result-v1" or envelope.get("result") != expected \
                    or process.returncode != (0 if result["request_satisfied"] else 1) \
                    or envelope.get("exit_code") != process.returncode \
                    or envelope.get("operation_satisfied") != result["request_satisfied"]:
                raise RuntimeError(f"CLI/MCP evidence semantics differ: {variant}")
            comparisons.append({"variant": variant, "exit_code": process.returncode,
                                "result_sha256": _sha256(expected)})
        if workspace_identity() != before:
            raise RuntimeError("read-only evidence workflow modified its workspace")
    observation = _observation(initialized, tools, schema, results, results[-1])
    observation.update(variants=[case[0] for case in cases], semantic_results=results,
                       cli_comparisons=comparisons, validated_inputs=validated,
                       validated_sources=validated_sources,
                       fixture_scope="Synthetic RunLedger fixtures; no formal backend or signing executed.",
                       workspace_unchanged=True)
    return observation


_ADAPTERS = {
    "evidence": _evidence_observation,
    "inspect": _inspect_observation,
    "document-code": _document_observation,
    "analyze-codebase": _analyze_codebase_observation,
    "generate-traceability-matrix": _traceability_observation,
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
