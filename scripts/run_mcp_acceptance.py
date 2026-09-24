#!/usr/bin/env python3
# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Run declared MCP parity cases and emit revision-bound acceptance evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

import mcp_server
from pipeline.parity_inventory import ACCEPTANCE_EVIDENCE_SCHEMA, load_parity_plan


def _sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=root, check=True,
        text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE).stdout.strip()


def _case_result(root: Path, case: dict, revision: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="formalspecgen-acceptance-") as directory:
        junit = Path(directory) / "junit.xml"
        process = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--no-cov",
             str(case["test"]), f"--junitxml={junit}"],
            cwd=root, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False)
        counts = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
        if junit.is_file():
            document = ElementTree.parse(junit).getroot()
            suites = ([document] if document.tag == "testsuite"
                      else list(document.findall(".//testsuite")))
            for name in counts:
                counts[name] = sum(int(suite.get(name, "0")) for suite in suites)
        passed = (
            process.returncode == 0 and counts["tests"] > 0
            and counts["failures"] == counts["errors"] == counts["skipped"] == 0)
        return {
            "kind": case["kind"],
            "test": case["test"],
            "variants": sorted(set(case.get("variants", ()))),
            "result": "passed" if passed else "failed",
            "revision": revision,
            "exit_code": process.returncode,
            "junit": counts,
            "output_sha256": hashlib.sha256(
                process.stdout.encode("utf-8")).hexdigest(),
        }


async def _inspect_transport_observation() -> dict:
    with tempfile.TemporaryDirectory(prefix="formalspecgen-mcp-transport-") as directory:
        workspace = Path(directory)
        (workspace / "Probe.java").write_text(
            "public class Probe { public int value() { return 1; } }\n",
            encoding="utf-8")
        previous = Path.cwd()
        os.chdir(workspace)
        try:
            parameters = StdioServerParameters(
                command=sys.executable,
                args=[str(Path(mcp_server.__file__).resolve())],
                cwd=str(workspace), env=dict(os.environ))
            with anyio.fail_after(30):
                async with stdio_client(parameters) as (read, write):
                    async with ClientSession(read, write) as session:
                        initialized = await session.initialize()
                        tools = await session.list_tools()
                        tool = next(item for item in tools.tools
                                    if item.name == "inspect_code")
                        response = await session.call_tool(
                            "inspect_code", {"source": "Probe.java"})
                        if response.isError or not isinstance(
                                response.structuredContent, dict):
                            raise RuntimeError("inspect_code MCP transport call failed")
                        result = response.structuredContent
        finally:
            os.chdir(previous)
    schema = tool.inputSchema
    semantic_result = {
        key: result.get(key) for key in (
            "status", "claim", "scope", "parser_mode", "source_sha256",
            "class", "metrics", "findings")
    }
    return {
        "transport": "mcp-stdio-subprocess",
        "mcp_sdk_version": importlib.metadata.version("mcp"),
        "server": initialized.serverInfo.model_dump(mode="json"),
        "discovered_tools": sorted(item.name for item in tools.tools),
        "input_schema": schema,
        "schema_sha256": _sha256(schema),
        "result_sha256": _sha256(semantic_result),
        "result_status": result.get("status"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", action="append", required=True)
    parser.add_argument(
        "--plan", type=Path, default=Path("mcpdocs/mcp_parity_plan.json"))
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    plan = load_parity_plan(args.plan)
    revision = _git(root, "rev-parse", "HEAD")
    expected_revision = os.environ.get("GITHUB_SHA")
    if expected_revision and expected_revision != revision:
        parser.error("GITHUB_SHA does not match the checked-out revision")
    dirty = bool(_git(root, "status", "--porcelain", "--untracked-files=all"))
    plan_sha256 = _sha256(plan)
    planned = {item["cli_command"]: item for item in plan["commands"]}
    commands = []
    failed = False
    for name in args.command:
        declaration = planned.get(name)
        contract = declaration.get("completion_contract") if declaration else None
        if not isinstance(contract, dict):
            parser.error(f"{name} has no completion contract")
        cases = [
            _case_result(root, case, revision)
            for case in contract.get("acceptance_cases", ())
        ]
        failed = failed or any(case["result"] != "passed" for case in cases)
        observation = (anyio.run(_inspect_transport_observation)
                       if name == "inspect" and not failed else None)
        commands.append({
            "cli_command": name,
            "required_variants": sorted(set(contract.get("required_variants", ()))),
            "cases": cases,
            "transport_observation": observation,
        })
    evidence = {
        "schema": ACCEPTANCE_EVIDENCE_SCHEMA,
        "revision": revision,
        "tree": _git(root, "rev-parse", "HEAD^{tree}"),
        "workspace_dirty": dirty,
        "plan_sha256": plan_sha256,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run": {
            "provider": "github-actions" if os.environ.get("GITHUB_ACTIONS") else "local",
            "id": os.environ.get("GITHUB_RUN_ID"),
            "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
        },
        "commands": commands,
    }
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")
    print(json.dumps({
        "evidence": str(args.evidence), "revision": revision,
        "workspace_dirty": dirty,
        "passed": not failed,
        "commands": args.command,
    }, sort_keys=True))
    return 1 if failed or dirty else 0


if __name__ == "__main__":
    raise SystemExit(main())
