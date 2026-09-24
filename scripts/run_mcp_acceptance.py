#!/usr/bin/env python3
# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Run declared MCP parity cases and emit revision-bound acceptance evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

from pipeline.parity_inventory import ACCEPTANCE_EVIDENCE_SCHEMA, load_parity_plan
from mcp_acceptance_adapters import collect_transport_observation


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


def _redacted_output(value: str) -> str:
    result = value
    for name, secret in os.environ.items():
        if secret and any(token in name.upper() for token in (
                "API_KEY", "TOKEN", "PASSWORD", "SECRET")):
            result = result.replace(secret, "[REDACTED]")
    return result


def _case_result(
        root: Path, case: dict, revision: str,
        artifacts: Path, index: int) -> dict:
    stem = f"{index:02d}-{case['kind']}"
    junit = artifacts / f"{stem}.junit.xml"
    output = artifacts / f"{stem}.pytest.txt"
    process = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--no-cov",
         str(case["test"]), f"--junitxml={junit}"],
        cwd=root, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False)
    sanitized = _redacted_output(process.stdout)
    output.write_text(sanitized, encoding="utf-8")
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
        "junit_artifact": f"{artifacts.name}/{junit.name}",
        "junit_sha256": (hashlib.sha256(junit.read_bytes()).hexdigest()
                           if junit.is_file() else None),
        "output_artifact": f"{artifacts.name}/{output.name}",
        "output_sha256": hashlib.sha256(sanitized.encode("utf-8")).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", action="append", required=True)
    parser.add_argument(
        "--plan", type=Path, default=Path("mcpdocs/mcp_parity_plan.json"))
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path)
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
    artifacts = (args.artifacts_dir or
                 args.evidence.parent / "mcp-acceptance-artifacts").resolve()
    artifacts.mkdir(parents=True, exist_ok=False)
    commands = []
    failed = False
    for name in args.command:
        declaration = planned.get(name)
        contract = declaration.get("completion_contract") if declaration else None
        if not isinstance(contract, dict):
            parser.error(f"{name} has no completion contract")
        command_artifacts = artifacts / name
        command_artifacts.mkdir()
        cases = [
            _case_result(root, case, revision, command_artifacts, index)
            for index, case in enumerate(contract.get("acceptance_cases", ()), 1)
        ]
        failed = failed or any(case["result"] != "passed" for case in cases)
        observation = (collect_transport_observation(name)
                       if not failed else None)
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
        "case_artifact_directory": artifacts.name,
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
