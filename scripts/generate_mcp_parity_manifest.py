#!/usr/bin/env python3
# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Generate or check the live CLI-to-MCP inventory and completion report."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import mcp_server
from pipeline.parity_inventory import (
    load_parity_plan,
    reconcile_parity_plan,
    render_parity_status,
)


def _handlers() -> dict[str, object]:
    return {
        name: value for name, value in vars(mcp_server).items()
        if callable(value) and not name.startswith("_")
    }


def _outputs(
        plan_path: Path,
        acceptance_evidence_path: Path | None = None) -> tuple[str, str]:
    evidence = (json.loads(acceptance_evidence_path.read_text(encoding="utf-8"))
                if acceptance_evidence_path else None)
    if evidence is not None:
        root = Path(__file__).resolve().parents[1]
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, check=True,
            text=True, stdout=subprocess.PIPE).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=root, check=True, text=True,
            stdout=subprocess.PIPE).stdout.strip()
        if evidence.get("revision") != head:
            raise ValueError("acceptance evidence does not match the checked-out revision")
        if dirty:
            raise ValueError("acceptance evidence requires a clean checked-out revision")
    manifest = reconcile_parity_plan(
        load_parity_plan(plan_path), handlers=_handlers(),
        acceptance_evidence=evidence)
    encoded = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    return encoded, render_parity_status(manifest)


def _check(path: Path, expected: str) -> bool:
    try:
        actual = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return actual == expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan", type=Path, default=Path("mcpdocs/mcp_parity_plan.json"))
    parser.add_argument(
        "--manifest", type=Path, default=Path("docs/mcp_parity_manifest.json"))
    parser.add_argument(
        "--status", type=Path, default=Path("docs/MCP_PARITY_STATUS.md"))
    parser.add_argument("--acceptance-evidence", type=Path)
    parser.add_argument(
        "--require-complete", action="append", default=[], metavar="COMMAND")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    manifest, status = _outputs(args.plan, args.acceptance_evidence)
    parsed = json.loads(manifest)
    completion = {
        item["cli_command"]: item["workflow_completion"]["complete"]
        for item in parsed["command_mappings"]
    }
    missing = [name for name in args.require_complete if not completion.get(name)]
    if missing:
        parser.error(
            "required workflow completion evidence is missing: " + ", ".join(missing))
    if args.check:
        stale = [
            str(path) for path, expected in (
                (args.manifest, manifest), (args.status, status))
            if not _check(path, expected)
        ]
        if stale:
            parser.error(
                "generated MCP parity files are stale: " + ", ".join(stale))
        if not parsed["inventory_complete"]:
            parser.error("MCP parity inventory contains unexplained drift")
        return 0
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.status.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(manifest, encoding="utf-8")
    args.status.write_text(status, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
