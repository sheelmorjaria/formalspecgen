#!/usr/bin/env python3
# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Generate and validate the pinned user-guide companion files."""

from __future__ import annotations

import argparse
import hashlib
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


GUIDE_INVENTORY_SCHEMA = "formalspecgen-guide-command-inventory-v1"


class _GuideLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.hrefs: list[str] = []
        self.sources: list[str] = []

    def handle_starttag(
            self, _tag: str,
            attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(str(values["id"]))
        if values.get("href"):
            self.hrefs.append(str(values["href"]))
        if values.get("src"):
            self.sources.append(str(values["src"]))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _inventory(plan: dict) -> dict:
    commands = []
    for command in plan["commands"]:
        arguments = []
        for mapping in command.get("argument_mappings", []):
            arguments.append({
                "cli_flags": mapping["cli_flags"],
                "mcp_field": mapping.get("proposed_mcp_field"),
                "disposition": mapping.get("disposition"),
                "declaration": mapping.get("baseline_declaration", {}),
            })
        commands.append({
            "cli_command": command["cli_command"],
            "workflow_kind": command.get("workflow_kind"),
            "strict_mcp_availability": command.get("baseline_strict_mcp"),
            "argument_declarations": arguments,
        })
    return {
        "schema": GUIDE_INVENTORY_SCHEMA,
        "guide_revision": plan["baseline_revision"],
        "scope": "Pinned user-guide edition; not the moving runtime policy.",
        "command_count": len(commands),
        "argument_declaration_count": sum(
            len(command["argument_declarations"]) for command in commands),
        "commands_with_admitted_subset": sum(
            command["strict_mcp_availability"] == "Admitted subset"
            for command in commands),
        "commands": commands,
        "provenance": plan.get("inventory_provenance", {}),
    }


def _guide_validation(
        guide: Path, inventory_bytes: bytes,
        expected_local_files: set[str]) -> str:
    guide_bytes = guide.read_bytes()
    parser = _GuideLinks()
    parser.feed(guide_bytes.decode("utf-8"))
    parser.close()
    ids = set(parser.ids)
    duplicate_ids = sorted({item for item in parser.ids if parser.ids.count(item) > 1})
    fragment_links = [href for href in parser.hrefs if href.startswith("#")]
    missing_fragments = sorted({
        href for href in fragment_links if href[1:] not in ids
    })
    local_links = sorted({
        urlparse(value).path
        for value in parser.hrefs + parser.sources
        if urlparse(value).scheme == "" and not value.startswith("#")
        and urlparse(value).path
    })
    unexpected_local = sorted(set(local_links) - expected_local_files)
    missing_local = sorted(expected_local_files - set(local_links))
    if duplicate_ids:
        raise ValueError("duplicate HTML ids: " + ", ".join(duplicate_ids))
    if missing_fragments:
        raise ValueError("unresolved same-page links: " + ", ".join(missing_fragments))
    if unexpected_local or missing_local:
        raise ValueError(
            f"guide local-link drift: unexpected={unexpected_local}, missing={missing_local}")
    return "\n".join([
        "# Published guide validation",
        "",
        "This record describes preparation of the static GitHub Pages edition. It is not formal",
        "verification evidence and does not update the guide beyond its pinned `91c6790` scope.",
        "",
        "## Checked publication inputs",
        "",
        f"- `index.html` SHA-256: `{_sha256(guide_bytes)}`",
        f"- `command_inventory.json` SHA-256: `{_sha256(inventory_bytes)}`",
        f"- Parsed HTML element IDs: {len(parser.ids)}",
        f"- Same-page fragment links checked: {len(fragment_links)}",
        "- Missing same-page targets: none",
        "- Duplicate element IDs: none",
        "- Linked publication files: `command_inventory.json`, `VALIDATION.md`",
        "- Unexpected relative assets: none",
        "",
        "## Scope limits",
        "",
        "- External URLs were retained but not fetched as part of publication validation.",
        "- No compiler, verifier, generated program, provider, or MCP server was run.",
        "- The guide remains an offline documentation edition pinned to `91c6790`; newer runtime",
        "  behavior must be checked against the current repository and generated parity report.",
        "",
    ])


def _expected(plan_path: Path, site: Path) -> tuple[bytes, str]:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("schema") != "formalspecgen-full-mcp-parity-plan-v1":
        raise ValueError("unsupported parity-plan schema")
    inventory = _inventory(plan)
    if inventory["command_count"] != plan["baseline_command_count"]:
        raise ValueError("guide command count does not match its pinned plan")
    if inventory["argument_declaration_count"] != \
            plan["baseline_argument_declaration_count"]:
        raise ValueError("guide argument count does not match its pinned plan")
    inventory_bytes = (
        json.dumps(inventory, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    validation = _guide_validation(
        site / "index.html", inventory_bytes,
        {"command_inventory.json", "VALIDATION.md"})
    return inventory_bytes, validation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan", type=Path, default=Path("mcpdocs/mcp_parity_plan.json"))
    parser.add_argument("--site", type=Path, default=Path("site"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    inventory, validation = _expected(args.plan, args.site)
    outputs = {
        args.site / "command_inventory.json": inventory,
        args.site / "VALIDATION.md": validation.encode("utf-8"),
    }
    if args.check:
        stale = [str(path) for path, expected in outputs.items()
                 if not path.is_file() or path.read_bytes() != expected]
        if stale:
            parser.error("generated Pages companions are stale: " + ", ".join(stale))
        return 0
    args.site.mkdir(parents=True, exist_ok=True)
    for path, content in outputs.items():
        path.write_bytes(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
