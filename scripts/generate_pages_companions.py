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

import mcp_server
from pipeline.capability_registry import mcp_capabilities
from pipeline.mcp_policy import (
    MCP_ADMISSION_POLICY_VERSION,
    canonical_profile_definition,
    profile_definition_sha256,
)
from pipeline.parity_inventory import handler_input_schema, reconcile_parity_plan


GUIDE_INVENTORY_SCHEMA = "formalspecgen-guide-command-inventory-v2"
GUIDE_CAPABILITIES_SCHEMA = "formalspecgen-guide-mcp-capabilities-v1"


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


def _handlers() -> dict[str, object]:
    return {
        name: value for name, value in vars(mcp_server).items()
        if callable(value) and not name.startswith("_")
    }


def _inventory(plan: dict, handlers: dict[str, object]) -> dict:
    parity = reconcile_parity_plan(plan, handlers=handlers)
    commands = [{
        "cli_command": item["cli_command"],
        "mcp_tool": item["target_mcp_tool"],
        "workflow_kind": item["workflow_kind"],
        "admission_status": item["adapter"]["status"],
        "completion_status": item["workflow_completion"]["status"],
        "argument_declarations": item["arguments"],
    } for item in parity["command_mappings"]]
    return {
        "schema": GUIDE_INVENTORY_SCHEMA,
        "application_version": parity["application_version"],
        "plan_baseline_revision": parity["plan_baseline_revision"],
        "scope": (
            "Generated live CLI inventory and static admission view; "
            "revision-bound completion requires CI acceptance evidence."),
        "command_count": len(commands),
        "argument_declaration_count": sum(
            len(command["argument_declarations"]) for command in commands),
        "commands_with_admitted_profile": parity["metrics"][
            "commands_with_admitted_profile"],
        "commands_complete_without_ci_evidence": parity["metrics"][
            "complete_workflow_commands"],
        "inventory_complete": parity["inventory_complete"],
        "commands": commands,
        "provenance": {
            "inventory_schema": parity["inventory"]["schema"],
            "inventory_sha256": parity["inventory"]["sha256"],
            "plugin_abi": parity["inventory"]["plugin_abi"],
        },
    }


def _capabilities(handlers: dict[str, object]) -> dict:
    capabilities = []
    for capability in mcp_capabilities(strict_isolation=True):
        handler = handlers.get(str(capability.mcp_tool))
        capabilities.append({
            "name": capability.name,
            "mcp_tool": capability.mcp_tool,
            "cli_command": capability.cli_command,
            "description": capability.description,
            "isolation": capability.mcp_isolation,
            "catalogue": "cli-and-mcp" if capability.cli_command else "mcp-only",
            "static_input_schema": (
                handler_input_schema(handler) if handler is not None else None),
            "profiles": [{
                **canonical_profile_definition(profile),
                "profile_sha256": profile_definition_sha256(profile),
            } for profile in capability.mcp_profiles],
        })
    return {
        "schema": GUIDE_CAPABILITIES_SCHEMA,
        "admission_policy_version": MCP_ADMISSION_POLICY_VERSION,
        "scope": (
            "Strict catalogue generated from the capability registry and "
            "Python handlers. Runtime MCP discovery is tested separately."),
        "capability_count": len(capabilities),
        "cli_capability_count": sum(
            item["cli_command"] is not None for item in capabilities),
        "mcp_only_capability_count": sum(
            item["cli_command"] is None for item in capabilities),
        "capabilities": capabilities,
    }


def _guide_validation(
        guide: Path, inventory_bytes: bytes, capabilities_bytes: bytes,
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
        "This record describes preparation of the current static GitHub Pages edition. It is",
        "documentation validation, not formal verification or revision-bound acceptance evidence.",
        "",
        "## Checked publication inputs",
        "",
        f"- `index.html` SHA-256: `{_sha256(guide_bytes)}`",
        f"- `command_inventory.json` SHA-256: `{_sha256(inventory_bytes)}`",
        f"- `mcp_capabilities.json` SHA-256: `{_sha256(capabilities_bytes)}`",
        f"- Parsed HTML element IDs: {len(parser.ids)}",
        f"- Same-page fragment links checked: {len(fragment_links)}",
        "- Missing same-page targets: none",
        "- Duplicate element IDs: none",
        "- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,",
        "  `VALIDATION.md`, and the archived `91c6790` guide",
        "- Unexpected relative assets: none",
        "",
        "## Scope limits",
        "",
        "- External URLs were retained but not fetched as part of publication validation.",
        "- No compiler, verifier, generated program, provider, or MCP transport was run.",
        "- Static handler schemas do not replace runtime MCP discovery acceptance.",
        "- Completion claims must be checked against the linked revision-bound CI evidence.",
        "",
    ])


def _expected(plan_path: Path, site: Path) -> tuple[bytes, bytes, str]:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("schema") != "formalspecgen-full-mcp-parity-plan-v1":
        raise ValueError("unsupported parity-plan schema")
    handlers = _handlers()
    inventory = _inventory(plan, handlers)
    capabilities = _capabilities(handlers)
    if inventory["command_count"] != plan["baseline_command_count"]:
        raise ValueError("guide command count does not match its pinned plan")
    if inventory["argument_declaration_count"] != \
            plan["baseline_argument_declaration_count"]:
        raise ValueError("guide argument count does not match its pinned plan")
    inventory_bytes = (
        json.dumps(inventory, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    capabilities_bytes = (
        json.dumps(capabilities, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    validation = _guide_validation(
        site / "index.html", inventory_bytes, capabilities_bytes,
        {"archive/91c6790/", "command_inventory.json",
         "mcp_capabilities.json", "VALIDATION.md"})
    return inventory_bytes, capabilities_bytes, validation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan", type=Path, default=Path("mcpdocs/mcp_parity_plan.json"))
    parser.add_argument("--site", type=Path, default=Path("site"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    inventory, capabilities, validation = _expected(args.plan, args.site)
    outputs = {
        args.site / "command_inventory.json": inventory,
        args.site / "mcp_capabilities.json": capabilities,
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
