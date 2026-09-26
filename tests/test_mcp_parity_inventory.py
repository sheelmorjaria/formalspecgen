# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Live CLI inventory and MCP parity-plan drift tests."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path

import mcp_server
from pipeline import __version__
from pipeline.cli import (
    ArgumentDeclaration,
    CLI_COMMAND_PLUGIN_ABI,
    CommandDeclaration,
    CommandPlugin,
)
from pipeline.parity_inventory import (
    CLI_INVENTORY_SCHEMA,
    PARITY_MANIFEST_SCHEMA,
    inventory_cli,
    load_parity_plan,
    reconcile_parity_plan,
    render_parity_status,
)


ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "mcpdocs" / "mcp_parity_plan.json"


def _handlers() -> dict[str, object]:
    return {
        name: value for name, value in vars(mcp_server).items()
        if callable(value) and not name.startswith("_")
    }


def test_live_builtin_inventory_matches_every_planned_declaration():
    manifest = reconcile_parity_plan(
        load_parity_plan(PLAN), handlers=_handlers())
    assert manifest["schema"] == PARITY_MANIFEST_SCHEMA
    assert manifest["inventory"]["schema"] == CLI_INVENTORY_SCHEMA
    assert manifest["inventory_complete"] is True
    assert manifest["issues"] == []
    assert manifest["metrics"] == {
        "discovered_commands": 38,
        "mapped_commands": 38,
        "discovered_argument_declarations": 205,
        "mapped_argument_declarations": 205,
        "commands_with_admitted_profile": 4,
        "complete_workflow_commands": 0,
    }
    assert manifest["full_workflow_parity_complete"] is False


def test_inventory_records_root_repl_hidden_and_inherited_semantics():
    inventory = inventory_cli()
    assert inventory["root_interface"] == {
        "help_flags": ["-h", "--help"],
        "version_flags": ["--version"],
        "version_text": f"formalspecgen {__version__}",
    }
    assert inventory["repl"]["free_text_route"] == "draft"
    assert "/reset" in inventory["repl"]["meta_commands"]
    commands = {item["command"]: item for item in inventory["commands"]}
    system = {tuple(item["flags"]): item for item in commands["system"]["arguments"]}
    assert system[("--executable",)]["hidden"] is True
    assert system[("--executable",)]["default"] == "formalspecgen"
    draft = {tuple(item["flags"]): item for item in commands["draft"]["arguments"]}
    assert draft[("--provider",)]["choices"] == ["glm", "openai", "ollama"]
    assert draft[("--provider",)]["default"] == "ollama"
    assert draft[("--model",)]["default"] is None


def test_committed_manifest_and_status_are_generated_from_live_inventory():
    manifest = reconcile_parity_plan(
        load_parity_plan(PLAN), handlers=_handlers())
    expected_json = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    assert (ROOT / "docs/mcp_parity_manifest.json").read_text(
        encoding="utf-8") == expected_json
    assert (ROOT / "docs/MCP_PARITY_STATUS.md").read_text(
        encoding="utf-8") == render_parity_status(manifest)


def test_drift_is_reported_for_missing_argument_and_changed_default():
    plan = load_parity_plan(PLAN)
    changed = deepcopy(plan)
    verify = next(
        command for command in changed["commands"]
        if command["cli_command"] == "verify")
    verify["argument_mappings"] = [
        mapping for mapping in verify["argument_mappings"]
        if mapping["cli_flags"] != ["--backend"]
    ]
    mode = next(
        mapping for mapping in verify["argument_mappings"]
        if mapping["cli_flags"] == ["--mode"])
    mode["baseline_declaration"]["default"] = "parse"
    changed["baseline_argument_declaration_count"] -= 1
    result = reconcile_parity_plan(changed, handlers=_handlers())
    assert result["inventory_complete"] is False
    assert any("live argument is unmapped: ['--backend']" in issue
               for issue in result["issues"])
    assert any("default drift" in issue for issue in result["issues"])


def _plugin_handler(_args: argparse.Namespace) -> int:
    return 0


def _plugin() -> CommandPlugin:
    return CommandPlugin(
        abi_id=CLI_COMMAND_PLUGIN_ABI,
        plugin_id="approved.example.v1",
        declarations=(CommandDeclaration(
            capability_name="approved_example",
            command_name="approved-example",
            handler_id="approved.example:run",
            handler=_plugin_handler,
            arguments=(ArgumentDeclaration(
                ("--limit",), {"type": int, "default": 2}),),
        ),),
    )


def test_approved_plugin_requires_and_accepts_an_explicit_plan_mapping():
    plugin = _plugin()
    base = load_parity_plan(PLAN)
    missing = reconcile_parity_plan(base, plugins=(plugin,), handlers=_handlers())
    assert any("live CLI command is unmapped: approved-example" in issue
               for issue in missing["issues"])

    extended = deepcopy(base)
    extended["commands"].append({
        "cli_command": "approved-example",
        "proposed_mcp_tool": "approved_example",
        "workflow_kind": "direct",
        "requirements": "Operator-approved example plugin.",
        "argument_mappings": [{
            "cli_flags": ["--limit"],
            "proposed_mcp_field": "limit",
            "disposition": "bounded_parameter",
            "requirement": "Retain the approved limit.",
            "baseline_declaration": {
                "flags": ["--limit"], "type": "int", "default": 2,
                "required": False,
            },
        }],
    })
    extended["baseline_command_count"] += 1
    extended["baseline_argument_declaration_count"] += 1
    mapped = reconcile_parity_plan(
        extended, plugins=(plugin,), handlers=_handlers())
    assert mapped["inventory_complete"] is True
    plugin_record = next(
        item for item in mapped["command_mappings"]
        if item["cli_command"] == "approved-example")
    assert plugin_record["origin"] == "plugin"
    assert plugin_record["plugin_id"] == "approved.example.v1"


def test_invalid_plan_schema_fails_closed(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text('{"schema":"unknown","commands":[]}', encoding="utf-8")
    try:
        load_parity_plan(path)
    except ValueError as exc:
        assert "unsupported" in str(exc)
    else:
        raise AssertionError("unknown parity schema must be rejected")
