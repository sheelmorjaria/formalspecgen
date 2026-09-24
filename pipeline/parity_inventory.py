# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Live CLI inventory and drift checks for the CLI-to-MCP parity programme.

The implementation plan is intentionally external data.  This module records
what the current parser actually accepts, reconciles every declaration by flag
identity, and reports adapter/admission status without treating registration as
workflow completion.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .capability_registry import CAPABILITIES
from .cli import (
    CLI_COMMAND_PLUGIN_ABI,
    CommandPlugin,
    _REPL_COMMANDS,
    build_parser,
)
from .mcp_policy import (
    MCP_ADMISSION_POLICY_VERSION,
    canonical_profile_definition,
)


CLI_INVENTORY_SCHEMA = "formalspecgen-live-cli-inventory-v1"
PARITY_MANIFEST_SCHEMA = "formalspecgen-mcp-parity-manifest-v2"
ACCEPTANCE_EVIDENCE_SCHEMA = "formalspecgen-mcp-acceptance-evidence-v1"
REPL_META_COMMANDS = ("/help", "/session", "/reset", "/quit", "/exit")
COMPATIBILITY_ALIASES = {
    "draft_contract": ("draft_canonical_contract",),
    "macro_dictionary": ("macro_translate",),
}
BASE_ACCEPTANCE_KINDS = frozenset({
    "request_equivalence",
    "argument_delivery",
    "effect_enforcement",
    "result_equivalence",
    "mcp_transport",
})


class ParityInventoryError(ValueError):
    """The supplied target plan cannot account for the live CLI schema."""


def _json_value(value: Any) -> Any:
    if value is argparse.SUPPRESS:
        return "__ARGPARSE_SUPPRESS__"
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return repr(value)


def _action_kind(action: argparse.Action) -> str:
    names = {
        argparse._AppendAction: "append",
        argparse._StoreFalseAction: "store_false",
        argparse._StoreTrueAction: "store_true",
        argparse._StoreConstAction: "store_const",
        argparse._StoreAction: "store",
        argparse._CountAction: "count",
    }
    for action_type, name in names.items():
        if isinstance(action, action_type):
            return name
    return action.__class__.__name__


def _type_name(value: Any) -> str | None:
    if value is None:
        return None
    return getattr(value, "__name__", repr(value))


def _argument_record(action: argparse.Action) -> dict[str, Any]:
    positional = not action.option_strings
    flags = list(action.option_strings) if action.option_strings else [action.dest]
    choices = list(action.choices) if action.choices is not None else []
    record = {
        "flags": flags,
        "dest": action.dest,
        "positional": positional,
        "required": bool(action.required),
        "default": _json_value(action.default),
        "choices": [_json_value(item) for item in choices],
        "nargs": _json_value(action.nargs),
        "const": _json_value(action.const),
        "type": _type_name(action.type),
        "action": _action_kind(action),
        "help": None if action.help is argparse.SUPPRESS else action.help,
        "hidden": action.help is argparse.SUPPRESS,
        "metavar": _json_value(action.metavar),
    }
    if isinstance(action, argparse._VersionAction):
        record["version"] = action.version
    return record


def _subparsers(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:
    matches = [
        action for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    ]
    if len(matches) != 1:
        raise ParityInventoryError("CLI parser must contain exactly one command collection")
    return matches[0]


def inventory_cli(
        plugins: tuple[CommandPlugin, ...] = ()) -> dict[str, Any]:
    """Return a JSON-safe inventory generated from the live argparse parser."""
    parser = build_parser(plugins)
    subparsers = _subparsers(parser)
    plugin_by_command = {
        declaration.command_name: plugin.plugin_id
        for plugin in plugins for declaration in plugin.declarations
    }
    plugin_declarations = {
        declaration.command_name: declaration
        for plugin in plugins for declaration in plugin.declarations
    }
    help_by_command = {
        action.dest: action.help for action in subparsers._choices_actions
    }
    commands = []
    for command_name, command_parser in subparsers.choices.items():
        plugin_declaration = plugin_declarations.get(command_name)
        arguments = [
            _argument_record(action)
            for action in command_parser._actions
            if not isinstance(action, argparse._HelpAction)
        ]
        commands.append({
            "command": command_name,
            "origin": ("plugin" if command_name in plugin_by_command else "builtin"),
            "plugin_id": plugin_by_command.get(command_name),
            "handler_id": (
                plugin_declaration.handler_id if plugin_declaration
                else f"pipeline.cli:dispatch:{command_name}"),
            "human_only": bool(
                plugin_declaration.human_only if plugin_declaration else False),
            "mcp_exposed_intent": bool(
                plugin_declaration.mcp_exposed if plugin_declaration else False),
            "help": help_by_command.get(command_name),
            "description": command_parser.description,
            "arguments": arguments,
        })
    root_arguments = [
        _argument_record(action)
        for action in parser._actions
        if not isinstance(action, (argparse._HelpAction, argparse._SubParsersAction))
    ]
    help_action = next(
        action for action in parser._actions
        if isinstance(action, argparse._HelpAction))
    version_action = next(
        action for action in parser._actions
        if isinstance(action, argparse._VersionAction))
    inventory = {
        "schema": CLI_INVENTORY_SCHEMA,
        "application_version": __version__,
        "plugin_abi": CLI_COMMAND_PLUGIN_ABI,
        "program": parser.prog,
        "description": parser.description,
        "root_interface": {
            "help_flags": list(help_action.option_strings),
            "version_flags": list(version_action.option_strings),
            "version_text": version_action.version,
        },
        "root_arguments": root_arguments,
        "repl": {
            "command_routes": sorted(_REPL_COMMANDS),
            "meta_commands": list(REPL_META_COMMANDS),
            "free_text_route": "draft",
        },
        "plugins": [
            {
                "plugin_id": plugin.plugin_id,
                "commands": [item.command_name for item in plugin.declarations],
            }
            for plugin in plugins
        ],
        "commands": commands,
        "command_count": len(commands),
        "argument_declaration_count": sum(
            len(command["arguments"]) for command in commands),
    }
    inventory["sha256"] = _canonical_sha256(inventory)
    return inventory


def _canonical_sha256(value: Any) -> str:
    payload = deepcopy(value)
    if isinstance(payload, dict):
        payload.pop("sha256", None)
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_parity_plan(path: str | Path) -> dict[str, Any]:
    plan_path = Path(path)
    try:
        value = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ParityInventoryError(f"cannot load parity plan: {exc}") from exc
    if value.get("schema") != "formalspecgen-full-mcp-parity-plan-v1":
        raise ParityInventoryError("unsupported MCP parity-plan schema")
    if not isinstance(value.get("commands"), list):
        raise ParityInventoryError("parity plan commands must be a list")
    return value


def _actual_by_flags(command: dict[str, Any]) -> dict[tuple[str, ...], dict[str, Any]]:
    return {tuple(argument["flags"]): argument for argument in command["arguments"]}


def _expected_semantics(mapping: dict[str, Any]) -> dict[str, Any]:
    baseline = mapping.get("baseline_declaration", {})
    result = {
        "required": bool(baseline.get("required", False)),
        "default": baseline.get("default"),
        "choices": baseline.get("choices", []),
    }
    for key in ("action", "type", "nargs", "const"):
        if key in baseline:
            result[key] = baseline[key]
    return result


def _argument_drift(
        command: str, mapping: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    issues = []
    for key, expected in _expected_semantics(mapping).items():
        observed = actual.get(key)
        if observed != expected:
            issues.append(
                f"{command} {mapping['cli_flags']}: {key} drift "
                f"(live={observed!r}, plan={expected!r})")
    return issues


def _adapter_status(target: str, handler_names: set[str]) -> dict[str, Any]:
    capability = next(
        (item for item in CAPABILITIES if item.mcp_tool == target), None)
    aliases = COMPATIBILITY_ALIASES.get(target, ())
    alias_handlers = sorted(alias for alias in aliases if alias in handler_names)
    if capability and capability.mcp_profiles and target in handler_names:
        return {
            "status": "admitted",
            "profiles": [canonical_profile_definition(profile)
                         for profile in capability.mcp_profiles],
            "compatibility_aliases": alias_handlers,
        }
    if target in handler_names:
        return {
            "status": "adapter_present_not_admitted",
            "profiles": [],
            "compatibility_aliases": alias_handlers,
        }
    trust_capability = next(
        (item for item in CAPABILITIES
         if item.name == target and item.trust_action), None)
    if trust_capability:
        return {
            "status": "approval_coordinator_missing",
            "profiles": [],
            "compatibility_aliases": alias_handlers,
        }
    if alias_handlers:
        return {
            "status": "compatibility_alias_present_target_missing",
            "profiles": [],
            "compatibility_aliases": alias_handlers,
        }
    return {
        "status": "adapter_missing",
        "profiles": [],
        "compatibility_aliases": [],
    }


def handler_input_schema(handler: Any) -> dict[str, Any]:
    """Describe the Python signature that FastMCP turns into tool inputs."""
    signature = inspect.signature(handler)
    fields = []
    for parameter in signature.parameters.values():
        if parameter.kind in {
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD}:
            continue
        annotation = parameter.annotation
        fields.append({
            "name": parameter.name,
            "required": parameter.default is inspect.Parameter.empty,
            "default": (None if parameter.default is inspect.Parameter.empty
                        else _json_value(parameter.default)),
            "annotation": (None if annotation is inspect.Parameter.empty
                           else getattr(annotation, "__name__", str(annotation))),
            "keyword_only": parameter.kind is inspect.Parameter.KEYWORD_ONLY,
        })
    return {"fields": fields, "field_names": [item["name"] for item in fields]}


def _workflow_completion(
        planned: dict[str, Any], adapter: dict[str, Any],
        handler_schema: dict[str, Any] | None, *,
        acceptance_evidence: dict[str, Any] | None = None,
        plan_sha256: str | None = None) -> dict[str, Any]:
    """Evaluate parity from concrete coverage evidence, never admission alone."""
    blockers: list[str] = []
    mapped_fields = sorted({
        mapping.get("proposed_mcp_field")
        for mapping in planned.get("argument_mappings", [])
        if mapping.get("proposed_mcp_field")
    })
    observed_fields = set((handler_schema or {}).get("field_names", ()))
    missing_fields = sorted(set(mapped_fields) - observed_fields)
    unverified_mappings = [
        mapping.get("proposed_mcp_field") or str(mapping.get("cli_flags"))
        for mapping in planned.get("argument_mappings", [])
        if mapping.get("implementation_status") != "verified"
    ]
    if adapter["status"] != "admitted":
        blockers.append("invocation_profile_not_admitted")
    if handler_schema is None:
        blockers.append("mcp_input_schema_not_observed")
    elif missing_fields:
        blockers.append("mapped_inputs_missing_from_mcp_schema")
    if unverified_mappings:
        blockers.append("argument_mappings_not_verified")

    declaration = planned.get("completion_contract")
    required_variants: list[str] = []
    covered_variants: list[str] = []
    evidence_revision = None
    acceptance_cases: list[dict[str, Any]] = []
    transport_observation: dict[str, Any] | None = None
    if not isinstance(declaration, dict):
        blockers.append("completion_contract_missing")
    else:
        required_variants = sorted(set(declaration.get("required_variants", ())))
        expected_cases = [dict(case) for case in declaration.get(
            "acceptance_cases", ()) if isinstance(case, dict)]
        required_kinds = set(BASE_ACCEPTANCE_KINDS)
        workflow_kind = str(planned.get("workflow_kind") or "")
        if "resumable" in workflow_kind:
            required_kinds.add("session_replay")
        if "approval" in workflow_kind or workflow_kind == "read_or_human_approval":
            required_kinds.add("approval_security")
        declared = {
            (str(case.get("kind")), str(case.get("test"))): case
            for case in expected_cases
            if isinstance(case.get("kind"), str)
            and isinstance(case.get("test"), str)
            and "::" in case["test"]
        }
        declared_kinds = {kind for kind, _test in declared}
        if not required_kinds.issubset(declared_kinds):
            blockers.append("required_acceptance_cases_not_declared")

        command_evidence = None
        if not isinstance(acceptance_evidence, dict):
            blockers.append("runner_acceptance_evidence_missing")
        elif acceptance_evidence.get("schema") != ACCEPTANCE_EVIDENCE_SCHEMA:
            blockers.append("runner_acceptance_evidence_invalid")
        elif plan_sha256 and acceptance_evidence.get("plan_sha256") != plan_sha256:
            blockers.append("runner_acceptance_plan_mismatch")
        elif acceptance_evidence.get("workspace_dirty") is not False:
            blockers.append("runner_acceptance_workspace_not_clean")
        else:
            run = acceptance_evidence.get("run")
            if not isinstance(run, dict) or run.get("provider") != "github-actions" \
                    or not run.get("id") or not run.get("attempt"):
                blockers.append("trusted_runner_provenance_missing")
            tree = acceptance_evidence.get("tree")
            if not isinstance(tree, str) or not re.fullmatch(r"[0-9a-f]{40}", tree):
                blockers.append("runner_source_tree_identity_missing")
            evidence_revision = acceptance_evidence.get("revision")
            if not isinstance(evidence_revision, str) or not re.fullmatch(
                    r"[0-9a-f]{40}", evidence_revision):
                blockers.append("revision_bound_acceptance_missing")
            command_evidence = next((
                item for item in acceptance_evidence.get("commands", ())
                if isinstance(item, dict)
                and item.get("cli_command") == planned.get("cli_command")), None)
            if command_evidence is None:
                blockers.append("runner_command_evidence_missing")

        if command_evidence is not None:
            acceptance_cases = [
                dict(case) for case in command_evidence.get("cases", ())
                if isinstance(case, dict)]
            passed = {
                (str(case.get("kind")), str(case.get("test"))): case
                for case in acceptance_cases
                if case.get("result") == "passed"
                and case.get("revision") == evidence_revision
                and isinstance(case.get("output_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", case["output_sha256"])
                and isinstance(case.get("junit_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", case["junit_sha256"])
                and isinstance(case.get("junit"), dict)
                and isinstance(case["junit"].get("tests"), int)
                and case["junit"]["tests"] > 0
                and all(isinstance(case["junit"].get(name), int)
                        and case["junit"][name] == 0
                        for name in ("failures", "errors", "skipped"))
            }
            variant_mismatches = [
                key for key, case in passed.items() if key in declared
                and set(case.get("variants", ())) !=
                set(declared[key].get("variants", ()))
            ]
            if variant_mismatches:
                blockers.append("acceptance_case_variant_mismatch")
            passed_kinds = {
                kind for (kind, test) in declared
                if (kind, test) in passed
                and (kind, test) not in variant_mismatches
            }
            covered_variants = sorted({
                str(variant)
                for key, case in passed.items()
                if key in declared and key not in variant_mismatches
                for variant in case.get("variants", ())
            })
            transport = command_evidence.get("transport_observation")
            if not isinstance(transport, dict) or not all(
                    isinstance(transport.get(field), str)
                    and re.fullmatch(r"[0-9a-f]{64}", transport[field])
                    for field in ("schema_sha256", "result_sha256")):
                blockers.append("transport_observation_missing")
            else:
                transport_observation = dict(transport)
        else:
            passed_kinds = set()
        if not required_kinds.issubset(passed_kinds):
            blockers.append("required_acceptance_cases_missing_or_unpassed")
        if not required_variants or not set(required_variants).issubset(
                covered_variants):
            blockers.append("workflow_variants_incomplete")

    complete = not blockers
    return {
        "status": "complete" if complete else "incomplete",
        "complete": complete,
        "mapped_mcp_fields": mapped_fields,
        "observed_mcp_fields": sorted(observed_fields),
        "missing_mcp_fields": missing_fields,
        "unverified_argument_mappings": unverified_mappings,
        "required_variants": required_variants,
        "covered_variants": covered_variants,
        "evidence_revision": evidence_revision,
        "acceptance_cases": acceptance_cases,
        "transport_observation": transport_observation,
        "blockers": blockers,
    }


def reconcile_parity_plan(
        plan: dict[str, Any], *, plugins: tuple[CommandPlugin, ...] = (),
        handler_names: Iterable[str] = (),
        handlers: dict[str, Any] | None = None,
        acceptance_evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    """Bind a target plan to the current parser and report every drift."""
    inventory = inventory_cli(plugins)
    live_commands = {item["command"]: item for item in inventory["commands"]}
    planned_commands = {item.get("cli_command"): item for item in plan["commands"]}
    issues: list[str] = []
    if None in planned_commands:
        issues.append("parity plan contains a command without cli_command")
        planned_commands.pop(None, None)
    duplicate_count = len(plan["commands"]) - len(planned_commands)
    if duplicate_count:
        issues.append(f"parity plan contains {duplicate_count} duplicate command(s)")
    for missing in sorted(set(live_commands) - set(planned_commands)):
        issues.append(f"live CLI command is unmapped: {missing}")
    for stale in sorted(set(planned_commands) - set(live_commands)):
        issues.append(f"planned CLI command is absent from live parser: {stale}")

    command_mappings = []
    mapped_arguments = 0
    admitted_commands = 0
    handler_values = handlers or {}
    known_handlers = set(handler_names) | set(handler_values)
    complete_commands = 0
    plan_sha256 = _canonical_sha256(plan)
    for command_name in sorted(set(live_commands) & set(planned_commands)):
        live = live_commands[command_name]
        planned = planned_commands[command_name]
        actual_arguments = _actual_by_flags(live)
        planned_arguments: dict[tuple[str, ...], dict[str, Any]] = {}
        for mapping in planned.get("argument_mappings", []):
            flags = tuple(mapping.get("cli_flags", ()))
            if not flags:
                issues.append(f"{command_name}: mapping without cli_flags")
            elif flags in planned_arguments:
                issues.append(f"{command_name}: duplicate mapping for {list(flags)}")
            else:
                planned_arguments[flags] = mapping
        for flags in sorted(set(actual_arguments) - set(planned_arguments)):
            issues.append(f"{command_name}: live argument is unmapped: {list(flags)}")
        for flags in sorted(set(planned_arguments) - set(actual_arguments)):
            issues.append(f"{command_name}: planned argument is absent: {list(flags)}")
        mapped = []
        for flags in sorted(set(actual_arguments) & set(planned_arguments)):
            actual = actual_arguments[flags]
            mapping = planned_arguments[flags]
            issues.extend(_argument_drift(command_name, mapping, actual))
            mapped.append({
                "cli": actual,
                "mcp_field": mapping.get("proposed_mcp_field"),
                "disposition": mapping.get("disposition"),
                "requirement": mapping.get("requirement"),
            })
        mapped_arguments += len(mapped)
        target = planned.get("proposed_mcp_tool")
        target_capability = next(
            (item for item in CAPABILITIES
             if item.mcp_tool == target or
             (item.trust_action and item.name == target)), None)
        if target_capability and target_capability.cli_command != command_name:
            issues.append(
                f"{command_name}: capability registry CLI mapping drift "
                f"(registry={target_capability.cli_command!r}, target={target!r})")
        adapter = _adapter_status(target, known_handlers)
        if adapter["status"] == "admitted":
            admitted_commands += 1
        schema = (handler_input_schema(handler_values[target])
                  if target in handler_values else None)
        completion = _workflow_completion(
            planned, adapter, schema,
            acceptance_evidence=acceptance_evidence,
            plan_sha256=plan_sha256)
        if completion["complete"]:
            complete_commands += 1
        command_mappings.append({
            "cli_command": command_name,
            "target_mcp_tool": target,
            "workflow_kind": planned.get("workflow_kind"),
            "requirements": planned.get("requirements"),
            "origin": live["origin"],
            "plugin_id": live["plugin_id"],
            "arguments": mapped,
            "adapter": adapter,
            "mcp_input_schema": schema,
            "workflow_completion": completion,
        })

    plan_declared_count = sum(
        len(command.get("argument_mappings", [])) for command in plan["commands"])
    if plan.get("baseline_command_count") != len(plan["commands"]):
        issues.append("plan baseline_command_count does not match its command list")
    if plan.get("baseline_argument_declaration_count") != plan_declared_count:
        issues.append(
            "plan baseline_argument_declaration_count does not match its mappings")
    manifest = {
        "schema": PARITY_MANIFEST_SCHEMA,
        "application_version": __version__,
        "admission_policy_version": MCP_ADMISSION_POLICY_VERSION,
        "plan_schema": plan.get("schema"),
        "plan_baseline_revision": plan.get("baseline_revision"),
        "plan_sha256": plan_sha256,
        "completion_policy": {
            "principle": "admission_is_not_workflow_completion",
            "required_acceptance_kinds": sorted(BASE_ACCEPTANCE_KINDS),
            "additional_resumable_kind": "session_replay",
            "additional_approval_kind": "approval_security",
            "acceptance_evidence_schema": ACCEPTANCE_EVIDENCE_SCHEMA,
            "requires_runner_produced_acceptance_evidence": True,
            "requires_revision_bound_pass_results": True,
            "requires_complete_variant_coverage": True,
            "requires_verified_argument_mappings": True,
            "requires_observed_mcp_input_fields": True,
        },
        "acceptance_evidence": ({
            "revision": acceptance_evidence.get("revision"),
            "tree": acceptance_evidence.get("tree"),
            "plan_sha256": acceptance_evidence.get("plan_sha256"),
            "workspace_dirty": acceptance_evidence.get("workspace_dirty"),
            "run": acceptance_evidence.get("run"),
            "sha256": _canonical_sha256(acceptance_evidence),
        } if isinstance(acceptance_evidence, dict) else None),
        "inventory": inventory,
        "metrics": {
            "discovered_commands": inventory["command_count"],
            "mapped_commands": len(command_mappings),
            "discovered_argument_declarations": inventory[
                "argument_declaration_count"],
            "mapped_argument_declarations": mapped_arguments,
            "commands_with_admitted_profile": admitted_commands,
            "complete_workflow_commands": complete_commands,
        },
        "command_mappings": command_mappings,
        "issues": issues,
        "inventory_complete": not issues,
        "full_workflow_parity_complete": (
            not issues and complete_commands == inventory["command_count"]),
    }
    manifest["sha256"] = _canonical_sha256(manifest)
    return manifest


def render_parity_status(manifest: dict[str, Any]) -> str:
    """Generate the human-readable completion report from the same manifest."""
    metrics = manifest["metrics"]
    lines = [
        "# MCP parity status",
        "",
        "This file is generated from the live CLI parser and `mcpdocs/mcp_parity_plan.json`.",
        "Do not edit it by hand.",
        "",
        "## Inventory",
        "",
        f"- Commands mapped: {metrics['mapped_commands']} / "
        f"{metrics['discovered_commands']}",
        f"- Argument declarations mapped: "
        f"{metrics['mapped_argument_declarations']} / "
        f"{metrics['discovered_argument_declarations']}",
        f"- Commands with at least one admitted invocation profile: "
        f"{metrics['commands_with_admitted_profile']} / "
        f"{metrics['discovered_commands']}",
        f"- Complete command workflows: "
        f"{metrics['complete_workflow_commands']} / "
        f"{metrics['discovered_commands']}",
        f"- Inventory drift: {'none' if manifest['inventory_complete'] else 'detected'}",
        f"- Full workflow parity: "
        f"{'complete' if manifest['full_workflow_parity_complete'] else 'in progress'}",
        "",
        "## Per-command status",
        "",
        "| CLI command | Target MCP tool | Workflow | Admission | Completion | Arguments |",
        "| --- | --- | --- | --- | --- | ---: |",
    ]
    for command in manifest["command_mappings"]:
        lines.append(
            f"| `{command['cli_command']}` | `{command['target_mcp_tool']}` | "
            f"`{command['workflow_kind']}` | `{command['adapter']['status']}` | "
            f"`{command['workflow_completion']['status']}` | "
            f"{len(command['arguments'])} |")
    lines.extend(["", "## Drift", ""])
    if manifest["issues"]:
        lines.extend(f"- {issue}" for issue in manifest["issues"])
    else:
        lines.append("No command or argument drift detected.")
    lines.append("")
    return "\n".join(lines)
