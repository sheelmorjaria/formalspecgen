#!/usr/bin/env python3
# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Generate and validate the pinned user-guide companion files."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
from html import escape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlparse

import mcp_server
from pipeline.capability_registry import mcp_capabilities
from pipeline.evidence_consumer import EvidenceWorkflowRequest
from pipeline.capability_discovery import CapabilityDiscoveryRequest
from pipeline.agentic.run_reader import RunReadRequest
from pipeline.worker_queries import WorkerArtifactsRequest
from pipeline.project_planning import ProjectWorkflowRequest
from pipeline.mcp_policy import (
    MCP_ADMISSION_POLICY_VERSION,
    canonical_profile_definition,
    profile_definition_sha256,
)
from pipeline.parity_inventory import handler_input_schema, reconcile_parity_plan
from pipeline.workflow_contracts import (
    BisimulationWorkflowRequest,
    SecurityTemplateWorkflowRequest,
    ApplyRefactorWorkflowRequest,
    CodebaseAnalysisWorkflowRequest,
    TraceabilityWorkflowRequest,
    VerificationWorkflowRequest,
)


GUIDE_INVENTORY_SCHEMA = "formalspecgen-guide-command-inventory-v2"
GUIDE_CAPABILITIES_SCHEMA = "formalspecgen-guide-mcp-capabilities-v1"


class _GuideLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.hrefs: list[str] = []
        self.sources: list[str] = []
        self.examples: dict[str, str] = {}
        self.cli_examples: dict[str, str] = {}
        self._example_kind = "mcp"
        self._example_name: str | None = None
        self._example_parts: list[str] = []

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
        if values.get("data-workflow-example") or values.get("data-cli-example"):
            if self._example_name is not None:
                raise ValueError("nested workflow examples are not supported")
            self._example_kind = "cli" if values.get("data-cli-example") else "mcp"
            self._example_name = str(
                values.get("data-cli-example") or values["data-workflow-example"])
            self._example_parts = []

    def handle_data(self, data: str) -> None:
        if self._example_name is not None:
            self._example_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag != "code" or self._example_name is None:
            return
        collection = self.cli_examples if self._example_kind == "cli" else self.examples
        if self._example_name in collection:
            raise ValueError(f"duplicate workflow example: {self._example_name}")
        collection[self._example_name] = "".join(self._example_parts)
        self._example_name = None
        self._example_parts = []


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
        expected_local_files: set[str], manual: str) -> str:
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
    _validate_workflow_examples(parser.examples)
    _validate_cli_examples(parser.cli_examples)
    manual_path = guide.parent / "FORMALSPECGEN_USER_GUIDE.html"
    documents = {guide: guide_bytes.decode("utf-8"), manual_path: manual}
    manual_parser = _validate_html_links(manual_path, manual, documents)
    _validate_html_links(guide, guide_bytes.decode("utf-8"), documents)
    return "\n".join([
        "# Published guide validation",
        "",
        "This record describes preparation of the current static GitHub Pages edition. It is",
        "documentation validation, not formal verification or revision-bound acceptance evidence.",
        "",
        "## Checked publication inputs",
        "",
        f"- `index.html` SHA-256: `{_sha256(guide_bytes)}`",
        f"- `FORMALSPECGEN_USER_GUIDE.html` SHA-256: `{_sha256(manual.encode('utf-8'))}`",
        f"- `command_inventory.json` SHA-256: `{_sha256(inventory_bytes)}`",
        f"- `mcp_capabilities.json` SHA-256: `{_sha256(capabilities_bytes)}`",
        f"- Parsed HTML element IDs: {len(parser.ids)}",
        f"- Same-page fragment links checked: {len(fragment_links)}",
        "- Missing same-page targets: none",
        "- Duplicate element IDs: none",
        "- Linked publication files: `command_inventory.json`, `mcp_capabilities.json`,",
        "  `VALIDATION.md`, `FORMALSPECGEN_USER_GUIDE.html`, and the archived `91c6790` guide",
        f"- Operating-manual IDs: {len(manual_parser.ids)}; local links and cross-page fragments checked",
        f"- All {json.loads(inventory_bytes)['command_count']} command-reference and index admission labels generated from the live inventory",
        "- Unexpected relative assets: none",
        "- Handwritten verification, analysis, refactoring, and traceability MCP payloads validated through application request models",
        f"- Current landing-page CLI examples parsed against the real CLI: {len(parser.cli_examples)}",
        "",
        "## Scope limits",
        "",
        "- External URLs were retained but not fetched as part of publication validation.",
        "- Detailed manual recipes and source references originate at 91c6790; their formal workflows were not rerun.",
        "- No compiler, verifier, generated program, provider, or MCP transport was run.",
        "- Static handler schemas do not replace runtime MCP discovery acceptance.",
        "- Completion claims must be checked against the linked revision-bound CI evidence.",
        "",
    ])


def _validate_cli_examples(examples: dict[str, str]) -> None:
    from pipeline.cli import build_parser
    expected = {
        "project-plan": "project",
        "bisimulation": "verify-bisimulation",
        "security-templates": "security-exploit",
        "run-show": "run",
        "worker-artifacts": "worker",
        "capabilities": "capabilities",
        "evidence-explain": "evidence",
        "evidence-diff": "evidence",
        "evidence-source": "evidence",
        "inspect-stdout": "inspect",
        "inspect": "inspect", "analyze": "analyze-codebase",
        "document": "document-code", "verify": "verify",
        "preserve": "verify-refactor", "traceability": "generate-traceability-matrix",
    }
    if set(examples) != set(expected):
        raise ValueError("guide CLI example set drift")
    parser = build_parser()
    for name, text in examples.items():
        tokens = shlex.split(text)
        if not tokens or tokens[0] != "formalspecgen":
            raise ValueError(f"invalid CLI example: {name}")
        try:
            args = parser.parse_args(tokens[1:])
        except SystemExit as exc:
            raise ValueError(f"invalid CLI example: {name}") from exc
        if args.command != expected[name]:
            raise ValueError(f"wrong command for CLI example: {name}")
        if name == "project-plan":
            request = ProjectWorkflowRequest(args.manifest, args.operation, args.target)
            if request != ProjectWorkflowRequest("project.json", "plan", "app") or args.json != "-":
                raise ValueError("project example must plan app from project.json on stdout")
        if name == "security-templates":
            request = SecurityTemplateWorkflowRequest(args.report, args.target, args.out_dir, args.json)
            if request.effective_export != "review/poc-verdict.json":
                raise ValueError("template example must use the default controlled verdict export")
        if name == "bisimulation":
            request = BisimulationWorkflowRequest(args.baseline, args.refactored, args.mapping)
            if args.json != "-" or Path(request.mapping).name != "mapping.json":
                raise ValueError("preflight example must read mapping.json and render JSON stdout")
        if name == "worker-artifacts":
            request = WorkerArtifactsRequest(args.work_item_id)
            if request.work_item_id != "work-001" or args.operation != "artifacts" or args.json != "-":
                raise ValueError("worker example must read work-001 artifact references on stdout")
        if name == "run-show":
            request = RunReadRequest(args.run_id)
            if request.run_id != "review-001" or args.operation != "show" or args.json != "-":
                raise ValueError("run example must read review-001 on stdout")
        if name == "capabilities":
            request = CapabilityDiscoveryRequest(args.name)
            if request.name != "verify" or args.json != "-":
                raise ValueError("capabilities example must describe verify on stdout")
        if name == "inspect-stdout" and args.json != "-":
            raise ValueError("stdout inspection example must use --json -")
        if name == "evidence-explain":
            request = EvidenceWorkflowRequest(args.manifest, args.operation, args.expected_sha256)
            if request.operation != "explain" or args.json != "-":
                raise ValueError("evidence example must explain existing evidence on stdout")
        if name == "evidence-diff":
            request = EvidenceWorkflowRequest(args.manifest, args.operation, args.expected_sha256,
                                              args.comparison_manifest, args.comparison_expected_sha256)
            if request.operation != "diff" or args.json != "-":
                raise ValueError("evidence diff example must compare existing evidence on stdout")
        if name == "evidence-source":
            request = EvidenceWorkflowRequest(args.manifest, args.operation, args.expected_sha256, source=args.source)
            if request.operation != "validate" or not request.source or args.json != "-":
                raise ValueError("evidence source example must explicitly check a source on stdout")
        if name == "document" and not args.no_llm:
            raise ValueError("manual documentation example must remain provider-free")
        if name == "verify" and args.mode != "esc":
            raise ValueError("manual verification example must retain its ESC objective")


def _validate_html_links(
        path: Path, text: str, documents: dict[Path, str]) -> _GuideLinks:
    """Validate same-page and cross-page anchors without fetching external URLs."""
    parser = _GuideLinks()
    parser.feed(text)
    parser.close()
    if len(set(parser.ids)) != len(parser.ids):
        raise ValueError(f"duplicate HTML ids in {path.name}")
    parsed = {path: parser}
    for value in parser.hrefs + parser.sources:
        link = urlparse(value)
        if link.scheme or link.netloc:
            continue
        target = path.parent / unquote(link.path) if link.path else path
        if target.is_dir():
            target = target / "index.html"
        if not target.is_file():
            raise ValueError(f"missing local link in {path.name}: {value}")
        if link.fragment:
            linked = parsed.get(target)
            if linked is None:
                linked = _GuideLinks()
                linked.feed(documents.get(target) or target.read_text(encoding="utf-8"))
                parsed[target] = linked
            if unquote(link.fragment) not in linked.ids:
                raise ValueError(f"missing fragment in {path.name}: {value}")
    return parser


def _manual_admission(text: str, inventory: dict) -> str:
    """Refresh only marked availability labels, preserving manual recipes."""
    commands = {item["cli_command"]: item for item in inventory["commands"]}
    for label, count in (("CLI commands", inventory["command_count"]),
                         ("argument declarations", inventory["argument_declaration_count"])):
        text = re.sub(r'(<span class="chip">)\d+ ' + label + r'(</span>)',
                      lambda match: match[1] + str(count) + " " + label + match[2], text)
    for tag, attribute in (("p", "data-cli-command"), ("td", "data-cli-admission")):
        pattern = rf'<{tag} {attribute}="([^"]+)">[\s\S]*?</{tag}>'
        seen: list[str] = []
        def replace(match: re.Match) -> str:
            name = match[1]
            seen.append(name)
            item = commands.get(name)
            if item is None:
                raise ValueError(f"unknown manual command: {name}")
            admitted = item["admission_status"] == "admitted"
            label = "Admitted profiles; not a completion claim" if admitted else "Not admitted"
            if tag == "p":
                label = (
                    "<strong>Interface availability.</strong> Operator CLI; strict MCP: "
                    + label + '. See <a href="index.html#catalogue">current invocation scope</a>'
                    + ' and <a href="index.html#approvals">human approval boundaries</a>.')
            return f'<{tag} {attribute}="{escape(name, quote=True)}">{label}</{tag}>'
        text = re.sub(pattern, replace, text)
        if len(seen) != len(commands) or set(seen) != set(commands):
            raise ValueError(f"manual command coverage drift: {attribute}")
    return text


def _validate_workflow_examples(examples: dict[str, str]) -> None:
    if set(examples) != {
            "project-plan",
            "bisimulation", "security-templates",
            "worker-artifacts", "run-show", "capabilities", "verify-java", "analyze-codebase", "apply-refactor-java", "traceability", "evidence-explain", "evidence-diff", "evidence-source"}:
        raise ValueError(
            "guide workflow-example drift: expected project-plan, security-templates, bisimulation, verify-java, analyze-codebase, "
            "worker-artifacts, run-show, capabilities, apply-refactor-java, traceability, evidence-explain, evidence-diff, and evidence-source, found "
            + ", ".join(sorted(examples)))
    if ProjectWorkflowRequest(**json.loads(examples["project-plan"])) != ProjectWorkflowRequest("project.json", "plan", "app"):
        raise ValueError("project example must plan app from project.json")
    if RunReadRequest(**json.loads(examples["run-show"])).run_id != "review-001":
        raise ValueError("run example must read review-001")
    preflight = BisimulationWorkflowRequest(**json.loads(examples["bisimulation"]))
    templates = SecurityTemplateWorkflowRequest(**json.loads(examples["security-templates"]))
    if templates.effective_export != "review/poc-verdict.json":
        raise ValueError("template example must use the default controlled verdict export")
    if Path(preflight.mapping).name != "mapping.json" or preflight.result_export != "preflight/result.json":
        raise ValueError("preflight example must bind mapping.json and controlled result export")
    if WorkerArtifactsRequest(**json.loads(examples["worker-artifacts"])).work_item_id != "work-001":
        raise ValueError("worker example must read work-001")
    capability_request = CapabilityDiscoveryRequest(**json.loads(examples["capabilities"]))
    if capability_request.name != "verify":
        raise ValueError("capabilities example must describe verify")
    payload = json.loads(examples["verify-java"])
    evidence = EvidenceWorkflowRequest(**json.loads(examples["evidence-explain"]))
    if evidence.operation != "explain":
        raise ValueError("evidence-explain example must request explanation")
    comparison = EvidenceWorkflowRequest(**json.loads(examples["evidence-diff"]))
    if comparison.operation != "diff":
        raise ValueError("evidence-diff example must request comparison")
    source = EvidenceWorkflowRequest(**json.loads(examples["evidence-source"]))
    if source.operation != "validate" or not source.source:
        raise ValueError("evidence-source example must request explicit source validation")
    TraceabilityWorkflowRequest(**json.loads(examples["traceability"]))
    request = VerificationWorkflowRequest(**payload)
    if request.language not in {"java", "jml"} or \
            request.effective_backend != "openjml":
        raise ValueError("verify-java example does not resolve to Java/OpenJML")
    analysis = CodebaseAnalysisWorkflowRequest(**json.loads(
        examples["analyze-codebase"]))
    if analysis.language != "polyglot" or \
            analysis.effective_backend != "builtin-codebase-analysis":
        raise ValueError(
            "analyze-codebase example does not resolve to bounded built-in analysis")
    refactor = ApplyRefactorWorkflowRequest(**json.loads(
        examples["apply-refactor-java"]))
    if refactor.language != "java" or refactor.effective_backend != "openjml" or \
            refactor.pattern != "extract-method":
        raise ValueError(
            "apply-refactor-java example does not resolve to Java/OpenJML extract-method")


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
    manual = _manual_admission(
        (site / "FORMALSPECGEN_USER_GUIDE.html").read_text(encoding="utf-8"), inventory)
    validation = _guide_validation(
        site / "index.html", inventory_bytes, capabilities_bytes,
        {"archive/91c6790/", "command_inventory.json",
         "mcp_capabilities.json", "VALIDATION.md", "FORMALSPECGEN_USER_GUIDE.html"},
        manual)
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
        args.site / "FORMALSPECGEN_USER_GUIDE.html": _manual_admission(
            (args.site / "FORMALSPECGEN_USER_GUIDE.html").read_text(encoding="utf-8"),
            json.loads(inventory)).encode("utf-8"),
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
