# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Regression checks for the current and archived GitHub Pages publication."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

from scripts.generate_pages_companions import (
    _expected, _GuideLinks, _manual_admission, _validate_cli_examples,
    _validate_html_links, _validate_workflow_examples,
)
import pytest


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
GUIDE_SHA256 = "c0166554af547efade4448daf310732a51b6889c7964c5a1d38169a2626eb2d6"
ARCHIVED_GUIDE_SHA256 = \
    "59a55b2d8479014d01c988c79100d2968397c8d49122bba167e993d920ceaf55"


def test_current_guide_and_generated_companions_are_current():
    inventory, capabilities, validation = _expected(
        ROOT / "mcpdocs" / "mcp_parity_plan.json", SITE)

    assert hashlib.sha256((SITE / "index.html").read_bytes()).hexdigest() == \
        GUIDE_SHA256
    assert (SITE / "command_inventory.json").read_bytes() == inventory
    assert (SITE / "mcp_capabilities.json").read_bytes() == capabilities
    assert (SITE / "VALIDATION.md").read_text(encoding="utf-8") == validation

    decoded = json.loads(inventory)
    assert decoded["schema"] == "formalspecgen-guide-command-inventory-v2"
    assert decoded["command_count"] == 43
    assert decoded["argument_declaration_count"] == 224
    assert decoded["commands_with_admitted_profile"] == 14
    assert decoded["commands_complete_without_ci_evidence"] == 0
    strict = json.loads(capabilities)
    assert strict["capability_count"] == 22
    assert strict["cli_capability_count"] == 14
    assert strict["mcp_only_capability_count"] == 8
    assert {"verify_refactor", "apply_refactor", "analyze_codebase"}.issubset({
        item["mcp_tool"] for item in strict["capabilities"]}
    )
    assert {"get_approval_request", "complete_refactor_signing"}.issubset({
        item["mcp_tool"] for item in strict["capabilities"]})


def test_historical_91c6790_guide_is_byte_preserved():
    archive = SITE / "archive" / "91c6790"
    assert hashlib.sha256((archive / "index.html").read_bytes()).hexdigest() == \
        ARCHIVED_GUIDE_SHA256
    assert (archive / "command_inventory.json").is_file()
    assert (archive / "VALIDATION.md").is_file()


def test_manual_preserves_all_command_recipes_and_current_availability():
    manual = (SITE / "FORMALSPECGEN_USER_GUIDE.html").read_text()
    archived = (SITE / "archive/91c6790/index.html").read_text()
    inventory = json.loads((SITE / "command_inventory.json").read_text())
    assert manual == _manual_admission(manual, inventory)
    assert len(inventory["commands"]) == 43
    for command in inventory["commands"]:
        name = command["cli_command"]
        if name in {"evidence", "capabilities", "run", "worker", "project"}:
            assert f'<h2 id="{name}">' in manual
            assert f'data-cli-command="{name}"' in manual
            continue
        def section(document):
            start = document.index(f'<h2 id="{name}">')
            end = document.index("</section>", start)
            return document[start:end]
        old_section, new_section = section(archived), section(manual)
        # Preserve each command's invocations, option tables and examples.
        for pattern in (r"<pre[\s\S]*?</pre>", r"<table[\s\S]*?</table>"):
            assert re.findall(pattern, new_section) == re.findall(pattern, old_section)
        assert f'data-cli-command="{name}"' in new_section
        if command["admission_status"] == "admitted":
            assert "Admitted profiles; not a completion claim" in new_section
        else:
            assert "strict MCP: Not admitted" in new_section
    assert 'id="integration-notes"' in manual
    assert "two specific profiles" not in manual
    assert "default strict MCP catalogue</strong>" not in manual


def test_integrated_pages_have_valid_navigation_and_cli_examples():
    documents = {SITE / name: (SITE / name).read_text() for name in (
        "index.html", "FORMALSPECGEN_USER_GUIDE.html")}
    for path, text in documents.items():
        _validate_html_links(path, text, documents)
    parser = _GuideLinks()
    parser.feed(documents[SITE / "index.html"])
    _validate_cli_examples(parser.cli_examples)
    assert len(parser.cli_examples) == 16
    assert 'FORMALSPECGEN_USER_GUIDE.html#command-reference' in parser.hrefs
    assert "scripted automation" in documents[SITE / "index.html"]
    assert "Not yet a universal approval bridge" in documents[SITE / "index.html"]


def test_broken_cross_page_link_fails_publication_validation():
    path = SITE / "index.html"
    text = path.read_text().replace(
        "FORMALSPECGEN_USER_GUIDE.html#command-reference",
        "FORMALSPECGEN_USER_GUIDE.html#missing-command-reference")
    with pytest.raises(ValueError, match="missing fragment"):
        _validate_html_links(path, text, {path: text})


def test_invalid_cli_option_and_missing_command_labels_fail_validation():
    parser = _GuideLinks()
    parser.feed((SITE / "index.html").read_text())
    parser.cli_examples["verify"] += " --invented-option"
    with pytest.raises(ValueError, match="invalid CLI example"):
        _validate_cli_examples(parser.cli_examples)
    parser.examples["evidence-explain"] = json.dumps({
        "manifest": "run/evidence/manifest.json", "operation": "sign"})
    with pytest.raises(ValueError, match="evidence operation"):
        _validate_workflow_examples(parser.examples)
    inventory = json.loads((SITE / "command_inventory.json").read_text())
    manual = (SITE / "FORMALSPECGEN_USER_GUIDE.html").read_text()
    manual = manual.replace('data-cli-command="verify"', 'data-cli-command="unknown"')
    with pytest.raises(ValueError, match="unknown manual command"):
        _manual_admission(manual, inventory)


def test_pages_workflow_publishes_only_the_site_directory():
    workflow_path = ROOT / ".github" / "workflows" / "pages.yml"
    workflow = yaml.load(workflow_path.read_text(encoding="utf-8"),
                         Loader=yaml.BaseLoader)

    assert workflow["permissions"] == {
        "contents": "read",
        "actions": "read",
        "pages": "write",
        "id-token": "write",
    }
    steps = workflow["jobs"]["build"]["steps"]
    action_versions = {step.get("uses") for step in steps if step.get("uses")}
    assert action_versions == {
        "actions/checkout@v6",
        "actions/setup-python@v5",
        "actions/configure-pages@v6",
        "actions/upload-pages-artifact@v5",
    }
    upload = next(step for step in steps
                  if step.get("uses") == "actions/upload-pages-artifact@v5")
    assert upload["with"]["path"] == "site"
    assert workflow["jobs"]["deploy"]["steps"][0]["uses"] == \
        "actions/deploy-pages@v4"


def test_pages_publication_has_only_deliberate_regular_files():
    published = {
        path.relative_to(SITE).as_posix()
        for path in SITE.rglob("*")
        if not path.name.endswith(":Zone.Identifier")
    }
    assert published == {
        "index.html",
        "FORMALSPECGEN_USER_GUIDE.html",
        "command_inventory.json",
        "mcp_capabilities.json",
        "VALIDATION.md",
        "archive",
        "archive/91c6790",
        "archive/91c6790/index.html",
        "archive/91c6790/command_inventory.json",
        "archive/91c6790/VALIDATION.md",
    }
    assert all(not path.is_symlink() for path in SITE.rglob("*"))
    assert all(path.is_file() for path in SITE.rglob("*") if not path.is_dir())
