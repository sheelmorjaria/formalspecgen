# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Regression checks for the current and archived GitHub Pages publication."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from scripts.generate_pages_companions import _expected


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
GUIDE_SHA256 = "886a5f6104461c70ed22bc8639c475ccca90931fa31eeae158c246cb77db5f47"
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
    assert decoded["command_count"] == 38
    assert decoded["argument_declaration_count"] == 205
    assert decoded["commands_with_admitted_profile"] == 4
    assert decoded["commands_complete_without_ci_evidence"] == 0
    strict = json.loads(capabilities)
    assert strict["capability_count"] == 12
    assert strict["cli_capability_count"] == 4
    assert strict["mcp_only_capability_count"] == 8
    assert "verify_refactor" in {
        item["mcp_tool"] for item in strict["capabilities"]}


def test_historical_91c6790_guide_is_byte_preserved():
    archive = SITE / "archive" / "91c6790"
    assert hashlib.sha256((archive / "index.html").read_bytes()).hexdigest() == \
        ARCHIVED_GUIDE_SHA256
    assert (archive / "command_inventory.json").is_file()
    assert (archive / "VALIDATION.md").is_file()


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
