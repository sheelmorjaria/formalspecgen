# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Declarations alone must never become workflow-completion evidence."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from pipeline import parity_inventory as inventory

KINDS = (
    "request_equivalence", "argument_delivery", "effect_enforcement",
    "result_equivalence", "mcp_transport",
)
ADAPTER = {"status": "admitted", "profiles": [{"name": "review-fixture"}]}
SCHEMA = {"field_names": ["source", "mode"], "fields": []}
REVISION = "1" * 40  # Synthetic; not claimed to be a repository commit.


@pytest.fixture
def synthetic_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "pipeline").mkdir()
    (tmp_path / "tests").mkdir()
    monkeypatch.setattr(inventory, "__file__", str(tmp_path / "pipeline" / "parity_inventory.py"))
    return tmp_path


def plan(test_node: str = "tests/fixture.py::test_not_executed") -> dict:
    return {
        "workflow_kind": "direct",
        "argument_mappings": [
            {"proposed_mcp_field": field, "implementation_status": "verified"}
            for field in ("source", "mode")
        ],
        "completion_contract": {
            "required_variants": ["java"], "covered_variants": ["java"],
            "evidence_revision": REVISION,
            "acceptance_cases": [
                {"kind": kind, "test": test_node, "result": "passed", "revision": REVISION}
                for kind in KINDS
            ],
        },
    }


def evaluate(candidate: dict) -> dict:
    return inventory._workflow_completion(candidate, ADAPTER, SCHEMA)


def test_existing_file_with_nonexistent_test_nodes_is_not_evidence(synthetic_root: Path):
    (synthetic_root / "tests" / "fixture.py").write_text("# No tests exist.\n", encoding="utf-8")
    assert evaluate(plan())["complete"] is False


def test_existing_test_function_without_run_evidence_is_incomplete(synthetic_root: Path):
    (synthetic_root / "tests" / "fixture.py").write_text(
        "def test_not_executed():\n    assert True\n", encoding="utf-8")
    # Function existence is not a record of its execution on the reviewed revision.
    assert evaluate(plan())["complete"] is False


def test_missing_test_file_remains_incomplete(synthetic_root: Path):
    assert evaluate(plan())["complete"] is False


@pytest.mark.parametrize("outcome", ["failed", "skipped"])
def test_nonpassing_outcomes_cannot_complete_a_workflow(synthetic_root: Path, outcome: str):
    (synthetic_root / "tests" / "fixture.py").write_text("# Placeholder\n", encoding="utf-8")
    candidate = plan()
    candidate["completion_contract"]["acceptance_cases"][0]["result"] = outcome
    assert evaluate(candidate)["complete"] is False


def test_inconsistent_case_revision_remains_incomplete(synthetic_root: Path):
    (synthetic_root / "tests" / "fixture.py").write_text("# Placeholder\n", encoding="utf-8")
    candidate = deepcopy(plan())
    candidate["completion_contract"]["acceptance_cases"][0]["revision"] = "2" * 40
    assert evaluate(candidate)["complete"] is False
