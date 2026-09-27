# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Bounded refactor capture and executable guide-example regressions."""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server
from pipeline.workflow_contracts import WorkflowContext
from pipeline.workflow_services import _refactor_inputs
from scripts.generate_pages_companions import (
    _GuideLinks,
    _validate_workflow_examples,
)


def _context(root: Path, **budget: int) -> WorkflowContext:
    return WorkflowContext.for_cli(
        ("workspace_read",), workspace_root=root, resource_budget=budget)


def _pair(tmp_path: Path, baseline: bytes, candidate: bytes) -> tuple[Path, Path]:
    left = tmp_path / "baseline" / "Probe.java"
    right = tmp_path / "candidate" / "Probe.java"
    left.parent.mkdir()
    right.parent.mkdir()
    left.write_bytes(baseline)
    right.write_bytes(candidate)
    return left, right


def _tracked_open(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    original = Path.open
    returned: list[int] = []

    class TrackingReader(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            chunk = super().read(size)
            returned.append(len(chunk))
            return chunk

    def open_path(path: Path, mode: str = "r", *args, **kwargs):
        if mode == "rb":
            with original(path, mode) as handle:
                return TrackingReader(handle.read())
        return original(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_path)
    return returned


def test_oversized_refactor_source_reads_only_limit_plus_probe(
        tmp_path, monkeypatch):
    baseline, candidate = _pair(tmp_path, b"abcdef", b"x")
    returned = _tracked_open(monkeypatch)

    with pytest.raises(ValueError, match="configured limit of 4 bytes"):
        _refactor_inputs(
            baseline, candidate, _context(tmp_path, max_input_bytes=4))

    assert sum(returned) == 5


def test_aggregate_refactor_limit_is_consumed_across_sources(
        tmp_path, monkeypatch):
    baseline, candidate = _pair(tmp_path, b"abc", b"def")
    returned = _tracked_open(monkeypatch)

    with pytest.raises(ValueError, match="configured limit of 5 bytes"):
        _refactor_inputs(
            baseline, candidate, _context(tmp_path, max_input_bytes=5))

    assert sum(returned) == 6


def test_zero_refactor_budget_reads_only_the_overflow_probe(
        tmp_path, monkeypatch):
    baseline, candidate = _pair(tmp_path, b"x", b"")
    returned = _tracked_open(monkeypatch)

    with pytest.raises(ValueError, match="configured limit of 0 bytes"):
        _refactor_inputs(
            baseline, candidate, _context(tmp_path, max_input_bytes=0))

    assert sum(returned) == 1


@pytest.mark.parametrize("limit", [5, 6])
def test_valid_and_exact_refactor_budgets_capture_complete_sources(
        tmp_path, limit):
    baseline, candidate = _pair(tmp_path, b"ab", b"cde")

    manifest, captured_baseline, captured_candidate = _refactor_inputs(
        baseline, candidate, _context(tmp_path, max_input_bytes=limit))

    assert manifest["total_bytes"] == 5
    assert manifest["total_files"] == 2
    assert captured_baseline[0].content == b"ab"
    assert captured_candidate[0].content == b"cde"


def test_multifile_refactor_enforces_source_count_before_capture(tmp_path):
    baseline = tmp_path / "baseline" / "Probe.java"
    candidate = tmp_path / "candidate"
    baseline.parent.mkdir()
    candidate.mkdir()
    baseline.write_text("class Probe {}", encoding="utf-8")
    (candidate / "Probe.java").write_text("class Probe {}", encoding="utf-8")
    (candidate / "Helper.java").write_text("class Helper {}", encoding="utf-8")

    with pytest.raises(ValueError, match="configured file limit"):
        _refactor_inputs(
            baseline, candidate, _context(
                tmp_path, max_input_bytes=1024, max_input_files=2))


def test_strict_mcp_refactor_supplies_byte_and_file_budgets(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    observed = {}

    def reject(_request, context):
        observed.update(context.resource_budget)
        raise ValueError("stop after observing limits")

    with patch("mcp_server.run_refactor_verification", side_effect=reject):
        result = mcp_server.verify_refactor(
            "baseline/Probe.java", "candidate/Probe.java")

    assert result["code"] == "invalid_refactor_request"
    assert observed == {
        "max_input_bytes": mcp_server.MCP_REFACTOR_MAX_INPUT_BYTES,
        "max_input_files": mcp_server.MCP_REFACTOR_MAX_INPUT_FILES,
    }


def test_current_guide_java_verification_example_is_application_valid():
    guide = Path(__file__).resolve().parents[1] / "site" / "index.html"
    parser = _GuideLinks()
    parser.feed(guide.read_text(encoding="utf-8"))
    parser.close()

    _validate_workflow_examples(parser.examples)
    payload = json.loads(parser.examples["verify-java"])
    assert "backend" not in payload
    assert payload == {
        "source": "src/Counter.java",
        "mode": "esc",
        "result_export": "verification/counter.json",
    }
