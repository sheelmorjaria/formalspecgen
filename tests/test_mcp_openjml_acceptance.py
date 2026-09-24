# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Real OpenJML-to-MCP-handler acceptance with durable evidence validation."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import mcp_server
from pipeline import config
from pipeline.lifecycle import RunLedger


REQUIRED = os.environ.get("FORMALSPECGEN_REQUIRE_OPENJML_MCP_ACCEPTANCE") == "1"
pytestmark = pytest.mark.skipif(
    not REQUIRED,
    reason="real MCP/OpenJML acceptance requires the pinned verifier and sandbox",
)


def _assert_committed_receipt(result: dict) -> Path:
    receipt = result["evidence"]
    assert receipt["publication_status"] == "COMMITTED"
    manifest = Path(receipt["manifest_path"])
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == \
        receipt["manifest_sha256"]
    validation = RunLedger.validate(manifest.parents[1])
    assert validation["valid"] is True, validation
    terminal = json.loads(manifest.read_text(encoding="utf-8"))["terminal"]
    assert terminal["source_snapshot_manifest_sha256"] == \
        result["execution"]["snapshot_manifest_sha256"]
    assert terminal["execution_policy_compliance"] == \
        result["execution"]["policy_compliance"]
    return manifest


def test_real_openjml_proof_isolated_published_and_tamper_evident(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert Path(config.OPENJML).is_file(), "the pinned OpenJML launcher is required"
    source = Path("Proven.java")
    source.write_text(
        "public class Proven {\n"
        "  //@ ensures \\result == 1;\n"
        "  public static int value() { return 1; }\n"
        "}\n",
        encoding="utf-8",
    )

    result = mcp_server.verify_code(str(source), mode="esc")
    assert result["request_satisfied"] is True, result.get("output")
    assert result["claim"] == "DEDUCTIVE_PROOF"
    assert result["execution"]["policy_compliance"] == "ENFORCED"
    manifest = _assert_committed_receipt(result)

    artifact = manifest.parent / "001-proof.json"
    artifact.write_text(artifact.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    validation = RunLedger.validate(manifest.parents[1])
    assert validation["valid"] is False
    assert validation["status"] == "INVALID"


def test_real_openjml_counterexample_cannot_mint_proof(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = Path("Broken.java")
    source.write_text(
        "public class Broken {\n"
        "  //@ ensures \\result == 1;\n"
        "  public static int value() { return 2; }\n"
        "}\n",
        encoding="utf-8",
    )

    result = mcp_server.verify_code(str(source), mode="esc")
    assert result["request_satisfied"] is False
    assert result["claim"] == "NO_PROOF"
    assert result["execution"]["policy_compliance"] == "ENFORCED"
    _assert_committed_receipt(result)


def test_missing_cgroup_delegation_fails_without_fallback(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = Path("NoDelegation.java")
    source.write_text("public class NoDelegation {}\n", encoding="utf-8")
    monkeypatch.setenv("FORMALSPECGEN_CGROUP_ROOT", str(tmp_path / "not-a-cgroup"))

    result = mcp_server.verify_code(str(source), mode="esc")
    assert result["request_satisfied"] is False
    assert result["claim"] == "NO_PROOF"
    assert result["execution"]["status"] == "RESOURCE_CONTROL_UNAVAILABLE"
    assert result["execution"]["policy_compliance"] == "NOT_ENFORCED"
    _assert_committed_receipt(result)
