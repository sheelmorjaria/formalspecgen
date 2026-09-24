# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Strict MCP admission and effect tests for deterministic documentation."""

from __future__ import annotations

import inspect
import os
from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server
from pipeline.mcp_artifacts import (
    MCPArtifactError,
    publish_new_artifacts,
    read_bounded_text,
)
from pipeline.mcp_policy import (
    MCPPolicyViolation,
    authorize_mcp_invocation,
)


JAVA = """public class Inventory {
    private int stock;
    public Inventory() { this.stock = 5; }
    public void reserve() {
        if (stock > 0) { stock = stock - 1; }
    }
    public void restock() {
        if (stock < 5) { stock = stock + 1; }
    }
}
"""


def test_mcp_documentation_signature_is_narrow():
    assert tuple(inspect.signature(mcp_server.document_code).parameters) == (
        "source", "out")


def _source(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    source = Path("Inventory.java")
    source.write_text(JAVA, encoding="utf-8")
    return source


def test_deterministic_java_documentation_publishes_new_unreviewed_artifacts(
        tmp_path, monkeypatch):
    source = _source(tmp_path, monkeypatch)
    with patch("subprocess.run") as process, \
            patch("pipeline.code_documentation._chat_fn") as provider:
        result = mcp_server.document_code(str(source), "docs/Inventory.md")

    assert result["status"] == "DOCUMENTED"
    assert result["claim"] == "UNREVIEWED_EXTRACTION_DOCUMENTATION"
    assert result["documented_behavior_proved"] is False
    assert result["validation"]["status"] == "NOT_RUN"
    assert result["mcp_admission"]["profile"] == \
        "java-deterministic-documentation"
    assert result["mcp_admission"]["granted_effects"] == [
        "workspace_read", "workspace_write_new"]
    assert result["workflow_result"]["request"]["provider"] is None
    assert result["workflow_result"]["execution"] is None
    assert result["workflow_result"]["publication"] is None
    document = Path(result["document"])
    candidate = Path(result["candidate"])
    assert document == tmp_path / ".formalspecgen/mcp-output/docs/Inventory.md"
    assert candidate == (tmp_path / ".formalspecgen/mcp-output/domains/candidates/"
                         "inventory.v2.yaml")
    assert "Review Status: UNREVIEWED" in document.read_text(encoding="utf-8")
    assert "domain_name: Inventory" in candidate.read_text(encoding="utf-8")
    process.assert_not_called()
    provider.assert_not_called()


def test_unsupported_language_rejects_before_documentation_dispatch(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("Inventory.rs").write_text("struct Inventory { stock: i32 }", encoding="utf-8")
    with patch("pipeline.code_documentation.prepare_deterministic_documentation") as workflow:
        result = mcp_server.document_code("Inventory.rs", "docs/Inventory.md")
    workflow.assert_not_called()
    assert result["status"] == "ISOLATION_UNSUPPORTED"
    assert result["request_satisfied"] is False


@pytest.mark.parametrize("effects", [
    ("workspace_read", "provider_access"),
    ("workspace_read", "external_execution"),
])
def test_documentation_profile_rejects_provider_or_execution(effects):
    admission = authorize_mcp_invocation(
        "document_code", mode="deterministic", language="java",
        backend="builtin-documentation", provider=None, effects=effects)
    assert admission.admitted is False


def test_omitted_write_permission_fails_at_publication_boundary(tmp_path):
    admission = authorize_mcp_invocation(
        "document_code", mode="deterministic", language="java",
        backend="builtin-documentation", effects=("workspace_read",))
    assert admission.admitted is True
    with pytest.raises(MCPPolicyViolation, match="workspace_write_new"):
        publish_new_artifacts(
            tmp_path / "outputs", {"result.md": "result"}, admission,
            max_total_bytes=100)


def test_input_and_output_scope_fail_before_workflow_dispatch(tmp_path, monkeypatch):
    source = _source(tmp_path, monkeypatch)
    outside = tmp_path.parent / "Outside.java"
    outside.write_text(JAVA, encoding="utf-8")
    with patch("pipeline.code_documentation.prepare_deterministic_documentation") as workflow:
        escaped_input = mcp_server.document_code(str(outside), "docs/Inventory.md")
        escaped_output = mcp_server.document_code(str(source), "../Inventory.md")
        absolute_output = mcp_server.document_code(str(source), str(tmp_path / "result.md"))
    workflow.assert_not_called()
    assert escaped_input["code"] == "path_outside_workspace"
    assert escaped_output["code"] == "OUTPUT_SCOPE_VIOLATION"
    assert absolute_output["code"] == "OUTPUT_SCOPE_VIOLATION"


def test_existing_output_is_never_replaced(tmp_path, monkeypatch):
    source = _source(tmp_path, monkeypatch)
    destination = tmp_path / ".formalspecgen/mcp-output/docs/Inventory.md"
    destination.parent.mkdir(parents=True)
    destination.write_text("reviewed existing content", encoding="utf-8")
    result = mcp_server.document_code(str(source), "docs/Inventory.md")
    assert result["code"] == "OUTPUT_ALREADY_EXISTS"
    assert destination.read_text(encoding="utf-8") == "reviewed existing content"


def test_existing_candidate_prevents_partial_document_publication(tmp_path, monkeypatch):
    source = _source(tmp_path, monkeypatch)
    root = tmp_path / ".formalspecgen/mcp-output"
    candidate = root / "domains/candidates/inventory.v2.yaml"
    candidate.parent.mkdir(parents=True)
    candidate.write_text("reviewed candidate", encoding="utf-8")
    result = mcp_server.document_code(str(source), "docs/Inventory.md")
    assert result["code"] == "OUTPUT_ALREADY_EXISTS"
    assert candidate.read_text(encoding="utf-8") == "reviewed candidate"
    assert not (root / "docs/Inventory.md").exists()


def test_symlinked_output_component_is_rejected(tmp_path, monkeypatch):
    source = _source(tmp_path, monkeypatch)
    root = tmp_path / ".formalspecgen/mcp-output"
    outside = tmp_path / "outside"
    root.mkdir(parents=True)
    outside.mkdir()
    (root / "docs").symlink_to(outside, target_is_directory=True)
    result = mcp_server.document_code(str(source), "docs/Inventory.md")
    assert result["code"] == "OUTPUT_SYMLINK_REJECTED"
    assert not (outside / "Inventory.md").exists()


def test_server_designated_output_root_and_symlinked_root_policy(tmp_path, monkeypatch):
    source = _source(tmp_path, monkeypatch)
    monkeypatch.setenv("FORMALSPECGEN_MCP_OUTPUT_ROOT", "generated/mcp")
    result = mcp_server.document_code(str(source), "docs/Inventory.md")
    assert Path(result["document"]) == tmp_path / "generated/mcp/docs/Inventory.md"

    outside = tmp_path / "outside-root"
    outside.mkdir()
    (tmp_path / "linked-root").symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv("FORMALSPECGEN_MCP_OUTPUT_ROOT", "linked-root")
    rejected = mcp_server.document_code(str(source), "docs/Other.md")
    assert rejected["code"] == "OUTPUT_SYMLINK_REJECTED"


def test_input_and_result_limits_fail_closed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    oversized = Path("Oversized.java")
    oversized.write_bytes(b" " * (mcp_server.MCP_DOCUMENT_MAX_INPUT_BYTES + 1))
    result = mcp_server.document_code(str(oversized), "docs/Oversized.md")
    assert result["code"] == "INPUT_LIMIT_EXCEEDED"

    admission = authorize_mcp_invocation(
        "document_code", mode="deterministic", language="java",
        backend="builtin-documentation",
        effects=("workspace_read", "workspace_write_new"))
    with pytest.raises(MCPArtifactError, match="result limit"):
        publish_new_artifacts(
            tmp_path / "outputs", {"large.md": "xx"}, admission,
            max_total_bytes=1)
    assert not (tmp_path / "outputs").exists()


def test_artifact_boundaries_reject_invalid_encoding_and_paths(tmp_path):
    admission = authorize_mcp_invocation(
        "document_code", mode="deterministic", language="java",
        backend="builtin-documentation",
        effects=("workspace_read", "workspace_write_new"))
    invalid = tmp_path / "Invalid.java"
    invalid.write_bytes(b"\xff")
    with pytest.raises(MCPArtifactError, match="valid UTF-8"):
        read_bounded_text(invalid, admission, max_bytes=10)
    with pytest.raises(MCPArtifactError, match="Missing.java"):
        read_bounded_text(tmp_path / "Missing.java", admission, max_bytes=10)
    for path in ("../escape.md", "/absolute.md", "."):
        with pytest.raises(MCPArtifactError, match="unsafe output path"):
            publish_new_artifacts(
                tmp_path / "outputs", {path: "result"}, admission,
                max_total_bytes=100)


def test_publication_race_rolls_back_artifacts_from_same_request(tmp_path):
    admission = authorize_mcp_invocation(
        "document_code", mode="deterministic", language="java",
        backend="builtin-documentation",
        effects=("workspace_read", "workspace_write_new"))
    real_link = os.link
    calls = 0

    def collide_on_second(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise FileExistsError(str(destination))
        return real_link(source, destination)

    root = tmp_path / "outputs"
    with patch("pipeline.mcp_artifacts.os.link", side_effect=collide_on_second):
        with pytest.raises(MCPArtifactError, match="refusing to replace"):
            publish_new_artifacts(
                root, {"a.md": "first", "b.md": "second"}, admission,
                max_total_bytes=100)
    assert not (root / "a.md").exists()
    assert not (root / "b.md").exists()


def test_missing_input_is_a_structured_failure(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = mcp_server.document_code("Missing.java", "docs/Missing.md")
    assert result["status"] == "FAIL"
    assert result["claim"] == "NO_PROOF"
    assert result["code"] == "input_unavailable"
