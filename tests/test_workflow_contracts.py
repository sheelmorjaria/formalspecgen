# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Shared request, result and permission-context regression tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline.mcp_policy import MCPPolicyViolation, authorize_mcp_invocation
from pipeline.mcp_provider_policy import resolve_documentation_model
from pipeline.code_documentation import DocumentationNarrative
from pipeline.workflow_contracts import (
    DocumentationWorkflowRequest,
    InspectionWorkflowRequest,
    VerificationWorkflowRequest,
    WorkflowContext,
    WorkflowInterface,
    bind_workflow_result,
)
from pipeline.workflow_services import (
    run_documentation_preparation,
    run_java_verification,
)


def test_equivalent_cli_and_mcp_verification_inputs_normalize_identically(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = Path("Counter.java")
    cli = VerificationWorkflowRequest(str(source), mode="ESC", backend="prusti")
    mcp = VerificationWorkflowRequest(str(source), mode="esc")
    assert cli == mcp
    assert cli.language == "java"
    assert cli.effective_backend == "openjml"


def test_deterministic_documentation_discards_inapplicable_provider_values(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cli = DocumentationWorkflowRequest(
        "Counter.java", "docs/Counter.md", no_llm=True,
        provider="openai", model="ignored")
    mcp = DocumentationWorkflowRequest(
        "Counter.java", "docs/Counter.md", no_llm=True, provider=None)
    assert cli == mcp
    assert cli.provider is None and cli.model is None
    assert cli.mode == "deterministic"


def test_effect_planner_separates_export_provider_and_publication():
    verification = VerificationWorkflowRequest("Counter.java")
    assert verification.required_effects(WorkflowInterface.CLI) == (
        "external_execution", "workspace_read")
    assert verification.required_effects(WorkflowInterface.MCP) == (
        "evidence_publication", "external_execution", "workspace_read")
    inspection = InspectionWorkflowRequest("Counter.java", result_export="result.json")
    assert inspection.required_effects(WorkflowInterface.CLI) == (
        "workspace_read", "workspace_write_new")
    provider_docs = DocumentationWorkflowRequest(
        "Counter.java", "Counter.md", provider="ollama")
    assert provider_docs.required_effects(WorkflowInterface.CLI) == (
        "provider_access", "workspace_read", "workspace_write_new")


def test_context_rejects_missing_authority_and_child_widening(tmp_path):
    admission = authorize_mcp_invocation(
        "inspect_code", mode="inspect", language="java",
        backend="builtin-java-inspector", effects=("workspace_read",))
    with pytest.raises(MCPPolicyViolation, match="missing required effects"):
        WorkflowContext.for_mcp(
            admission, ("workspace_read", "external_execution"),
            workspace_root=tmp_path)
    context = WorkflowContext.for_mcp(
        admission, ("workspace_read",), workspace_root=tmp_path)
    child = context.child(("workspace_read",))
    assert child.summary()["authority"]["parent"]["profile"] == \
        "java-readonly-inspection"
    with pytest.raises(MCPPolicyViolation, match="cannot widen"):
        context.child(("workspace_read", "external_execution"))
    with pytest.raises(TypeError):
        child.resource_budget["max_input_bytes"] = 1


def test_context_rejects_invalid_resource_budget(tmp_path):
    authority = WorkflowContext.for_cli(
        ("workspace_read",), workspace_root=tmp_path).authority
    with pytest.raises(ValueError, match="non-negative integers"):
        WorkflowContext(
            WorkflowInterface.CLI, authority, tmp_path,
            ("workspace_read",), resource_budget={"bytes": -1})


def test_shared_java_service_constructs_same_semantic_result(tmp_path):
    source = tmp_path / "Counter.java"
    source.write_text("class Counter {}", encoding="utf-8")
    request = VerificationWorkflowRequest(str(source), mode="check")
    context = WorkflowContext.for_cli(
        request.required_effects(WorkflowInterface.CLI), workspace_root=tmp_path)
    result = run_java_verification(
        request, context, lambda _source, _mode: (0, "typecheck ok"))
    assert result.payload["status"] == "VERIFIED"
    assert result.payload["request_satisfied"] is True
    assert result.payload["source"] == str(source)


def test_result_envelope_keeps_assurance_dimensions_separate(tmp_path):
    request = InspectionWorkflowRequest(str(tmp_path / "Counter.java"))
    payload = bind_workflow_result(
        {"status": "INSPECTED", "claim": "NO_PROOF", "findings": []},
        request, WorkflowInterface.CLI)
    envelope = payload["workflow_result"]
    assert envelope["workflow_status"] == "INSPECTED"
    assert envelope["verification"] == {
        "claim": "NO_PROOF", "request_satisfied": False}
    assert envelope["execution"] is None
    assert envelope["publication"] is None
    assert envelope["approval"] is None


def _documentation_context(
        request: DocumentationWorkflowRequest, tmp_path: Path, **budget: int
) -> WorkflowContext:
    base = WorkflowContext.for_cli(
        request.required_effects(WorkflowInterface.CLI),
        workspace_root=tmp_path, output_root=tmp_path / "out")
    return WorkflowContext(
        WorkflowInterface.CLI, base.authority, tmp_path,
        request.required_effects(WorkflowInterface.CLI),
        tmp_path / "out", budget)


def test_documentation_service_reports_language_read_and_extraction_failures(
        tmp_path):
    rust = tmp_path / "Counter.rs"
    rust.write_text("struct Counter { value: i32 }", encoding="utf-8")
    request = DocumentationWorkflowRequest(
        str(rust), "Counter.md", no_llm=True)
    assert run_documentation_preparation(
        request, _documentation_context(request, tmp_path)).payload["status"] == \
        "UNSUPPORTED_LANGUAGE"

    invalid = tmp_path / "Invalid.java"
    invalid.write_bytes(b"\xff")
    request = DocumentationWorkflowRequest(
        str(invalid), "Invalid.md", no_llm=True)
    assert run_documentation_preparation(
        request, _documentation_context(request, tmp_path)).payload["code"] == \
        "input_unavailable"

    oversized = tmp_path / "Oversized.java"
    oversized.write_text("class Oversized {}", encoding="utf-8")
    request = DocumentationWorkflowRequest(
        str(oversized), "Oversized.md", no_llm=True)
    assert run_documentation_preparation(
        request, _documentation_context(
            request, tmp_path, max_input_bytes=1)).payload["code"] == \
        "INPUT_LIMIT_EXCEEDED"

    empty = tmp_path / "Empty.java"
    empty.write_text("class Empty {}", encoding="utf-8")
    request = DocumentationWorkflowRequest(str(empty), "Empty.md", no_llm=True)
    assert run_documentation_preparation(
        request, _documentation_context(request, tmp_path)).payload["code"] == \
        "UNPARSEABLE_SOURCE"

    with patch("pathlib.Path.open", side_effect=OSError("read denied")):
        assert run_documentation_preparation(
            request, _documentation_context(request, tmp_path)).payload["code"] == \
            "input_unavailable"


def test_documentation_service_bounds_provider_result(tmp_path):
    source = tmp_path / "Counter.java"
    source.write_text(
        "public class Counter { private int value = 1; "
        "public void down() { if (value > 0) value = value - 1; } "
        "public void up() { if (value < 1) value = value + 1; } }",
        encoding="utf-8")
    request = DocumentationWorkflowRequest(
        str(source), "Counter.md", provider="ollama")
    generated = DocumentationNarrative(
        {"overview": "x" * 100, "invariant_prose": {}}, "fixture", {})
    result = run_documentation_preparation(
        request, _documentation_context(
            request, tmp_path, max_provider_response_bytes=10),
        generate=lambda *_args: generated)
    assert result.payload["code"] == "PROVIDER_RESULT_LIMIT_EXCEEDED"


def test_mcp_documentation_model_policy_is_server_controlled(monkeypatch):
    monkeypatch.setenv(
        "FORMALSPECGEN_MCP_DOCUMENT_MODELS",
        "ollama:approved:tag, openai:approved-openai")
    assert resolve_documentation_model("ollama", "approved:tag") == "approved:tag"
    assert resolve_documentation_model("openai", "approved-openai") == \
        "approved-openai"
    assert resolve_documentation_model("glm", None)
    with pytest.raises(MCPPolicyViolation, match="not approved"):
        resolve_documentation_model("unknown", None)
    with pytest.raises(MCPPolicyViolation, match="not approved"):
        resolve_documentation_model("ollama", "unapproved")
    monkeypatch.setenv("FORMALSPECGEN_MCP_DOCUMENT_MODELS", "malformed")
    with pytest.raises(MCPPolicyViolation, match="provider:model"):
        resolve_documentation_model("ollama", None)
