# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Shared request, result and permission-context regression tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.mcp_policy import MCPPolicyViolation, authorize_mcp_invocation
from pipeline.workflow_contracts import (
    DocumentationWorkflowRequest,
    InspectionWorkflowRequest,
    VerificationWorkflowRequest,
    WorkflowContext,
    WorkflowInterface,
    bind_workflow_result,
)
from pipeline.workflow_services import run_java_verification


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
