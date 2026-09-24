# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""End-to-end acceptance cases for the complete documentation workflow."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("mcp")

import mcp_server  # noqa: E402
from pipeline import cli  # noqa: E402
from pipeline.code_documentation import DocumentationNarrative  # noqa: E402
from pipeline.mcp_policy import authorize_mcp_invocation  # noqa: E402
from pipeline.workflow_contracts import (  # noqa: E402
    DocumentationWorkflowRequest,
    WorkflowInterface,
)
from scripts.mcp_acceptance_adapters import (  # noqa: E402
    collect_transport_observation,
)


JAVA = """public class Inventory {
    private int stock = 5;
    public void reserve() { if (stock > 0) { stock = stock - 1; } }
    public void restock() { if (stock < 5) { stock = stock + 1; } }
}
"""
VARIANTS = (
    "java-deterministic", "java-deterministic-export",
    "java-provider-glm", "java-provider-openai", "java-provider-ollama",
    "java-project-root", "java-provider-model", "java-provider-export",
)
SEMANTIC_FIELDS = (
    "status", "claim", "source_sha256", "narrative_source", "schema_valid",
    "schema_reason", "operation_inference", "validation",
    "documented_behavior_proved",
)


def _source(root: Path) -> Path:
    source = root / "Inventory.java"
    source.write_text(JAVA, encoding="utf-8")
    return source


def _narrative(model: str) -> DocumentationNarrative:
    return DocumentationNarrative(
        {"overview": "Fixture provider overview.", "invariant_prose": {}},
        model, {"prompt_tokens": 1, "completion_tokens": 1})


def test_documentation_cli_and_mcp_requests_normalize_equivalently(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = _source(tmp_path)
    defaults = {
        "glm": mcp_server.config.GLM_MODEL,
        "openai": mcp_server.config.OPENAI_MODEL,
        "ollama": mcp_server.config.OLLAMA_MODEL,
    }
    cases = [
        {"no_llm": True, "provider": "ollama", "model": "ignored"},
        {"no_llm": True, "provider": "openai", "model": None},
        *({"no_llm": False, "provider": provider, "model": model}
          for provider, model in defaults.items()),
    ]
    for index, options in enumerate(cases):
        export = None if index == 0 else f"results/{index}.json"
        expected = DocumentationWorkflowRequest(
            str(source), f"docs/{index}.md", project_root=f"component-{index}",
            result_export=export, **options)
        if expected.provider is None:
            result = mcp_server.document_code(
                str(source), expected.out, project_root=expected.project_root,
                no_llm=True, provider="ollama", model="ignored",
                result_export=export)
        else:
            with patch(
                    "pipeline.code_documentation.generate_narrative_strict",
                    return_value=_narrative(expected.model or "")):
                result = mcp_server.document_code(
                    str(source), expected.out, project_root=expected.project_root,
                    provider=expected.provider, model=expected.model,
                    result_export=export)
        assert result["workflow_result"]["request"] == expected.as_dict()
        assert expected.required_effects(WorkflowInterface.MCP) == tuple(
            result["mcp_admission"]["requested_effects"])


def test_documentation_cli_parser_and_transport_schema_cover_all_inputs(
        tmp_path, monkeypatch):
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("real stdio MCP acceptance is required only in its provisioned CI job")
    monkeypatch.chdir(tmp_path)
    parsed = cli.build_parser().parse_args([
        "document-code", "Inventory.java", "--out", "docs/Inventory.md",
        "--project-root", "component", "--no-llm",
        "--provider", "openai", "--model", "approved-model",
        "--json", "results/Inventory.json",
    ])
    assert (parsed.source, parsed.out, parsed.project_root, parsed.no_llm,
            parsed.provider, parsed.model, parsed.json) == (
        "Inventory.java", "docs/Inventory.md", "component", True,
        "openai", "approved-model", "results/Inventory.json")
    observation = collect_transport_observation("document-code")
    schema = observation["input_schema"]
    assert schema["required"] == ["source", "out"]
    assert set(schema["properties"]) == {
        "source", "out", "project_root", "no_llm", "provider", "model",
        "result_export"}


def test_documentation_effects_provider_policy_and_outputs_are_enforced(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = _source(tmp_path)
    deterministic = authorize_mcp_invocation(
        "document_code", mode="deterministic", language="java",
        backend="builtin-documentation",
        effects=("workspace_read", "workspace_write_new"))
    assisted = authorize_mcp_invocation(
        "document_code", mode="provider-assisted", language="java",
        backend="builtin-documentation", provider="ollama",
        effects=("workspace_read", "workspace_write_new", "provider_access"))
    assert deterministic.permits("provider_access") is False
    assert assisted.permits("provider_access") is True
    for provider in ("glm", "openai", "ollama"):
        admission = authorize_mcp_invocation(
            "document_code", mode="provider-assisted", language="java",
            backend="builtin-documentation", provider=provider,
            effects=("workspace_read", "workspace_write_new", "provider_access"))
        assert admission.admitted is True
        assert admission.permits("provider_access") is True

    outside = tmp_path.parent / "Outside.java"
    outside.write_text(JAVA, encoding="utf-8")
    assert mcp_server.document_code(
        str(outside), "docs/out.md", no_llm=True)["code"] == \
        "path_outside_workspace"
    assert mcp_server.document_code(
        str(source), "../out.md", no_llm=True)["code"] == \
        "OUTPUT_SCOPE_VIOLATION"
    assert mcp_server.document_code(
        str(source), "docs/out.md", project_root="../project",
        no_llm=True)["code"] == "OUTPUT_SCOPE_VIOLATION"
    assert mcp_server.document_code(
        str(source), "docs/out.md", no_llm=True,
        result_export="../result.json")["code"] == "OUTPUT_SCOPE_VIOLATION"

    first = mcp_server.document_code(
        str(source), "docs/once.md", no_llm=True)
    assert first["status"] == "DOCUMENTED"
    second = mcp_server.document_code(
        str(source), "docs/once.md", no_llm=True)
    assert second["code"] == "OUTPUT_ALREADY_EXISTS"


def test_documentation_cli_and_mcp_results_are_semantically_equivalent(
        tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = _source(tmp_path)
    variants = [
        ("deterministic", None, None),
        ("glm", "glm", mcp_server.config.GLM_MODEL),
        ("openai", "openai", mcp_server.config.OPENAI_MODEL),
        ("ollama", "ollama", mcp_server.config.OLLAMA_MODEL),
    ]
    for name, provider, model in variants:
        cli_arguments = [
            "document-code", str(source), "--out", f"cli/{name}.md",
            "--project-root", f"cli-{name}",
            "--json", f"cli/{name}.json",
        ]
        if provider is None:
            cli_arguments.append("--no-llm")
        else:
            cli_arguments.extend(["--provider", provider, "--model", model])
        generated = _narrative(model or "disabled")
        with patch(
                "pipeline.code_documentation.generate_narrative_strict",
                return_value=generated):
            assert cli.main(cli_arguments) == 0
            cli_result = json.loads(
                (tmp_path / f"cli/{name}.json").read_text(encoding="utf-8"))
            mcp_result = mcp_server.document_code(
                str(source), f"mcp/{name}.md", project_root=f"mcp-{name}",
                no_llm=provider is None, provider=provider or "ollama",
                model=model, result_export=f"mcp/{name}.json")

        assert {key: cli_result[key] for key in SEMANTIC_FIELDS} == {
            key: mcp_result[key] for key in SEMANTIC_FIELDS}
        assert cli_result.get("provider") == mcp_result.get("provider")
        assert cli_result["workflow_result"]["verification"] == \
            mcp_result["workflow_result"]["verification"]
        assert mcp_result["publication"]["status"] == "COMMITTED"


def test_real_mcp_transport_discovers_and_calls_documentation_variants():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("real stdio MCP acceptance is required only in its provisioned CI job")
    observation = collect_transport_observation("document-code")
    assert observation["transport"] == "mcp-stdio-subprocess"
    assert observation["result_status"] == "DOCUMENTED"
    assert "document_code" in observation["discovered_tools"]
