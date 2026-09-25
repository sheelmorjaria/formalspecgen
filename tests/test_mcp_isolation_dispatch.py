# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""MCP strict mode must reject undeclared routes before workflow dispatch."""

from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server
from pipeline.capability_registry import mcp_capabilities
from pipeline.isolated_verification import IsolatedVerificationResult


@pytest.mark.parametrize("suffix", [".rs", ".c"])
@pytest.mark.parametrize("setting", [None, "1"])
def test_native_direct_is_admitted_but_refactor_still_fails_before_dispatch(
        tmp_path, monkeypatch, suffix, setting):
    monkeypatch.chdir(tmp_path)
    if setting is None:
        monkeypatch.delenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", raising=False)
    else:
        monkeypatch.setenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", setting)

    baseline = Path(f"baseline{suffix}")
    candidate = Path(f"candidate{suffix}")
    baseline.write_text("int f(void) { return 1; }", encoding="utf-8")
    candidate.write_text("int f(void) { return 1; }", encoding="utf-8")

    raw = {"status": "VERIFIED", "exit_code": 0, "claim": "DEDUCTIVE_PROOF"}
    if suffix == ".c":
        raw.update({"proved_goals": 1, "total_goals": 1})
    with patch("mcp_server.execute_isolated_verification",
               return_value=IsolatedVerificationResult(raw)) as direct_backend:
        direct = mcp_server.verify_code(str(candidate))
    direct_backend.assert_called_once()
    assert direct["status"] == "VERIFIED"
    assert direct["request_satisfied"] is True
    assert direct["strict_isolation_supported"] is True

    with patch(
            "pipeline.refactor_gate.verify_contract_preserving_refactor"
    ) as downstream:
        indirect = mcp_server.verify_refactor(str(baseline), str(candidate))
    downstream.assert_not_called()
    assert indirect["status"] == "ISOLATION_UNSUPPORTED"
    assert indirect["claim"] == "NO_PROOF"
    assert indirect["request_satisfied"] is False
    assert indirect["tool"] == "verify_refactor"


@pytest.mark.parametrize("setting", [None, "1"])
def test_implementation_and_system_routes_fail_before_dispatch(
        monkeypatch, setting):
    if setting is None:
        monkeypatch.delenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", raising=False)
    else:
        monkeypatch.setenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", setting)

    with patch("pipeline.orchestrator.run_implementation_loop") as implementation:
        implementation_result = mcp_server.implement_code("missing.java")
    implementation.assert_not_called()
    assert implementation_result["status"] == "ISOLATION_UNSUPPORTED"
    assert implementation_result["request_satisfied"] is False

    with patch("pipeline.system_orchestrator.verify_system") as system:
        system_result = mcp_server.system("missing.json")
    system.assert_not_called()
    assert system_result["status"] == "ISOLATION_UNSUPPORTED"
    assert system_result["request_satisfied"] is False


def test_strict_catalogue_contains_only_declared_supported_routes():
    strict = {item.mcp_tool: item.mcp_isolation
              for item in mcp_capabilities(strict_isolation=True)}
    assert strict == {
        "verify_code": "strict-execution",
        "inspect_code": "non-executing",
        "document_code": "non-executing",
        "submit_work_item": "a2a-coordination",
        "get_work_item": "a2a-coordination",
        "get_work_artifacts": "a2a-coordination",
        "cancel_work_item": "a2a-coordination",
    }
    assert all(item.mcp_isolation in {
        "a2a-coordination", "strict-java", "strict-execution",
        "non-executing", "unsupported"
    } for item in mcp_capabilities())


def test_server_registers_only_strict_catalogue_by_default(monkeypatch):
    monkeypatch.delenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", raising=False)

    class FakeFastMCP:
        def __init__(self, _name):
            self.registered = []

        def tool(self):
            def register(value):
                self.registered.append(value.__name__)
                return value
            return register

    monkeypatch.setattr(mcp_server, "FastMCP", FakeFastMCP)
    server = mcp_server.create_server()
    assert server.registered == [
        "verify_code", "inspect_code", "document_code", "submit_work_item",
        "get_work_item", "get_work_artifacts", "cancel_work_item"]
