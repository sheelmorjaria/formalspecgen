from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server


def test_mcp_workspace_paths_are_contained(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = Path("Counter.java")
    source.write_text("public class Counter {}", encoding="utf-8")
    assert mcp_server.inspect_code("Counter.java")["status"] == "INSPECTED"
    with pytest.raises(ValueError, match="inside"):
        mcp_server.inspect_code("../Counter.java")


def test_mcp_verify_code_returns_structured_java_verdict(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = Path("Counter.java"); source.write_text("public class Counter {}")
    with patch("mcp_server.verify", return_value=(0, "ok")):
        result = mcp_server.verify_code("Counter.java", "check")
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "NO_PROOF"
    assert result["exit_code"] == 0


def test_mcp_server_reports_optional_dependency_boundary():
    if mcp_server.FastMCP is not None:
        pytest.skip("MCP SDK is installed in this environment")
    with pytest.raises(RuntimeError, match="MCP SDK is not installed"):
        mcp_server.create_server()
