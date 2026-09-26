# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Real stdio MCP and OpenJML acceptance for the supervised goal path."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

import pytest

pytest.importorskip("mcp")
import anyio  # noqa: E402
from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

import mcp_server  # noqa: E402
from pipeline.a2a_coordination import current_git_revision  # noqa: E402
from pipeline.lifecycle import RunLedger  # noqa: E402


REQUIRED = os.environ.get("FORMALSPECGEN_REQUIRE_OPENJML_MCP_ACCEPTANCE") == "1"
pytestmark = pytest.mark.skipif(
    not REQUIRED,
    reason="real agent/MCP/OpenJML acceptance requires the provisioned sandbox",
)


async def _round_trip(arguments: dict, environment: dict[str, str]):
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(mcp_server.__file__).resolve())],
        cwd=str(Path.cwd()), env=environment)
    with anyio.fail_after(90):
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                schema = next(
                    tool.inputSchema for tool in tools.tools
                    if tool.name == "start_agent_run")
                response = await session.call_tool(
                    "start_agent_run", arguments=arguments)
                assert response.isError is False
                assert isinstance(response.structuredContent, dict)
                return schema, response.structuredContent


def test_real_transport_supervisor_binds_goal_tool_and_evidence(tmp_path):
    root = Path.cwd().resolve()
    source = root / "tests" / "fixtures" / "AgentProof.java"
    state_root = tmp_path / "agent-state"
    environment = {
        **os.environ,
        "FORMALSPECGEN_AGENT_STATE_ROOT": str(state_root),
        "FORMALSPECGEN_AGENT_PRINCIPAL": "ci-supervisor",
    }
    arguments = {
        "run_id": f"agent-acceptance-{uuid.uuid4().hex}",
        "objective": "Inspect and verify the approved acceptance fixture",
        "base_revision": current_git_revision(root),
        "source": source.relative_to(root).as_posix(),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "mode": "esc",
        "proposed_actions": ["inspect", "verify"],
        "allowed_paths": [source.relative_to(root).as_posix()],
        "protected_paths": ["pipeline/mcp_policy.py"],
    }

    schema, result = anyio.run(_round_trip, arguments, environment)

    assert set(("run_id", "objective", "base_revision", "source",
                "source_sha256")).issubset(schema["required"])
    assert result["status"] == "COMPLETED", result
    assert result["request_satisfied"] is True
    assert result["claim"] == "DEDUCTIVE_PROOF"
    assert result["source_changes_applied"] is False
    assert result["human_approval_granted"] is False
    review_path = Path(result["review"]["path"])
    assert review_path.is_file()
    assert hashlib.sha256(review_path.read_bytes()).hexdigest() == \
        result["review"]["sha256"]
    review = json.loads(review_path.read_text(encoding="utf-8"))
    child = review["verification"]["evidence"]
    assert child["publication_status"] == "COMMITTED"
    child_manifest = Path(child["manifest_path"])
    assert RunLedger.validate(child_manifest.parents[1])["valid"] is True
    assert review["source_sha256"] == arguments["source_sha256"]
    assert review["human_approval"]["granted"] is False
