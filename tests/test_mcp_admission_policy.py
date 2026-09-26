# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Invocation-granular MCP admission and effect-boundary regressions."""

from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server
from pipeline.capability_registry import _capability, capability, mcp_capabilities
from pipeline.mcp_policy import (
    MCPPolicyViolation,
    authorize_mcp_invocation,
    require_mcp_effect,
)


@pytest.mark.parametrize("mode", ["parse", "check", "esc"])
def test_java_openjml_modes_have_one_exact_admission(mode):
    admission = authorize_mcp_invocation(
        "verify_code", mode=mode, language="java", backend="openjml",
        effects=("workspace_read", "external_execution", "evidence_publication"))
    assert admission.admitted is True
    assert admission.profile.name == "java-openjml-verification"
    assert admission.provider is None


@pytest.mark.parametrize(("change", "value"), [
    ("mode", "rac"),
    ("language", "rust"),
    ("backend", "prusti"),
    ("provider", "openai"),
    ("effects", ("workspace_read", "workspace_write_new")),
])
def test_java_admission_rejects_unapproved_combinations(change, value):
    request = {
        "mode": "esc",
        "language": "java",
        "backend": "openjml",
        "provider": None,
        "effects": ("workspace_read", "external_execution", "evidence_publication"),
    }
    request[change] = value
    admission = authorize_mcp_invocation("verify_code", **request)
    assert admission.admitted is False
    assert admission.rejection()["status"] == "ISOLATION_UNSUPPORTED"
    assert admission.rejection()["request_satisfied"] is False


def test_unknown_effect_and_capability_fail_closed():
    unknown_effect = authorize_mcp_invocation(
        "inspect_code", mode="inspect", language="java",
        backend="builtin-java-inspector", effects=("shell_escape",))
    assert unknown_effect.admitted is False
    assert "unknown requested effects" in unknown_effect.reason

    unknown_capability = authorize_mcp_invocation(
        "missing", mode="inspect", language="java", backend="builtin",
        effects=())
    assert unknown_capability.admitted is False
    assert unknown_capability.reason == "unknown MCP capability"


def test_inspection_profile_cannot_cross_execution_or_provider_boundary():
    admission = authorize_mcp_invocation(
        "inspect_code", mode="inspect", language="java",
        backend="builtin-java-inspector", effects=("workspace_read",))
    assert admission.admitted is True
    require_mcp_effect(admission, "workspace_read")
    with pytest.raises(MCPPolicyViolation, match="external_execution"):
        require_mcp_effect(admission, "external_execution")
    with pytest.raises(MCPPolicyViolation, match="provider_access"):
        require_mcp_effect(admission, "provider_access")
    with pytest.raises(MCPPolicyViolation, match="unknown MCP effect"):
        require_mcp_effect(admission, "shell_escape")


def test_inspect_code_has_no_hidden_process_or_provider_access(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("Probe.java").write_text("public class Probe {}\n", encoding="utf-8")
    with patch("subprocess.run") as process, \
            patch("pipeline.llm._chat_fn") as provider:
        result = mcp_server.inspect_code("Probe.java")
    assert result["status"] == "INSPECTED"
    assert result["mcp_admission"]["profile"] == "java-readonly-inspection"
    process.assert_not_called()
    provider.assert_not_called()


def test_doctor_remains_blocked_before_executable_probes(monkeypatch):
    monkeypatch.delenv("FORMALSPECGEN_MCP_STRICT_JAVA_ONLY", raising=False)
    with patch("pipeline.doctor.inspect_environment") as inspect_environment:
        result = mcp_server.doctor_environment()
    inspect_environment.assert_not_called()
    assert result["status"] == "ISOLATION_UNSUPPORTED"
    assert result["tool"] == "doctor_environment"


def test_human_trust_action_cannot_receive_an_mcp_profile():
    with pytest.raises(ValueError, match="human trust actions"):
        _capability({
            "name": "approve",
            "description": "approve evidence",
            "trust_action": True,
            "mcp_profiles": ({
                "name": "sandboxed-approval",
                "modes": ("approve",),
                "languages": ("none",),
                "backends": ("builtin",),
                "effects": (),
            },),
        })


@pytest.mark.parametrize(("isolation", "profile_change", "message"), [
    ("non-executing", {"effects": ("external_execution",)}, "cannot authorize execution"),
    ("non-executing", {"effects": ("provider_access",)}, "explicit provider allowlist"),
    ("non-executing", {"providers": ("openai",)}, "provider_access effect"),
    ("non-executing", {"effects": ("workspace_write_new",)}, "designated output scope"),
    ("non-executing", {"effects": ("shell_escape",)}, "unknown MCP profile effects"),
    ("non-executing", {"output_scope": "working-tree"}, "unknown MCP output scope"),
    ("non-executing", {"effects": ("remote_worker_dispatch",)},
     "requires A2A coordination"),
    ("a2a-coordination", {
        "effects": ("remote_worker_dispatch", "external_execution")},
     "cannot acquire local execution"),
])
def test_registry_rejects_incoherent_profile_permissions(
        isolation, profile_change, message):
    profile = {
        "name": "candidate",
        "modes": ("inspect",),
        "languages": ("java",),
        "backends": ("builtin",),
        "effects": (),
    }
    profile.update(profile_change)
    with pytest.raises(ValueError, match=message):
        _capability({
            "name": "candidate",
            "description": "candidate",
            "mcp_isolation": isolation,
            "mcp_profiles": (profile,),
        })


def test_every_strict_capability_has_visible_invocation_profiles():
    strict = mcp_capabilities(strict_isolation=True)
    assert {item.name for item in strict} == {
        "verify_code", "inspect_code", "document_code",
        "submit_work_item", "get_work_item", "get_work_artifacts",
        "cancel_work_item", "start_agent_run", "get_agent_run",
        "resume_agent_run", "cancel_agent_run"}
    assert all(item.mcp_profiles for item in strict)
    documentation = capability("document_code")
    assert documentation.cli_command == "document-code"
    assert documentation.mcp_profiles[0].output_scope == "designated-new-artifacts"
    assert documentation.mcp_profiles[0].evidence == "unreviewed-documentation"
    assert capability("doctor").mcp_profiles == ()
    trust_actions = [item for item in mcp_capabilities() if item.trust_action]
    assert trust_actions == []
