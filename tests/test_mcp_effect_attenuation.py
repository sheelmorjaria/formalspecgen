# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""An invocation receives only the effects it explicitly requested."""

from dataclasses import replace
from itertools import combinations

import pytest

from pipeline.mcp_policy import (
    MCP_ADMISSION_POLICY_VERSION,
    MCPPolicyViolation,
    authorize_mcp_invocation,
    profile_definition_sha256,
    require_mcp_effect,
)


VERIFICATION_EFFECTS = (
    "workspace_read", "external_execution", "evidence_publication",
)
EFFECT_SUBSETS = tuple(
    combination
    for size in range(len(VERIFICATION_EFFECTS) + 1)
    for combination in combinations(VERIFICATION_EFFECTS, size)
)


@pytest.mark.parametrize("requested", EFFECT_SUBSETS)
def test_verification_effects_are_attenuated_to_each_request(requested):
    admission = authorize_mcp_invocation(
        "verify_code", mode="esc", language="java", backend="openjml",
        effects=requested)
    assert admission.admitted is True
    assert set(admission.granted_effects) == set(requested)
    for effect in VERIFICATION_EFFECTS:
        assert admission.permits(effect) is (effect in requested)
        if effect in requested:
            require_mcp_effect(admission, effect)
        else:
            with pytest.raises(MCPPolicyViolation, match=effect):
                require_mcp_effect(admission, effect)


def test_complete_verification_request_remains_supported_and_auditable():
    admission = authorize_mcp_invocation(
        "verify_code", mode="esc", language="java", backend="openjml",
        effects=VERIFICATION_EFFECTS)
    summary = admission.summary()
    assert admission.admitted is True
    assert set(summary["requested_effects"]) == set(VERIFICATION_EFFECTS)
    assert set(summary["granted_effects"]) == set(VERIFICATION_EFFECTS)
    assert summary["profile_definition"] == {
        "name": "java-openjml-verification",
        "modes": ["check", "esc", "parse"],
        "languages": ["java", "jml"],
        "backends": ["openjml"],
        "effects": ["evidence_publication", "external_execution", "workspace_read"],
        "providers": [],
        "output_scope": "immutable-evidence-only",
        "evidence": "execution-observation-and-terminal-manifest",
    }
    assert summary["profile_sha256"] == \
        profile_definition_sha256(admission.profile)
    assert len(summary["profile_sha256"]) == 64
    changed = replace(admission.profile, evidence="different-evidence-requirement")
    assert profile_definition_sha256(changed) != summary["profile_sha256"]
    assert summary["admission_policy_version"] == MCP_ADMISSION_POLICY_VERSION


def test_disallowed_effect_is_rejected_instead_of_granted():
    admission = authorize_mcp_invocation(
        "verify_code", mode="esc", language="java", backend="openjml",
        effects=("workspace_read", "workspace_write_new"))
    assert admission.admitted is False
    assert admission.granted_effects == ()
    assert admission.permits("workspace_read") is False


def test_readonly_inspection_grants_only_its_requested_read():
    admission = authorize_mcp_invocation(
        "inspect_code", mode="inspect", language="java",
        backend="builtin-java-inspector", effects=("workspace_read",))
    assert admission.granted_effects == ("workspace_read",)
    assert admission.permits("workspace_read") is True
    assert admission.permits("external_execution") is False
    assert admission.permits("provider_access") is False


def test_unknown_effect_boundary_fails_even_when_request_is_admitted():
    admission = authorize_mcp_invocation(
        "verify_code", mode="esc", language="java", backend="openjml",
        effects=VERIFICATION_EFFECTS)
    with pytest.raises(MCPPolicyViolation, match="unknown MCP effect"):
        require_mcp_effect(admission, "unknown")
