# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed admission for specific MCP invocation profiles and effects."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from .capability_registry import MCP_EFFECTS, MCPInvocationProfile, capability


MCP_ADMISSION_POLICY_VERSION = "mcp-admission-v2"


class MCPPolicyViolation(RuntimeError):
    """An effect boundary was reached without a matching admission."""


@dataclass(frozen=True)
class MCPAdmission:
    capability: str
    admitted: bool
    mode: str
    language: str
    backend: str
    provider: str | None
    requested_effects: tuple[str, ...]
    profile: MCPInvocationProfile | None = None
    reason: str = ""

    @property
    def granted_effects(self) -> tuple[str, ...]:
        if not self.admitted or self.profile is None:
            return ()
        return tuple(sorted(set(self.requested_effects) & set(self.profile.effects)))

    def permits(self, effect: str) -> bool:
        return effect in self.granted_effects

    def rejection(self) -> dict[str, Any]:
        return {
            "status": "ISOLATION_UNSUPPORTED",
            "claim": "NO_PROOF",
            "request_satisfied": False,
            "tool": self.capability,
            "mode": self.mode,
            "language": self.language,
            "backend": self.backend,
            "strict_isolation_supported": False,
            "durable_publication_supported": False,
            "admission_profile": None,
            "requested_effects": list(self.requested_effects),
            "granted_effects": [],
            "admission_policy_version": MCP_ADMISSION_POLICY_VERSION,
            "message": self.reason or "the requested invocation profile is not admitted",
        }

    def summary(self) -> dict[str, Any]:
        definition = canonical_profile_definition(self.profile) if self.profile else None
        digest = profile_definition_sha256(self.profile) if self.profile else None
        return {
            "profile": self.profile.name if self.profile else None,
            "mode": self.mode,
            "language": self.language,
            "backend": self.backend,
            "provider": self.provider,
            "requested_effects": list(self.requested_effects),
            "granted_effects": list(self.granted_effects),
            "profile_definition": definition,
            "profile_sha256": digest,
            "admission_policy_version": MCP_ADMISSION_POLICY_VERSION,
        }


def canonical_profile_definition(
        profile: MCPInvocationProfile) -> dict[str, Any]:
    """Return the stable, complete permission ceiling bound into evidence."""
    return {
        "name": profile.name,
        "modes": sorted(set(profile.modes)),
        "languages": sorted(set(profile.languages)),
        "backends": sorted(set(profile.backends)),
        "effects": sorted(set(profile.effects)),
        "providers": sorted(set(profile.providers)),
        "output_scope": profile.output_scope,
        "evidence": profile.evidence,
    }


def profile_definition_sha256(profile: MCPInvocationProfile) -> str:
    encoded = json.dumps(
        canonical_profile_definition(profile), sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def authorize_mcp_invocation(
        capability_name: str, *, mode: str, language: str, backend: str,
        effects: Iterable[str], provider: str | None = None) -> MCPAdmission:
    """Resolve one complete request against the registry's admitted profiles."""
    normalized_mode = mode.strip().lower()
    normalized_language = language.strip().lower()
    normalized_backend = backend.strip().lower()
    normalized_provider = provider.strip().lower() if provider else None
    requested_effects = tuple(sorted(set(effects)))
    unknown_effects = sorted(set(requested_effects) - MCP_EFFECTS)
    base = {
        "capability": capability_name,
        "mode": normalized_mode,
        "language": normalized_language,
        "backend": normalized_backend,
        "provider": normalized_provider,
        "requested_effects": requested_effects,
    }
    if unknown_effects:
        return MCPAdmission(
            **base, admitted=False,
            reason="unknown requested effects: " + ", ".join(unknown_effects))
    try:
        spec = capability(capability_name)
    except KeyError:
        return MCPAdmission(**base, admitted=False, reason="unknown MCP capability")
    if spec.trust_action:
        return MCPAdmission(
            **base, admitted=False,
            reason="human trust actions are never agent-admissible")
    for profile in spec.mcp_profiles:
        if normalized_mode not in profile.modes or \
                normalized_language not in profile.languages or \
                normalized_backend not in profile.backends:
            continue
        if not set(requested_effects).issubset(profile.effects):
            continue
        if normalized_provider is not None and \
                normalized_provider not in profile.providers:
            continue
        if normalized_provider is not None and "provider_access" not in profile.effects:
            continue
        return MCPAdmission(**base, admitted=True, profile=profile)
    return MCPAdmission(
        **base, admitted=False,
        reason=("no admitted profile matches the requested command, mode, language, "
                "backend, provider, and effects"))


def require_mcp_effect(admission: MCPAdmission, effect: str) -> None:
    """Recheck an admitted request at a concrete side-effect boundary."""
    if effect not in MCP_EFFECTS:
        raise MCPPolicyViolation(f"unknown MCP effect boundary: {effect}")
    if not admission.permits(effect):
        raise MCPPolicyViolation(
            f"MCP profile does not authorize {effect}: {admission.capability}")
