# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed admission for specific MCP invocation profiles and effects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .capability_registry import MCP_EFFECTS, MCPInvocationProfile, capability


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

    def permits(self, effect: str) -> bool:
        return bool(
            self.admitted
            and self.profile is not None
            and effect in self.profile.effects
        )

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
            "message": self.reason or "the requested invocation profile is not admitted",
        }

    def summary(self) -> dict[str, Any]:
        return {
            "profile": self.profile.name if self.profile else None,
            "mode": self.mode,
            "language": self.language,
            "backend": self.backend,
            "provider": self.provider,
            "effects": list(self.requested_effects),
        }


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
