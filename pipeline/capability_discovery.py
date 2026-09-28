# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Data-only discovery, not environment readiness or authorization."""
from dataclasses import dataclass
import hashlib
import json

from . import __version__
from .capability_registry import CAPABILITIES, mcp_capabilities
from .mcp_policy import MCP_ADMISSION_POLICY_VERSION, canonical_profile_definition
from .workflow_contracts import WorkflowContext


@dataclass(frozen=True)
class CapabilityDiscoveryRequest:
    name: str | None = None

    def __post_init__(self):
        if self.name is not None and (not isinstance(self.name, str)
                or not self.name or len(self.name) > 128
                or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in self.name)):
            raise ValueError("name must be an exact registry, CLI, or MCP identifier (at most 128 characters)")

    def required_effects(self):
        return ()

    def as_dict(self):
        return {"schema": "formalspecgen-capability-request-v1", "name": self.name}


def discover_capabilities(request: CapabilityDiscoveryRequest, context: WorkflowContext) -> dict:
    """Describe built-in declarations with no workspace or external effects."""
    strict = {spec.name for spec in mcp_capabilities(strict_isolation=True)}
    entries = []
    for spec in sorted(CAPABILITIES, key=lambda item: item.name):
        entries.append({
            "name": spec.name, "description": spec.description,
            "cli_command": spec.cli_command, "mcp_tool": spec.mcp_tool,
            "human_only": spec.trust_action, "strict_mcp_exposed": spec.name in strict,
            "isolation": spec.mcp_isolation,
            "admission": ("HUMAN_ONLY" if spec.trust_action else
                          "PROFILE_AVAILABLE" if spec.name in strict else
                          "UNADMITTED" if spec.mcp_tool else "NOT_EXPOSED"),
            "profiles": [canonical_profile_definition(p) for p in spec.mcp_profiles],
            "claim_boundary": spec.epistemic_boundary,
        })
    registry = {"application_version": __version__, "policy_version": MCP_ADMISSION_POLICY_VERSION,
                "capabilities": entries}
    encoded = json.dumps(registry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    selected = entries if request.name is None else [item for item in entries
        if request.name in {item["name"], item["cli_command"], item["mcp_tool"]}]
    satisfied = request.name is None or len(selected) == 1
    return {
        "schema": "formalspecgen-capability-discovery-v1", "request": request.as_dict(),
        "status": "CAPABILITIES_LISTED" if satisfied else "CAPABILITY_NOT_RESOLVED",
        "request_satisfied": satisfied, "claim": "NO_PROOF",
        "code": None if satisfied else ("UNKNOWN_CAPABILITY" if not selected else "AMBIGUOUS_CAPABILITY"),
        "application_version": __version__, "policy_version": MCP_ADMISSION_POLICY_VERSION,
        "registry_sha256": hashlib.sha256(encoded).hexdigest(),
        "registry_count": len(entries), "capabilities": selected if satisfied else [],
        "scope": "installed-builtin-registry", "readiness": "NOT_ASSESSED",
        "workflow_completion": "NOT_ASSESSED", "invocation_authorized": False,
        "limitations": [
            "Static installed registry metadata, not a tool probe or live server discovery response.",
            "Profiles are permission ceilings; each invocation still requires authorization and request validation.",
            "Profile availability does not guarantee source support, backend readiness, proof success, or workflow completion.",
            "No providers, executables, workspace configuration, or workspace plugins are contacted or loaded.",
            "This registry is not the complete CLI parser inventory or a deployment plugin inventory.",
        ],
    }
