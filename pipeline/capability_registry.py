# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Declarative cross-interface capability registry.

The migration is intentionally incremental: every MCP exposure is listed here,
while high-drift commands move their argparse schema here one at a time.  A
capability cannot be registered on MCP without a registry entry.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ArgumentSpec:
    flags: tuple[str, ...]
    kwargs: dict[str, Any]


@dataclass(frozen=True)
class ClaimStage:
    claim: str
    minimum_step: int


@dataclass(frozen=True)
class MilestoneMetadata:
    lane: str
    deployment_split: str
    required_judges: tuple[str, ...]
    claims: tuple[ClaimStage, ...]
    claims_forbidden: tuple[str, ...]
    assumptions: tuple[str, ...]
    deployment_profiles: tuple[str, ...]
    hardware_profiles: tuple[str, ...]
    artifact_hash_bindings: tuple[str, ...]
    maturity_from: str
    maturity_to: str
    maturity_requires_step: int
    current_step: int
    step_status: str
    current_maturity: str
    completed_claims: tuple[str, ...]


@dataclass(frozen=True)
class CapabilitySpec:
    name: str
    description: str
    cli_command: str | None = None
    mcp_tool: str | None = None
    arguments: tuple[ArgumentSpec, ...] = ()
    epistemic_boundary: str = "No claim is minted without its named judge."
    trust_action: bool = False
    milestone: MilestoneMetadata | None = None


def _capability(value: dict[str, Any]) -> CapabilitySpec:
    """Decode an external package's data-only capability declaration."""
    milestone_value = value.get("milestone")
    milestone = None
    if milestone_value is not None:
        milestone_data = dict(milestone_value)
        milestone_data["claims"] = tuple(
            ClaimStage(**claim) if isinstance(claim, dict) else claim
            for claim in milestone_data.get("claims", ())
        )
        milestone = MilestoneMetadata(**milestone_data)
    arguments = tuple(
        ArgumentSpec(tuple(argument["flags"]), dict(argument.get("kwargs", {})))
        if isinstance(argument, dict)
        else argument
        for argument in value.get("arguments", ())
    )
    return CapabilitySpec(
        name=value["name"],
        description=value["description"],
        cli_command=value.get("cli_command"),
        mcp_tool=value.get("mcp_tool"),
        arguments=arguments,
        epistemic_boundary=value.get(
            "epistemic_boundary", "No claim is minted without its named judge."
        ),
        trust_action=value.get("trust_action", False),
        milestone=milestone,
    )


_MCP_TOOLS = (
    "verify_code",
    "validate_architecture",
    "implement_code",
    "inspect_code",
    "analyze_codebase",
    "document_code",
    "assess_security",
    "security_inspect",
    "security_exploit",
    "remediate_code",
    "correct_behavior",
    "apply_refactor",
    "verify_refactor",
    "verify_bisimulation",
    "optimize_algorithm",
    "discover_algorithms",
    "validate_domain",
    "compose",
    "reverify_composition",
    "unified_system",
    "draft_canonical_contract",
    "architecture",
    "system",
    "prove_equivalence",
    "generate_traceability_matrix",
    "verify_unbounded",
    "verify_linearizability",
    "verify_distributed",
    "verify_heap",
    "verify_hal",
    "macro_translate",
    "verify_lockfree",
    "verify_weak_memory",
    "verify_wcet",
    "verify_liveness",
    "verify_dma",
    "extract_intrusive_list",
    "resolve_callbacks",
)

_GENERIC_DATA = [{'name': 'verify_code',
  'description': 'verify code',
  'cli_command': None,
  'mcp_tool': 'verify_code',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'validate_architecture',
  'description': 'validate architecture',
  'cli_command': None,
  'mcp_tool': 'validate_architecture',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'implement_code',
  'description': 'implement code',
  'cli_command': None,
  'mcp_tool': 'implement_code',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'inspect_code',
  'description': 'inspect code',
  'cli_command': None,
  'mcp_tool': 'inspect_code',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'analyze_codebase',
  'description': 'analyze codebase',
  'cli_command': None,
  'mcp_tool': 'analyze_codebase',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'document_code',
  'description': 'document code',
  'cli_command': None,
  'mcp_tool': 'document_code',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'assess_security',
  'description': 'assess security',
  'cli_command': None,
  'mcp_tool': 'assess_security',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'security_inspect',
  'description': 'security inspect',
  'cli_command': None,
  'mcp_tool': 'security_inspect',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'security_exploit',
  'description': 'security exploit',
  'cli_command': None,
  'mcp_tool': 'security_exploit',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'remediate_code',
  'description': 'remediate code',
  'cli_command': None,
  'mcp_tool': 'remediate_code',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'correct_behavior',
  'description': 'correct behavior',
  'cli_command': None,
  'mcp_tool': 'correct_behavior',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'apply_refactor',
  'description': 'apply refactor',
  'cli_command': None,
  'mcp_tool': 'apply_refactor',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'verify_refactor',
  'description': 'verify refactor',
  'cli_command': None,
  'mcp_tool': 'verify_refactor',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'verify_bisimulation',
  'description': 'verify bisimulation',
  'cli_command': None,
  'mcp_tool': 'verify_bisimulation',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'optimize_algorithm',
  'description': 'optimize algorithm',
  'cli_command': None,
  'mcp_tool': 'optimize_algorithm',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'discover_algorithms',
  'description': 'discover algorithms',
  'cli_command': None,
  'mcp_tool': 'discover_algorithms',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'validate_domain',
  'description': 'validate domain',
  'cli_command': None,
  'mcp_tool': 'validate_domain',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'compose',
  'description': 'compose',
  'cli_command': None,
  'mcp_tool': 'compose',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'reverify_composition',
  'description': 'reverify composition',
  'cli_command': None,
  'mcp_tool': 'reverify_composition',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'unified_system',
  'description': 'unified system',
  'cli_command': None,
  'mcp_tool': 'unified_system',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'draft_canonical_contract',
  'description': 'draft canonical contract',
  'cli_command': None,
  'mcp_tool': 'draft_canonical_contract',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'architecture',
  'description': 'architecture',
  'cli_command': None,
  'mcp_tool': 'architecture',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'system',
  'description': 'system',
  'cli_command': None,
  'mcp_tool': 'system',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'prove_equivalence',
  'description': 'prove equivalence',
  'cli_command': None,
  'mcp_tool': 'prove_equivalence',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'generate_traceability_matrix',
  'description': 'generate traceability matrix',
  'cli_command': None,
  'mcp_tool': 'generate_traceability_matrix',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'verify_unbounded',
  'description': 'verify unbounded',
  'cli_command': None,
  'mcp_tool': 'verify_unbounded',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'verify_linearizability',
  'description': 'verify linearizability',
  'cli_command': None,
  'mcp_tool': 'verify_linearizability',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'verify_distributed',
  'description': 'verify distributed',
  'cli_command': None,
  'mcp_tool': 'verify_distributed',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'verify_heap',
  'description': 'verify heap',
  'cli_command': None,
  'mcp_tool': 'verify_heap',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'verify_hal',
  'description': 'verify hal',
  'cli_command': None,
  'mcp_tool': 'verify_hal',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'macro_translate',
  'description': 'macro translate',
  'cli_command': None,
  'mcp_tool': 'macro_translate',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'verify_lockfree',
  'description': 'verify lockfree',
  'cli_command': None,
  'mcp_tool': 'verify_lockfree',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'verify_weak_memory',
  'description': 'verify weak memory',
  'cli_command': None,
  'mcp_tool': 'verify_weak_memory',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'verify_wcet',
  'description': 'verify wcet',
  'cli_command': None,
  'mcp_tool': 'verify_wcet',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'verify_liveness',
  'description': 'verify liveness',
  'cli_command': None,
  'mcp_tool': 'verify_liveness',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'verify_dma',
  'description': 'verify dma',
  'cli_command': None,
  'mcp_tool': 'verify_dma',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'extract_intrusive_list',
  'description': 'extract intrusive list',
  'cli_command': None,
  'mcp_tool': 'extract_intrusive_list',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'resolve_callbacks',
  'description': 'resolve callbacks',
  'cli_command': None,
  'mcp_tool': 'resolve_callbacks',
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': False,
  'milestone': None},
 {'name': 'doctor',
  'description': 'Report judge readiness and evidence ceilings.',
  'cli_command': 'doctor',
  'mcp_tool': 'doctor_environment',
  'arguments': (),
  'epistemic_boundary': 'Always claim=NO_PROOF.',
  'trust_action': False,
  'milestone': None},
 {'name': 'promote_domain',
  'description': 'Human acceptance of reviewed evidence.',
  'cli_command': 'promote-domain',
  'mcp_tool': None,
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': True,
  'milestone': None},
 {'name': 'sign_artifact',
  'description': 'Human reviewer signature action.',
  'cli_command': 'sign-artifact',
  'mcp_tool': None,
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': True,
  'milestone': None},
 {'name': 'manage_trust',
  'description': 'Human reviewer key-policy action.',
  'cli_command': 'manage-trust',
  'mcp_tool': None,
  'arguments': (),
  'epistemic_boundary': 'No claim is minted without its named judge.',
  'trust_action': True,
  'milestone': None},
 {'name': 'm55_vfs',
  'description': 'Bounded VFS state machine, inode cache, and Rust refinement lane.',
  'cli_command': None,
  'mcp_tool': None,
  'arguments': (),
  'epistemic_boundary': 'Extraction never implies refinement; production requires the hash-bound '
                        'native gate in deliverable 4.',
  'trust_action': False,
  'milestone': {'lane': 'M55_vfs',
                'deployment_split': 'shared_algorithmic',
                'required_judges': ('TLC', 'Prusti', 'Z3'),
                'claims': ({'claim': 'BOUNDED_ARCHITECTURE_EVIDENCE', 'minimum_step': 3},
                           {'claim': 'SOURCE_MODEL_REFINEMENT', 'minimum_step': 4},
                           {'claim': 'HARDWARE_MEMORY_BOUND_PROVED', 'minimum_step': 4}),
                'claims_forbidden': ('SOURCE_MODEL_REFINEMENT_WITHOUT_NATIVE_GATE',
                                     'HARDWARE_MEMORY_BOUND_PROVED_WITHOUT_PROFILE_BOUND_POOL',
                                     'PRODUCTION_UNTIL_ALL_STEP_4_GATES'),
                'assumptions': ('hardware_page_table_walker:judge_pending',
                                'DMA physical isolation belongs to M39/M56'),
                'deployment_profiles': ('microkernel', 'monolith'),
                'hardware_profiles': ('n150', 'r52'),
                'artifact_hash_bindings': ('domains/candidates/vfs_bounded.v2.yaml',
                                           'domains/candidates/vfs_bounded.v2.validation.json',
                                           'domains/v2/vfs_bounded.json',
                                           'domains/v2/vfs_bounded.rust-refinement.yaml',
                                           'Vfs.rs'),
                'maturity_from': 'scaffold',
                'maturity_to': 'production',
                'maturity_requires_step': 4,
                'current_step': 4,
                'step_status': 'complete',
                'current_maturity': 'production',
                'completed_claims': ('BOUNDED_ARCHITECTURE_EVIDENCE',
                                     'SOURCE_MODEL_REFINEMENT',
                                     'HARDWARE_MEMORY_BOUND_PROVED')}}]

CAPABILITIES: tuple[CapabilitySpec, ...] = tuple(
    _capability(item) for item in _GENERIC_DATA
)


def capability(name: str) -> CapabilitySpec:
    matches = [item for item in CAPABILITIES if item.name == name]
    if len(matches) != 1:
        raise KeyError(f"capability registry expected exactly one {name!r} entry")
    return matches[0]


def mcp_capabilities() -> tuple[CapabilitySpec, ...]:
    return tuple(
        item for item in CAPABILITIES if item.mcp_tool and not item.trust_action
    )


def milestone_capabilities() -> tuple[CapabilitySpec, ...]:
    return tuple(item for item in CAPABILITIES if item.milestone is not None)


def add_cli_parser(
    subparsers: argparse._SubParsersAction, name: str
) -> argparse.ArgumentParser:
    spec = capability(name)
    if spec.cli_command is None or not spec.arguments:
        raise ValueError(f"capability {name!r} has no generated CLI schema")
    parser = subparsers.add_parser(spec.cli_command, help=spec.description)
    for argument in spec.arguments:
        parser.add_argument(*argument.flags, **argument.kwargs)
    return parser
