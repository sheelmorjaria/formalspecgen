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


_MCP_TOOLS = (
    "verify_code", "validate_architecture", "implement_code", "inspect_code",
    "analyze_codebase", "document_code", "assess_security", "security_inspect",
    "security_exploit", "remediate_code", "correct_behavior", "apply_refactor",
    "verify_refactor", "verify_bisimulation", "optimize_algorithm",
    "discover_algorithms", "validate_domain", "compose", "reverify_composition",
    "unified_system", "draft_canonical_contract", "architecture", "system",
    "prove_equivalence", "generate_traceability_matrix", "verify_unbounded",
    "verify_linearizability", "verify_distributed", "verify_heap", "verify_hal",
    "macro_translate", "verify_lockfree", "verify_weak_memory", "verify_wcet",
    "verify_liveness", "verify_dma", "extract_intrusive_list", "resolve_callbacks",
)

CAPABILITIES: tuple[CapabilitySpec, ...] = tuple(
    CapabilitySpec(name=name, description=name.replace("_", " "), mcp_tool=name)
    for name in _MCP_TOOLS
) + (
    CapabilitySpec(
        name="verify_kernel",
        description=("Run the multi-architecture OS evidence lattice for an explicit "
                     "deployment manifest and one or more hardware profiles."),
        cli_command="verify-kernel", mcp_tool="verify_kernel",
        arguments=(
            ArgumentSpec(("kernel_dir",), {"help": "directory containing the deployment manifest and sources"}),
            ArgumentSpec(("--profile",), {"action": "append", "required": True,
                                          "metavar": "PROFILE_JSON",
                                          "help": "human-owned hardware profile (repeatable)"}),
            ArgumentSpec(("--manifest",), {"default": "kernel.json",
                                           "help": "kernel.json or monolith.json deployment manifest"}),
            ArgumentSpec(("--json",), {"dest": "json_out", "default": None}),
        ),
        epistemic_boundary=("Mints only claim entries returned by their real or deterministic "
                            "judges; absent judges remain judge_pending."),
    ),
    CapabilitySpec(name="doctor", description="Report judge readiness and evidence ceilings.",
                   cli_command="doctor", epistemic_boundary="Always claim=NO_PROOF."),
    CapabilitySpec(
        name="m55_vfs",
        description="Bounded VFS state machine, inode cache, and Rust refinement lane.",
        epistemic_boundary=("Extraction never implies refinement; production requires the "
                            "hash-bound native gate in deliverable 4."),
        milestone=MilestoneMetadata(
            lane="M55_vfs", deployment_split="shared_algorithmic",
            required_judges=("TLC", "Prusti", "Z3"),
            claims=(ClaimStage("BOUNDED_ARCHITECTURE_EVIDENCE", 3),
                    ClaimStage("SOURCE_MODEL_REFINEMENT", 4),
                    ClaimStage("HARDWARE_MEMORY_BOUND_PROVED", 4)),
            claims_forbidden=("SOURCE_MODEL_REFINEMENT_WITHOUT_NATIVE_GATE",
                              "HARDWARE_MEMORY_BOUND_PROVED_WITHOUT_PROFILE_BOUND_POOL",
                              "PRODUCTION_UNTIL_ALL_STEP_4_GATES"),
            assumptions=("hardware_page_table_walker:judge_pending",
                         "DMA physical isolation belongs to M39/M56"),
            deployment_profiles=("microkernel", "monolith"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=("domains/candidates/vfs_bounded.v2.yaml",
                                    "domains/candidates/vfs_bounded.v2.validation.json",
                                    "domains/v2/vfs_bounded.json",
                                    "domains/v2/vfs_bounded.rust-refinement.yaml",
                                    "Vfs.rs"),
            maturity_from="scaffold", maturity_to="production",
            maturity_requires_step=4, current_step=4, step_status="complete",
            current_maturity="production",
            completed_claims=("BOUNDED_ARCHITECTURE_EVIDENCE",
                              "SOURCE_MODEL_REFINEMENT",
                              "HARDWARE_MEMORY_BOUND_PROVED"),
        ),
    ),
    CapabilitySpec(
        name="m56_virtio_blk",
        description="Confined user-space virtio-blk external-adapter lane.",
        epistemic_boundary=("Device behavior remains unverified; only DMA ranges, "
                            "syscall ownership, and bounded IPC routing are judged."),
        milestone=MilestoneMetadata(
            lane="M56_virtio_blk", deployment_split="profile_divergent_boundary",
            required_judges=("ESBMC",),
            claims=(ClaimStage("UNVERIFIED_EXTERNAL_ADAPTER", 1),
                    ClaimStage("DMA_ISOLATION_PROVED", 1),
                    ClaimStage("SYSCALL_BOUNDARY_PROVED", 1),
                    ClaimStage("IPC_ENDPOINT_TABLE_PROVED", 1),
                    ClaimStage("MPSC_BOUNDED_PARTITION_PROVED", 1)),
            claims_forbidden=("EXTERNAL_IO_SAFETY_PROVED",
                              "DRIVER_DEVICE_BEHAVIOR_PROVED"),
            assumptions=("virtio device behavior:unverified_external",
                         "hardware IOMMU enforcement:judge_pending"),
            deployment_profiles=("microkernel", "monolith"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/vfs/virtio_blk.rs",
                "examples/formalkernel/kernel/vfs/virtio_blk_dma.c",
                "examples/formalkernel/kernel/syscalls.json",
                "examples/formalkernel/kernel/ipc.json"),
            maturity_from="scaffold", maturity_to="boundary-contained",
            maturity_requires_step=1, current_step=1, step_status="complete",
            current_maturity="boundary-contained",
            completed_claims=("UNVERIFIED_EXTERNAL_ADAPTER",
                              "DMA_ISOLATION_PROVED",
                              "SYSCALL_BOUNDARY_PROVED",
                              "IPC_ENDPOINT_TABLE_PROVED",
                              "MPSC_BOUNDED_PARTITION_PROVED"),
        ),
    ),
    CapabilitySpec(
        name="m57_elf_loader",
        description="Bounded ELF64 process-loader and M48 permission lane.",
        epistemic_boundary=("Proves bounded parsing, layout, and declared UXN/AP "
                            "correspondence; hardware page walks and ERET remain pending."),
        milestone=MilestoneMetadata(
            lane="M57_elf_loader", deployment_split="microkernel_only",
            required_judges=(),
            claims=(ClaimStage("ELF_SEGMENT_LAYOUT_PROVED", 1),
                    ClaimStage("ELF_PERMISSION_CORRESPONDENCE_PROVED", 1),
                    ClaimStage("SPATIAL_ISOLATION_PROVED", 1)),
            claims_forbidden=("HARDWARE_PAGE_TABLE_WALK_PROVED",
                              "HARDWARE_EXCEPTION_LEVEL_TRANSITION_PROVED"),
            assumptions=("hardware page-table walker:judge_pending",
                         "EL1-to-EL0 ERET transition belongs to M62"),
            deployment_profiles=("microkernel",),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/elf_loader.json",
                "examples/formalkernel/kernel/loader/elf_loader.rs",
                "examples/formalkernel/kernel/mmu.json"),
            maturity_from="scaffold", maturity_to="boundary-contained",
            maturity_requires_step=1, current_step=1, step_status="complete",
            current_maturity="boundary-contained",
            completed_claims=("ELF_SEGMENT_LAYOUT_PROVED",
                              "ELF_PERMISSION_CORRESPONDENCE_PROVED",
                              "SPATIAL_ISOLATION_PROVED"),
        ),
    ),
    CapabilitySpec(
        name="m58_pq_tls",
        description="Bounded ML-KEM/ML-DSA TLS handshake-session pool.",
        epistemic_boundary=("Z3 proves only the exact memory ceiling; liboqs "
                            "correctness and cryptographic strength remain unproved."),
        milestone=MilestoneMetadata(
            lane="M58_pq_tls", deployment_split="shared_algorithmic",
            required_judges=("Z3",),
            claims=(ClaimStage("HARDWARE_MEMORY_BOUND_PROVED", 1),),
            claims_forbidden=("CRYPTOGRAPHIC_STRENGTH_PROVED",
                              "LIBOQS_IMPLEMENTATION_PROVED"),
            assumptions=("liboqs is an unverified external adapter",
                         "algorithm parameter sizes are human-reviewed inputs"),
            deployment_profiles=("microkernel", "monolith"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/net/pq_tls.json",
                "examples/formalkernel/kernel/net/pq_tls_pool.rs"),
            maturity_from="scaffold", maturity_to="bounded-evidence",
            maturity_requires_step=1, current_step=1, step_status="complete",
            current_maturity="bounded-evidence",
            completed_claims=("HARDWARE_MEMORY_BOUND_PROVED",),
        ),
    ),
    CapabilitySpec(
        name="m59_tls_handshake",
        description="Bounded TLC-checked PQ-TLS handshake control-state model.",
        epistemic_boundary=("TLC proves only the reviewed finite transition graph; "
                            "transcript authenticity, cryptography, and native refinement remain unproved."),
        milestone=MilestoneMetadata(
            lane="M59_tls_handshake", deployment_split="shared_algorithmic",
            required_judges=("TLC",),
            claims=(ClaimStage("BOUNDED_ARCHITECTURE_EVIDENCE", 1),),
            claims_forbidden=("CRYPTOGRAPHIC_STRENGTH_PROVED",
                              "TLS_TRANSCRIPT_AUTHENTICITY_PROVED",
                              "MBEDTLS_IMPLEMENTATION_REFINEMENT_PROVED"),
            assumptions=("external cryptographic outcomes are nondeterministic",
                         "weak fairness applies to handshake control progress"),
            deployment_profiles=("microkernel", "monolith"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/net/mbedtls_handshake_legacy.c",
                "examples/formalkernel/kernel/net/tls_handshake.json",
                "examples/formalkernel/kernel/net/tls_handshake.validation.json"),
            maturity_from="scaffold", maturity_to="bounded-evidence",
            maturity_requires_step=1, current_step=1, step_status="complete",
            current_maturity="bounded-evidence",
            completed_claims=("BOUNDED_ARCHITECTURE_EVIDENCE",),
        ),
    ),
    CapabilitySpec(
        name="m60_pq_wcet",
        description="Deployment-split PQ workload WCET and preemption lane.",
        epistemic_boundary=("Microkernel evidence bounds the EL1 scheduler handler; "
                            "monolith evidence bounds cooperative EL1 chunks. Silicon interrupt delivery remains pending."),
        milestone=MilestoneMetadata(
            lane="M60_pq_wcet", deployment_split="profile_divergent_boundary",
            required_judges=(),
            claims=(ClaimStage("PQ_PREEMPTION_BOUND_PROVED", 1),
                    ClaimStage("PQ_COOPERATIVE_WCET_BOUND_PROVED", 1)),
            claims_forbidden=("HARDWARE_INTERRUPT_DELIVERY_PROVED",
                              "MONOLITH_PREEMPTIVE_ISOLATION_PROVED"),
            assumptions=("profile instruction costs are human-owned",
                         "PQ workload remains EL0 in the microkernel",
                         "monolith invokes the hash-bound cooperative yield"),
            deployment_profiles=("microkernel", "monolith"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/net/pq_ntt_workload.c",
                "examples/formalkernel/kernel/net/pq_wcet.json",
                "examples/formalkernel/kernel/scheduler/sched_tick.c"),
            maturity_from="scaffold", maturity_to="bounded-evidence",
            maturity_requires_step=1, current_step=1, step_status="complete",
            current_maturity="bounded-evidence",
            completed_claims=("PQ_PREEMPTION_BOUND_PROVED",
                              "PQ_COOPERATIVE_WCET_BOUND_PROVED"),
        ),
    ),
    CapabilitySpec(name="promote_domain", description="Human acceptance of reviewed evidence.",
                   cli_command="promote-domain", trust_action=True),
    CapabilitySpec(name="sign_artifact", description="Human reviewer signature action.",
                   cli_command="sign-artifact", trust_action=True),
    CapabilitySpec(name="manage_trust", description="Human reviewer key-policy action.",
                   cli_command="manage-trust", trust_action=True),
)


def capability(name: str) -> CapabilitySpec:
    matches = [item for item in CAPABILITIES if item.name == name]
    if len(matches) != 1:
        raise KeyError(f"capability registry expected exactly one {name!r} entry")
    return matches[0]


def mcp_capabilities() -> tuple[CapabilitySpec, ...]:
    return tuple(item for item in CAPABILITIES if item.mcp_tool and not item.trust_action)


def milestone_capabilities() -> tuple[CapabilitySpec, ...]:
    return tuple(item for item in CAPABILITIES if item.milestone is not None)


def add_cli_parser(subparsers: argparse._SubParsersAction, name: str) -> argparse.ArgumentParser:
    spec = capability(name)
    if spec.cli_command is None or not spec.arguments:
        raise ValueError(f"capability {name!r} has no generated CLI schema")
    parser = subparsers.add_parser(spec.cli_command, help=spec.description)
    for argument in spec.arguments:
        parser.add_argument(*argument.flags, **argument.kwargs)
    return parser
