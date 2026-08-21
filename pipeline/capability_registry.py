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
    CapabilitySpec(
        name="m61_herd7",
        description="Hash-bound weak-memory litmus simulation with herd7.",
        epistemic_boundary=("Proves a forbidden outcome unreachable in the "
                            "declared herd model; does not prove source-to-litmus "
                            "refinement or physical silicon behavior."),
        milestone=MilestoneMetadata(
            lane="M61_herd7", deployment_split="shared_algorithmic",
            required_judges=("herd7",),
            claims=(ClaimStage("BARRIER_CORRESPONDENCE_PROVED", 1),
                    ClaimStage("WEAK_MEMORY_SAFETY_PROVED", 1)),
            claims_forbidden=("COMPILED_SOURCE_LITMUS_REFINEMENT_PROVED",
                              "PHYSICAL_SILICON_MEMORY_MODEL_PROVED"),
            assumptions=("litmus abstraction is human-reviewed",
                         "hardware implements the declared architectural model"),
            deployment_profiles=("microkernel", "monolith"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/weak_memory.json",
                "examples/formalkernel/kernel/weak_memory/x86_message_passing.litmus",
                "examples/formalkernel/kernel/weak_memory/aarch64_message_passing.litmus"),
            maturity_from="structural-evidence", maturity_to="model-evidence",
            maturity_requires_step=1, current_step=1,
            step_status="complete", current_maturity="model-evidence",
            completed_claims=("BARRIER_CORRESPONDENCE_PROVED",
                              "WEAK_MEMORY_SAFETY_PROVED"),
        ),
    ),
    CapabilitySpec(
        name="m62_exception_transition",
        description="TLC-checked EL1/EL0 exception control-state transition.",
        epistemic_boundary=("Proves the reviewed bounded transition model; "
                            "actual ERET semantics and compiled vector refinement "
                            "remain outside the claim."),
        milestone=MilestoneMetadata(
            lane="M62_exception_transition",
            deployment_split="microkernel_only", required_judges=("TLC",),
            claims=(ClaimStage("EXCEPTION_LEVEL_TRANSITION_MODEL_PROVED", 1),),
            claims_forbidden=("HARDWARE_EXCEPTION_LEVEL_TRANSITION_PROVED",
                              "COMPILED_VECTOR_REFINEMENT_PROVED"),
            assumptions=("ARM ERET follows the architectural specification",
                         "exception-vector assembly refines the reviewed model"),
            deployment_profiles=("microkernel",),
            hardware_profiles=("r52",),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/exception_transition.json",
                "examples/formalkernel/kernel/exception_transition.validation.json",
                "examples/formalkernel/kernel/mmu.json",
                "examples/formalkernel/kernel/syscalls.json",
                "examples/formalkernel/kernel/elf_loader.json"),
            maturity_from="scaffold", maturity_to="model-evidence",
            maturity_requires_step=1, current_step=1, step_status="complete",
            current_maturity="model-evidence",
            completed_claims=("EXCEPTION_LEVEL_TRANSITION_MODEL_PROVED",),
        ),
    ),
    CapabilitySpec(
        name="m63_scheduler_liveness",
        description="Per-task bounded scheduler starvation freedom under fairness.",
        epistemic_boundary=("TLC proves continuously-ready bounded tasks progress "
                            "under weak scheduler fairness; hardware timer fairness, "
                            "unbounded tasks, and C/model refinement remain unproved."),
        milestone=MilestoneMetadata(
            lane="M63_scheduler_liveness",
            deployment_split="shared_algorithmic", required_judges=("TLC",),
            claims=(ClaimStage("SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED", 1),),
            claims_forbidden=("UNBOUNDED_SCHEDULER_LIVENESS_PROVED",
                              "HARDWARE_TIMER_FAIRNESS_PROVED",
                              "SCHEDULER_SOURCE_MODEL_REFINEMENT_PROVED"),
            assumptions=("WF_vars(Schedule) weak fairness",
                         "bounded task set of three reviewed task identities"),
            deployment_profiles=("microkernel", "monolith"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/scheduler/runqueue.c",
                "examples/formalkernel/kernel/scheduler/liveness.json",
                "examples/formalkernel/kernel/scheduler/liveness.validation.json"),
            maturity_from="bounded-safety", maturity_to="temporal-model-evidence",
            maturity_requires_step=1, current_step=1, step_status="complete",
            current_maturity="temporal-model-evidence",
            completed_claims=("SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED",),
        ),
    ),
    CapabilitySpec(
        name="m64_user_heap",
        description="Fixed-capacity allocation-free EL0 process heap.",
        epistemic_boundary=("Kani proves bounded allocator operations over the "
                            "exact Rust source; physical frame assignment and "
                            "general-purpose libc allocation remain unproved."),
        milestone=MilestoneMetadata(
            lane="M64_user_heap", deployment_split="microkernel_only",
            required_judges=("Kani",),
            claims=(ClaimStage("USER_HEAP_CAPACITY_PROVED", 1),),
            claims_forbidden=("PHYSICAL_USER_HEAP_MAPPING_PROVED",
                              "GENERAL_PURPOSE_ALLOCATOR_PROVED"),
            assumptions=("kernel grants the declared 4096-byte frame window",),
            deployment_profiles=("microkernel",),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/user_heap.json",
                "examples/formalkernel/kernel/user/heap.rs",
                "examples/formalkernel/boot/proofs/src/lib.rs"),
            maturity_from="scaffold", maturity_to="bounded-evidence",
            maturity_requires_step=1, current_step=1, step_status="complete",
            current_maturity="bounded-evidence",
            completed_claims=("USER_HEAP_CAPACITY_PROVED",),
        ),
    ),
    CapabilitySpec(
        name="m65_server_capabilities",
        description="Z3-checked multi-server capability noninterference.",
        epistemic_boundary=("Proves the reviewed finite routing matrix; token "
                            "unforgeability and hardware syscall enforcement "
                            "remain MMU/syscall assumptions."),
        milestone=MilestoneMetadata(
            lane="M65_server_capabilities", deployment_split="microkernel_only",
            required_judges=("Z3",),
            claims=(ClaimStage("SERVER_CAPABILITY_NONINTERFERENCE_PROVED", 1),),
            claims_forbidden=("CAPABILITY_TOKEN_UNFORGEABILITY_PROVED",
                              "HARDWARE_CAPABILITY_ENFORCEMENT_PROVED"),
            assumptions=("M48 spatial isolation", "M49 syscall mediation"),
            deployment_profiles=("microkernel",),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/server_capabilities.json",),
            maturity_from="scaffold", maturity_to="bounded-evidence",
            maturity_requires_step=1, current_step=1, step_status="complete",
            current_maturity="bounded-evidence",
            completed_claims=("SERVER_CAPABILITY_NONINTERFERENCE_PROVED",),
        ),
    ),
    CapabilitySpec(
        name="m66_unikernel_profile",
        description="Feature-gated single-EL1 unikernel deployment profile.",
        epistemic_boundary=("Cargo proves the hash-bound no-std profile builds "
                            "with boundary lanes absent; bootability, runtime "
                            "behavior, and fault containment remain unproved."),
        milestone=MilestoneMetadata(
            lane="M66_unikernel_profile", deployment_split="unikernel_only",
            required_judges=("Cargo",),
            claims=(ClaimStage("UNIKERNEL_BUILD_PROVED", 1),),
            claims_forbidden=("UNIKERNEL_BOOT_PROVED",
                              "UNIKERNEL_FAULT_CONTAINMENT_PROVED",
                              "UNIKERNEL_RUNTIME_BEHAVIOR_PROVED"),
            assumptions=("single EL1 address space",
                         "shared algorithmic evidence remains source-bound"),
            deployment_profiles=("unikernel",),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/unikernel.json",
                "examples/formalkernel/unikernel/Cargo.toml",
                "examples/formalkernel/unikernel/src/lib.rs"),
            maturity_from="scaffold", maturity_to="bounded-evidence",
            maturity_requires_step=1, current_step=1, step_status="complete",
            current_maturity="bounded-evidence",
            completed_claims=("UNIKERNEL_BUILD_PROVED",),
        ),
    ),
    CapabilitySpec(
        name="m67_cortex_r52_port",
        description="Profile-bound Cortex-R52 ITCM/DTCM placement gate.",
        epistemic_boundary=("Proves declared memory-map and linker placement "
                            "correspondence; physical boot, SoC address "
                            "conformance, and measured WCET require hardware."),
        milestone=MilestoneMetadata(
            lane="M67_cortex_r52_port", deployment_split="shared_hardware",
            required_judges=("DeterministicGate", "PhysicalBoard:pending"),
            claims=(ClaimStage("R52_TCM_PLACEMENT_PROVED", 1),),
            claims_forbidden=("R52_PHYSICAL_BOOT_PROVED",
                              "R52_MEASURED_WCET_PROVED",
                              "R52_SOC_ADDRESS_CONFORMANCE_PROVED"),
            assumptions=("human-declared SoC TCM base addresses",
                         "physical Cortex-R52 execution remains judge_pending"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("r52",),
            artifact_hash_bindings=(
                "examples/formalkernel/profiles/r52.json",
                "examples/formalkernel/kernel/r52_port.json",
                "examples/formalkernel/boot/layout-r52.ld"),
            maturity_from="scaffold", maturity_to="bounded-evidence",
            maturity_requires_step=1, current_step=1, step_status="complete",
            current_maturity="bounded-evidence",
            completed_claims=("R52_TCM_PLACEMENT_PROVED",),
        ),
    ),
    CapabilitySpec(
        name="m68_r52_smmu_validation",
        description="R52 SMMU stream and DMA-contract correspondence.",
        epistemic_boundary=("Proves reviewed SMMU configuration arithmetic; "
                            "physical malicious-DMA blocking and external I/O "
                            "safety require board fault-injection evidence."),
        milestone=MilestoneMetadata(
            lane="M68_r52_smmu_validation", deployment_split="shared_hardware",
            required_judges=("DeterministicGate",
                             "PhysicalSMMUFaultInjection:pending"),
            claims=(ClaimStage("SMMU_CONFIGURATION_CORRESPONDENCE_PROVED", 1),),
            claims_forbidden=("EXTERNAL_IO_SAFETY_PROVED",
                              "PHYSICAL_SMMU_DMA_BLOCK_PROVED"),
            assumptions=("human-declared ARM SMMUv3 stream IDs",
                         "device and SMMU implement the reviewed configuration"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("r52",),
            artifact_hash_bindings=(
                "examples/formalkernel/profiles/r52.json",
                "examples/formalkernel/kernel/r52_smmu.json"),
            maturity_from="scaffold", maturity_to="bounded-evidence",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="bounded-evidence",
            completed_claims=("SMMU_CONFIGURATION_CORRESPONDENCE_PROVED",),
        ),
    ),
    CapabilitySpec(
        name="m69_intel_n150_port",
        description="Static Intel N150 x86_64 layout and VT-d correspondence.",
        epistemic_boundary=("Proves reviewed linker and VT-d tables correspond "
                            "to the N150 profile; physical boot, VT-d fault "
                            "behavior, and silicon TSO remain unproved."),
        milestone=MilestoneMetadata(
            lane="M69_intel_n150_port", deployment_split="shared_hardware",
            required_judges=("DeterministicGate", "PhysicalN150:pending"),
            claims=(ClaimStage("N150_PLATFORM_CONFIGURATION_PROVED", 1),),
            claims_forbidden=("N150_PHYSICAL_BOOT_PROVED",
                              "N150_PHYSICAL_VTD_PROVED",
                              "PHYSICAL_SILICON_MEMORY_MODEL_PROVED"),
            assumptions=("human-declared PCI requester IDs",
                         "firmware loads the image at the reviewed address"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150",),
            artifact_hash_bindings=(
                "examples/formalkernel/profiles/n150.json",
                "examples/formalkernel/kernel/n150_port.json",
                "examples/formalkernel/boot/layout-n150.ld",
                "examples/formalkernel/kernel/weak_memory/x86_message_passing.litmus"),
            maturity_from="scaffold", maturity_to="bounded-evidence",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="bounded-evidence",
            completed_claims=("N150_PLATFORM_CONFIGURATION_PROVED",),
        ),
    ),
    CapabilitySpec(
        name="m70_hard_realtime_traceability",
        description="Hash-bound system requirements-to-evidence matrix.",
        epistemic_boundary=("Proves applicable requirements are mapped to "
                            "minted evidence; it does not establish regulatory "
                            "certification or close physical hardware gaps."),
        milestone=MilestoneMetadata(
            lane="M70_hard_realtime_traceability",
            deployment_split="deployment_specific",
            required_judges=("DeterministicGate",
                             "CertificationAuthority:human_external"),
            claims=(ClaimStage("CERTIFICATION_TRACEABILITY_COMPLETE", 1),),
            claims_forbidden=("DO_178C_LEVEL_A_CERTIFIED",
                              "ISO_26262_CERTIFIED",
                              "PHYSICAL_HARD_REALTIME_PROVED"),
            assumptions=("requirements set is human-reviewed and complete",
                         "physical M67-M69 closures remain pending"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/certification_traceability.json",),
            maturity_from="evidence-lattice", maturity_to="pre-certification",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="pre-certification",
            completed_claims=("CERTIFICATION_TRACEABILITY_COMPLETE",),
        ),
    ),
    CapabilitySpec(
        name="m71_5_multicore_interference",
        description="Profile-bound shared-hardware interference inventory.",
        epistemic_boundary=("Enumerates and dispositions interference channels; "
                            "WCET inflation validation requires authenticated "
                            "measurements from each physical target."),
        milestone=MilestoneMetadata(
            lane="M71_5_multicore_interference",
            deployment_split="shared_hardware",
            required_judges=("DeterministicGate",
                             "TargetMeasurements:pending"),
            claims=(ClaimStage("MULTICORE_INTERFERENCE_CHANNELS_ENUMERATED", 1),),
            claims_forbidden=("TARGET_WCET_INTERFERENCE_BOUND_VALIDATED",
                              "MULTICORE_TIMING_INTERFERENCE_PROVED"),
            assumptions=("channel inventory is complete for reviewed targets",
                         "measurement authenticity requires human review"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/multicore_interference.json",),
            maturity_from="scaffold", maturity_to="inventory-complete",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="inventory-complete",
            completed_claims=("MULTICORE_INTERFERENCE_CHANNELS_ENUMERATED",),
        ),
    ),
    CapabilitySpec(
        name="m71_parameterized_rcu",
        description="Parameterized RCU grace-period safety with bounded witness.",
        epistemic_boundary=("TLAPS proves the invariant for an arbitrary "
                            "reader set and ESBMC checks a two-reader C witness; "
                            "source/model refinement, IRQ/NMI interaction, and "
                            "callback pressure remain pending."),
        milestone=MilestoneMetadata(
            lane="M71_parameterized_rcu", deployment_split="shared_algorithmic",
            required_judges=("TLAPS", "ESBMC"),
            claims=(ClaimStage("RCU_RECLAMATION_SAFETY_PROVED", 1),),
            claims_forbidden=("RCU_IMPLEMENTATION_REFINEMENT_PROVED",
                              "RCU_IRQ_NMI_SAFETY_PROVED",
                              "RCU_CALLBACK_PRESSURE_PROVED"),
            assumptions=("TLA atomic actions correspond to intended linearization points",
                         "C witness uses SC ESBMC atomic sections"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/scheduler/rcu.json",
                "examples/formalkernel/kernel/scheduler/RCURefinement.tla",
                "examples/formalkernel/kernel/scheduler/rcu_witness.c"),
            maturity_from="scaffold", maturity_to="parameterized-model-evidence",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="parameterized-model-evidence",
            completed_claims=("RCU_RECLAMATION_SAFETY_PROVED",),
        ),
    ),
    CapabilitySpec(
        name="m72_crash_consistent_vfs",
        description="TLC-checked write-ahead-log crash and recovery semantics.",
        epistemic_boundary=("TLC proves bounded atomic recovery under the "
                            "declared persistence contract; physical FUA, "
                            "device firmware, and fault injection remain pending."),
        milestone=MilestoneMetadata(
            lane="M72_crash_consistent_vfs",
            deployment_split="shared_algorithmic", required_judges=("TLC",),
            claims=(ClaimStage("FILESYSTEM_CRASH_ATOMICITY_PROVED", 1),),
            claims_forbidden=("PHYSICAL_FUA_SEMANTICS_PROVED",
                              "DEVICE_FIRMWARE_CRASH_SAFETY_PROVED",
                              "PHYSICAL_CRASH_INJECTION_VALIDATED"),
            assumptions=("declared WAL persistence and torn-write contract",
                         "physical device honors reviewed FUA boundary"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/vfs/journal.json",
                "examples/formalkernel/kernel/vfs/journal.validation.json",
                "domains/candidates/vfs_bounded.v2.yaml"),
            maturity_from="production", maturity_to="crash-model-evidence",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="crash-model-evidence",
            completed_claims=("FILESYSTEM_CRASH_ATOMICITY_PROVED",),
        ),
    ),
    CapabilitySpec(
        name="m73_tcp_resource_containment",
        description="Adversarial bounded TCP resource-partition model.",
        epistemic_boundary=("TLC proves pool and per-principal quota safety "
                            "under the modeled network envelope; full RFC "
                            "conformance and native-stack refinement remain pending."),
        milestone=MilestoneMetadata(
            lane="M73_tcp_resource_containment",
            deployment_split="shared_algorithmic", required_judges=("TLC",),
            claims=(ClaimStage("TCP_RESOURCE_CONTAINMENT_PROVED", 1),),
            claims_forbidden=("RFC9293_CONFORMANCE_PROVED",
                              "RFC5961_CONFORMANCE_PROVED",
                              "TCP_IMPLEMENTATION_REFINEMENT_PROVED"),
            assumptions=("two-principal quota partition is the deployment policy",
                         "adversarial envelope is complete for this bounded model"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/net/tcp_resource.json",
                "examples/formalkernel/kernel/net/tcp_resource.validation.json"),
            maturity_from="bounded-handshake", maturity_to="bounded-protocol-evidence",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="bounded-protocol-evidence",
            completed_claims=("TCP_RESOURCE_CONTAINMENT_PROVED",),
        ),
    ),
    CapabilitySpec(
        name="m74_microarch_mitigation_policy",
        description="Declared x86 mitigation completeness and cycle-budget policy.",
        epistemic_boundary=("Z3 proves policy completeness for a human-declared "
                            "CPUID/microcode profile; runtime identity, measured "
                            "latency, and speculative noninterference remain pending."),
        milestone=MilestoneMetadata(
            lane="M74_microarch_mitigation_policy",
            deployment_split="shared_hardware",
            required_judges=("Z3", "DeterministicCostGate",
                             "RuntimePlatformProbe:pending"),
            claims=(ClaimStage("MICROARCH_MITIGATION_POLICY_PROVED", 1),
                    ClaimStage("MITIGATION_WCET_BUDGET_PROVED", 1)),
            claims_forbidden=("SPECULATIVE_NONINTERFERENCE_PROVED",
                              "RUNTIME_CPUID_PROFILE_PROVED",
                              "MEASURED_MITIGATION_WCET_PROVED"),
            assumptions=("CPUID and microcode profile is human declared",
                         "per-mitigation cycle costs are declared, not measured"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150",),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/n150_mitigations.json",),
            maturity_from="hardcoded-mitigation-assumptions",
            maturity_to="declared-policy-evidence", maturity_requires_step=2,
            current_step=1, step_status="partial",
            current_maturity="declared-policy-evidence",
            completed_claims=("MICROARCH_MITIGATION_POLICY_PROVED",
                              "MITIGATION_WCET_BUDGET_PROVED"),
        ),
    ),
    CapabilitySpec(
        name="m75_tool_qualification_evidence",
        description="Independent golden-vector qualification-support evidence.",
        epistemic_boundary=("A standalone standard-library oracle checks the "
                            "reviewed vector corpus; DO-330 qualification, external "
                            "authority acceptance, and general correctness are not proved."),
        milestone=MilestoneMetadata(
            lane="M75_tool_qualification_evidence",
            deployment_split="shared_tooling",
            required_judges=("IndependentStdlibOracle",
                             "QualificationAuthority:human_external"),
            claims=(ClaimStage("TOOL_QUALIFICATION_EVIDENCE_READY", 1),),
            claims_forbidden=("DO330_QUALIFIED", "TOOL_CORRECTNESS_PROVED",
                              "GENERAL_TRANSFORMATION_CORRECTNESS_PROVED"),
            assumptions=("golden corpus is independently reviewed and representative",
                         "external authority determines qualification context"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/tool_qualification.json",
                "pipeline/qualification_oracle.py"),
            maturity_from="self-tested-tooling", maturity_to="qualification-evidence",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="qualification-evidence",
            completed_claims=("TOOL_QUALIFICATION_EVIDENCE_READY",),
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
