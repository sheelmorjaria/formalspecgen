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


DEPLOYMENT_PROFILE_POLICIES = {
    "safety": {
        "assurance_profile": "FK-Safety",
        "claims_forbidden": (
            "VM_RESOURCE_ISOLATION_PROVED", "NUMA_ACCOUNTING_PROVED",
            "SMP_SCHEDULER_INVARIANTS_PROVED", "PROCESS_CONCURRENCY_MODEL_PROVED",
            "GUEST_RESOURCE_NONINTERFERENCE_PROVED", "POSIX_CONFORMANCE_TESTED",
        ),
        "claims_required": ("HARDWARE_MEMORY_BOUND_PROVED", "WCET_BOUND_PROVEN",
                            "SPATIAL_ISOLATION_PROVED", "DMA_ISOLATION_PROVED",
                            "SYSTEM_COMPOSITION_PROVED"),
        "required_manifest_flags": {"hard_realtime": True,
                                    "dynamic_resources": False, "smp": False},
    },
    "desktop": {
        "assurance_profile": "FK-Desktop",
        "claims_forbidden": ("WCET_BOUND_PROVED",
                             "MULTICORE_INTERFERENCE_CHANNELS_ENUMERATED"),
        "claims_required": ("VM_RESOURCE_ISOLATION_PROVED",
                            "SMP_SCHEDULER_INVARIANTS_PROVED",
                            "PROCESS_CONCURRENCY_MODEL_PROVED",
                            "GUEST_RESOURCE_NONINTERFERENCE_PROVED",
                            "POSIX_CONFORMANCE_TESTED"),
        "required_manifest_flags": {"hard_realtime": False},
    },
}


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
                   cli_command="doctor", mcp_tool="doctor_environment",
                   epistemic_boundary="Always claim=NO_PROOF."),
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
    CapabilitySpec(
        name="m76_semantic_refinement_spine",
        description="Staged promoted-model to foundational Rust, LLVM IR, and object spine.",
        epistemic_boundary=("Step 3b-r1 validates a locally patched generic RefinedRust array-field "
                            "translation across five lengths; step 3b-r2 is blocked on named-const, iterator-pattern, "
                            "and slice-index support for the exact allocator; step 3c found no eligible existing "
                            "production primitive after the scalar adapter hit the unmodeled Result Try::branch shim; general IR "
                            "correspondence, and verified compilation remain pending."),
        milestone=MilestoneMetadata(
            lane="M76_semantic_refinement_spine", deployment_split="shared_algorithmic",
            required_judges=("Prusti", "Rustc", "RefinedRust",
                             "SemanticIRJudge:pending", "VerifiedCompiler:pending"),
            claims=(ClaimStage("REFINEMENT_CHAIN_ARTIFACTS_BOUND", 1),
                    ClaimStage("BOUNDED_COMPILED_REFINEMENT_VALIDATED", 2),
                    ClaimStage("REFINEDRUST_ARRAY_TRANSLATION_VALIDATED", 3),
                    ClaimStage("RUST_IMPLEMENTATION_REFINEMENT_PROVED", 3),
                    ClaimStage("COMPILER_REFINEMENT_CHAIN_PROVED", 4),
                    ClaimStage("END_TO_END_REFINEMENT_CHAIN_ESTABLISHED", 5)),
            claims_forbidden=("END_TO_END_REFINEMENT_CHAIN_WITHOUT_IR_SEMANTICS",
                              "VERIFIED_COMPILER_PROVED", "BINARY_SEMANTICS_PROVED"),
            assumptions=("Prusti ghost erasure has no runtime semantics",
                         "host rustc is not a verified compiler",
                         "RefinedRust 0.1.0 array-field correction is local and not upstream-accepted",
                         "Exact allocator iterator and slice-index semantics:judge_pending",
                         "RefinedRust Result Try::branch standard-library shim:judge_pending"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=("domains/v2/vfs_bounded.json", "Vfs.rs",
                                    "examples/formalkernel/kernel/refinement_spine.json",
                                    "examples/formalkernel/kernel/refinement/m76_3b_allocator_feasibility.json",
                                    "examples/formalkernel/kernel/refinement/refinedrust_array_regression/evidence.json",
                                    "examples/formalkernel/kernel/refinement/patches/refinedrust-0.1.0-array-place-rfn.patch",
                                    "examples/formalkernel/kernel/refinement/refinedrust_allocator/feasibility.json",
                                    "examples/formalkernel/kernel/refinement/refinedrust_feasibility_report.json",
                                    "examples/formalkernel/kernel/refinement/refinedrust_boundary_ledger.json",
                                    "examples/formalkernel/kernel/refinement/refinedrust_trait_impl_boundary/evidence.json"),
            maturity_from="horizontal-evidence", maturity_to="vertical-artifact-spine",
            maturity_requires_step=5, current_step=3, step_status="partial",
            current_maturity="vertical-artifact-spine",
            completed_claims=("REFINEMENT_CHAIN_ARTIFACTS_BOUND",
                              "BOUNDED_COMPILED_REFINEMENT_VALIDATED",
                              "REFINEDRUST_ARRAY_TRANSLATION_VALIDATED"),
        ),
    ),
    CapabilitySpec(
        name="m77_dynamic_vm_numa", description="Dynamic VM quota and NUMA accounting.",
        epistemic_boundary=("Z3 proves symbolic accounting for three declared processes "
                            "and two NUMA nodes; hardware mappings and arbitrary topology remain pending."),
        milestone=MilestoneMetadata(
            lane="M77_dynamic_vm_numa", deployment_split="shared_algorithmic",
            required_judges=("Z3", "HardwareTLB:pending"),
            claims=(ClaimStage("VM_RESOURCE_ISOLATION_PROVED", 1),
                    ClaimStage("NUMA_ACCOUNTING_PROVED", 1)),
            claims_forbidden=("HARDWARE_TLB_COHERENCE_PROVED",
                              "ARBITRARY_PROCESS_COUNT_PROVED",
                              "DYNAMIC_VM_IMPLEMENTATION_REFINEMENT_PROVED"),
            assumptions=("three-process admitted topology", "two static NUMA nodes"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=("examples/formalkernel/kernel/dynamic_vm.json",),
            maturity_from="fixed-pools", maturity_to="bounded-dynamic-quotas",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="bounded-dynamic-quotas",
            completed_claims=("VM_RESOURCE_ISOLATION_PROVED", "NUMA_ACCOUNTING_PROVED")),
    ),
    CapabilitySpec(
        name="m78_scalable_smp_scheduler", description="Parameterized SMP scheduler invariants.",
        epistemic_boundary=("TLAPS proves ownership, affinity, and migration invariants "
                            "for arbitrary finite sets; native refinement and liveness remain pending."),
        milestone=MilestoneMetadata(
            lane="M78_scalable_smp_scheduler", deployment_split="shared_algorithmic",
            required_judges=("TLAPS", "NativeRefinement:pending"),
            claims=(ClaimStage("SMP_SCHEDULER_INVARIANTS_PROVED", 1),),
            claims_forbidden=("SMP_SCHEDULER_LIVENESS_PROVED", "IPI_DELIVERY_PROVED",
                              "CPU_HOTPLUG_PROVED", "SMP_IMPLEMENTATION_REFINEMENT_PROVED"),
            assumptions=("finite CPU and task sets", "affinity is human policy"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=("examples/formalkernel/kernel/scheduler/SmpSchedulerRefinement.tla",),
            maturity_from="bounded-round-robin", maturity_to="parameterized-safety",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="parameterized-safety",
            completed_claims=("SMP_SCHEDULER_INVARIANTS_PROVED",)),
    ),
    CapabilitySpec(
        name="m79_iommu_pcie_nvme", description="IOMMU domains and multiqueue device containment.",
        epistemic_boundary=("Z3 and range gates prove declared requester/domain and queue-budget "
                            "isolation; physical fabrics, firmware, interrupts, and drivers remain pending."),
        milestone=MilestoneMetadata(
            lane="M79_iommu_pcie_nvme", deployment_split="shared_hardware",
            required_judges=("Z3", "PhysicalFaultInjection:pending"),
            claims=(ClaimStage("DEVICE_DMA_DOMAIN_ISOLATION_PROVED", 1),),
            claims_forbidden=("PHYSICAL_IOMMU_ENFORCEMENT_PROVED",
                              "NVME_DEVICE_BEHAVIOR_PROVED", "MSIX_DELIVERY_PROVED"),
            assumptions=("reviewed requester IDs and IOMMU roots", "one page per queue entry"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=("examples/formalkernel/kernel/device_fabric.json",),
            maturity_from="single-device-dma", maturity_to="bounded-multiqueue-fabric",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="bounded-multiqueue-fabric",
            completed_claims=("DEVICE_DMA_DOMAIN_ISOLATION_PROVED",)),
    ),
    CapabilitySpec(
        name="m80_general_process_model", description="Bounded fork, exec, and futex lifecycle.",
        epistemic_boundary=("TLC proves the bounded lifecycle and Z3 proves exec cleanup; "
                            "POSIX, native syscalls, futex hardware, and signals remain pending."),
        milestone=MilestoneMetadata(
            lane="M80_general_process_model", deployment_split="shared_algorithmic",
            required_judges=("TLC", "Z3", "NativeRefinement:pending"),
            claims=(ClaimStage("PROCESS_CONCURRENCY_MODEL_PROVED", 1),),
            claims_forbidden=("POSIX_CONFORMANCE_PROVED", "NATIVE_FUTEX_PROVED",
                              "PROCESS_IMPLEMENTATION_REFINEMENT_PROVED"),
            assumptions=("two processes and two threads", "M77 quota bound is two pages"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=("examples/formalkernel/kernel/process_model.json",
                                    "examples/formalkernel/kernel/process_model.validation.json"),
            maturity_from="loader-only", maturity_to="bounded-process-model",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="bounded-process-model",
            completed_claims=("PROCESS_CONCURRENCY_MODEL_PROVED",)),
    ),
    CapabilitySpec(
        name="m81_enterprise_security_root", description="Measured-boot and rollback policy model.",
        epistemic_boundary=("TLC and Z3 prove the declared admission policy; TPM silicon, firmware, "
                            "keys, cryptographic strength, and built-image measurement remain pending."),
        milestone=MilestoneMetadata(
            lane="M81_enterprise_security_root", deployment_split="shared_boot_policy",
            required_judges=("TLC", "Z3", "PhysicalTPM:pending"),
            claims=(ClaimStage("BOOT_TO_RUNTIME_INTEGRITY_CHAIN_PROVED", 1),),
            claims_forbidden=("PHYSICAL_TPM_SEMANTICS_PROVED", "KEY_CUSTODY_PROVED",
                              "SHA256_COLLISION_RESISTANCE_PROVED"),
            assumptions=("reviewed root key identity", "SHA-256 strength independently assumed"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=("examples/formalkernel/kernel/boot_integrity.json",
                                    "examples/formalkernel/kernel/boot_integrity.validation.json"),
            maturity_from="unsigned-boot", maturity_to="bounded-measured-boot-policy",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="bounded-measured-boot-policy",
            completed_claims=("BOOT_TO_RUNTIME_INTEGRITY_CHAIN_PROVED",)),
    ),
    CapabilitySpec(
        name="m82_network_scale", description="IPv6/UDP/TCP routing and queue partitioning.",
        epistemic_boundary=("TLC proves bounded routing/firewall terminality and Z3 proves "
                            "queue partitioning; RFC, native stack, and hardware remain pending."),
        milestone=MilestoneMetadata(
            lane="M82_network_scale", deployment_split="shared_algorithmic",
            required_judges=("TLC", "Z3", "NetworkHardware:pending"),
            claims=(ClaimStage("NETWORK_RESOURCE_PARTITION_PROVED", 1),),
            claims_forbidden=("FULL_IPV6_CONFORMANCE_PROVED", "NETWORK_STACK_REFINEMENT_PROVED",
                              "PHYSICAL_PACKET_DELIVERY_PROVED"),
            assumptions=("two-principal queue policy", "four static NIC queues"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=("examples/formalkernel/kernel/network_scale.json",
                                    "examples/formalkernel/kernel/network_scale.validation.json"),
            maturity_from="single-endpoint", maturity_to="bounded-network-fabric",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="bounded-network-fabric",
            completed_claims=("NETWORK_RESOURCE_PARTITION_PROVED",)),
    ),
    CapabilitySpec(
        name="m83_fault_hardware_resilience",
        description="ECC/MCE, watchdog, poisoned-page, and device-reset recovery model.",
        epistemic_boundary=("TLC proves one-fault recovery terminality and supervisor survival; "
                            "Z3 proves poisoned-page accounting. Physical delivery, firmware, "
                            "native handlers, and repeated-fault refinement remain pending."),
        milestone=MilestoneMetadata(
            lane="M83_fault_hardware_resilience", deployment_split="shared_recovery_policy",
            required_judges=("TLC", "Z3", "PhysicalFaultInjection:pending"),
            claims=(ClaimStage("FAULT_CONTAINMENT_RECOVERY_PROVED", 1),),
            claims_forbidden=("PHYSICAL_ECC_DELIVERY_PROVED", "MCE_HARDWARE_SEMANTICS_PROVED",
                              "FAULT_HANDLER_IMPLEMENTATION_REFINEMENT_PROVED"),
            assumptions=("single injected fault", "supervisor page remains healthy"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=("examples/formalkernel/kernel/fault_recovery.json",
                                    "examples/formalkernel/kernel/fault_recovery.validation.json"),
            maturity_from="fault-detection", maturity_to="bounded-recovery-model",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="bounded-recovery-model",
            completed_claims=("FAULT_CONTAINMENT_RECOVERY_PROVED",)),
    ),
    CapabilitySpec(
        name="m84_virtualization_isolation_domains",
        description="Bounded guest lifecycle and cross-resource isolation domains.",
        epistemic_boundary=("TLC proves a two-guest lifecycle and exact reservations; Z3 proves "
                            "static CPU, memory, network, and IOMMU partitions. Hardware VM "
                            "semantics, side channels, and native refinement remain pending."),
        milestone=MilestoneMetadata(
            lane="M84_virtualization_isolation_domains",
            deployment_split="shared_virtualization_policy",
            required_judges=("TLC", "Z3", "HardwareVirtualization:pending"),
            claims=(ClaimStage("GUEST_RESOURCE_NONINTERFERENCE_PROVED", 1),),
            claims_forbidden=("NESTED_PAGE_TABLE_ENFORCEMENT_PROVED",
                              "INTERRUPT_REMAP_HARDWARE_PROVED",
                              "HYPERVISOR_IMPLEMENTATION_REFINEMENT_PROVED",
                              "GUEST_SIDE_CHANNEL_NONINTERFERENCE_PROVED"),
            assumptions=("two admitted guests", "static resource reservations"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=("examples/formalkernel/kernel/guest_isolation.json",
                                    "examples/formalkernel/kernel/guest_isolation.validation.json"),
            maturity_from="process-isolation", maturity_to="bounded-guest-domains",
            maturity_requires_step=2, current_step=1, step_status="partial",
            current_maturity="bounded-guest-domains",
            completed_claims=("GUEST_RESOURCE_NONINTERFERENCE_PROVED",)),
    ),
    CapabilitySpec(
        name="m85_compatibility_operations",
        description="Stable ABI and empirical POSIX-subset/operations evidence.",
        epistemic_boundary=("A deterministic baseline gate checks ABI identity and a host-compiled "
                            "shim executes five POSIX-like calls. This is checked/tested evidence, "
                            "not full POSIX, target runtime, or native syscall proof."),
        milestone=MilestoneMetadata(
            lane="M85_compatibility_operations", deployment_split="shared_compatibility_surface",
            required_judges=("CCompilerRuntime", "TargetRuntime:pending"),
            claims=(ClaimStage("ABI_STABILITY_CHECKED", 1),
                    ClaimStage("POSIX_CONFORMANCE_TESTED", 1)),
            claims_forbidden=("ABI_STABILITY_PROVED", "FULL_POSIX_CONFORMANCE_PROVED",
                              "KERNEL_SYSCALL_REFINEMENT_PROVED",
                              "ATOMIC_FIELD_UPGRADE_PROVED"),
            assumptions=("reviewed ABI v1 baseline", "host runtime is an empirical surrogate"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=("examples/formalkernel/kernel/posix_compat_abi.json",
                                    "examples/formalkernel/kernel/posix_compat_abi.baseline.json",
                                    "examples/formalkernel/kernel/posix_compat.c"),
            maturity_from="kernel-specific-api", maturity_to="tested-compatibility-subset",
            maturity_requires_step=3, current_step=2, step_status="partial",
            current_maturity="tested-compatibility-subset",
            completed_claims=("ABI_STABILITY_CHECKED", "POSIX_CONFORMANCE_TESTED")),
    ),
    CapabilitySpec(
        name="m86_verus_production_modules",
        description="Verus qualification and broad functional verification of production Rust.",
        epistemic_boundary=("The pinned Verus judge is non-vacuously qualified. A byte-identical "
                            "ghost/spec overlay proves the exact production constructor and rejects "
                            "a semantic mutation. Allocate, release, and accounting remain excluded, "
                            "so allocator functional correctness remains locked."),
        milestone=MilestoneMetadata(
            lane="M86_verus_production_modules", deployment_split="shared_tooling",
            required_judges=("Verus",),
            claims=(ClaimStage("VERUS_JUDGE_QUALIFIED", 1),
                    ClaimStage("VERUS_PRODUCTION_OVERLAY_QUALIFIED", 2),
                    ClaimStage("ITERATOR_TRAVERSAL_SEMANTICS_PROVED", 3),
                    ClaimStage("GET_MUT_FRAME_SEMANTICS_PROVED", 4),
                    ClaimStage("OCCUPANCY_COUNT_CORRESPONDENCE_PROVED", 5),
                    ClaimStage("BOUNDED_ALLOCATOR_FUNCTIONAL_CORRECTNESS_PROVED", 6)),
            claims_forbidden=("RUST_IMPLEMENTATION_REFINEMENT_PROVED",
                              "COMPILER_REFINEMENT_CHAIN_PROVED",
                              "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED"),
            assumptions=("Verus and bundled solver binaries match the recorded hashes",
                         "ordinary imported Rust with zero obligations is not proof"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/verus_smoke/evidence.json",
                "examples/formalkernel/kernel/verus_allocator/feasibility.json",
                "examples/formalkernel/kernel/verus_allocator/overlay_evidence.json",
                "examples/formalkernel/kernel/verus_allocator/bridges/evidence.json"),
            maturity_from="judge-installed", maturity_to="production-functional-proof",
            maturity_requires_step=6, current_step=2, step_status="partial",
            current_maturity="exact-overlay-qualified",
            completed_claims=("VERUS_JUDGE_QUALIFIED",
                              "VERUS_PRODUCTION_OVERLAY_QUALIFIED")),
    ),
    CapabilitySpec(
        name="m86_2_verus_production_coverage",
        description="Rank and verify additional exact production safe-Rust modules with Verus.",
        epistemic_boundary=("Verus proves exact production virtio queue accounting and its "
                            "relation to the hash-accepted reviewed queue model. Device behavior, "
                            "interrupt delivery, DMA completion, and external I/O remain unproved."),
        milestone=MilestoneMetadata(
            lane="M86_2_verus_production_coverage", deployment_split="shared_tooling",
            required_judges=("Verus",),
            claims=(ClaimStage("VERUS_VIRTIO_BLK_OVERLAY_QUALIFIED", 2),
                    ClaimStage("VIRTIO_QUEUE_ACCOUNTING_IMPLEMENTATION_CORRECTNESS_PROVED", 3),
                    ClaimStage("VIRTIO_QUEUE_MODEL_BRIDGE_PROVED", 4)),
            claims_forbidden=("VM_ACCOUNTING_IMPLEMENTATION_CORRECTNESS_PROVED",
                              "DRIVER_DEVICE_BEHAVIOR_PROVED",
                              "EXTERNAL_IO_SAFETY_PROVED",
                              "RUST_IMPLEMENTATION_REFINEMENT_PROVED",
                              "COMPILER_REFINEMENT_CHAIN_PROVED",
                              "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED"),
            assumptions=("candidate ranking is guidance and not correctness evidence",
                         "M77 production Rust implementation is absent",
                         "candidate queue-model review is a human trust action"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/verus_m86_2_feasibility.json",
                "examples/formalkernel/kernel/verus_virtio/evidence.json",
                "examples/formalkernel/kernel/verus_virtio/functional_evidence.json",
                "examples/formalkernel/kernel/verus_virtio/mutation_suite.json",
                "examples/formalkernel/kernel/verus_virtio/queue_model.candidate.json",
                "examples/formalkernel/kernel/verus_virtio/queue_model.validation.json",
                "examples/formalkernel/kernel/verus_virtio/queue_model.reviewed.json",
                "examples/formalkernel/kernel/verus_virtio/model_bridge.json"),
            maturity_from="candidate-scan", maturity_to="production-functional-proof",
            maturity_requires_step=4, current_step=4, step_status="complete",
            current_maturity="reviewed-model-bridge",
            completed_claims=("VERUS_VIRTIO_BLK_OVERLAY_QUALIFIED",
                              "VIRTIO_QUEUE_ACCOUNTING_IMPLEMENTATION_CORRECTNESS_PROVED",
                              "VIRTIO_QUEUE_MODEL_BRIDGE_PROVED")),
    ),
    CapabilitySpec(
        name="m86_4_second_production_module",
        description="Apply the qualified Verus bridge lifecycle to a distinct module.",
        epistemic_boundary=("No exact production capability or rollback Rust transition exists. "
                            "Constant-only, semantically weak, and unsafe/volatile alternatives "
                            "are refused rather than replaced with proof-only code."),
        milestone=MilestoneMetadata(
            lane="M86_4_second_production_module", deployment_split="shared_tooling",
            required_judges=("Verus",),
            claims=(ClaimStage("VERUS_SECOND_MODULE_OVERLAY_QUALIFIED", 2),
                    ClaimStage("SECOND_MODULE_IMPLEMENTATION_CORRECTNESS_PROVED", 3),
                    ClaimStage("SECOND_MODULE_MODEL_BRIDGE_PROVED", 4)),
            claims_forbidden=("RUST_IMPLEMENTATION_REFINEMENT_PROVED",
                              "COMPILER_REFINEMENT_CHAIN_PROVED",
                              "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED"),
            assumptions=("candidate scan is non-evidentiary",
                         "production architecture determines when a new primitive exists"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/verus_m86_4_feasibility.json",
                "examples/formalkernel/kernel/verus_virtio/bridge_contract.json",
                "pipeline/implementation_bridge.py"),
            maturity_from="candidate-scan", maturity_to="reviewed-model-bridge",
            maturity_requires_step=4, current_step=1, step_status="complete",
            current_maturity="parked-no-eligible-production-module",
            completed_claims=()),
    ),
    CapabilitySpec(
        name="m87_1_atomic_primitive_feasibility",
        description="Find an exact production Rust atomic transition for weak-memory refinement.",
        epistemic_boundary=("The production tree currently contains no Rust Atomic operation "
                            "with explicit Ordering. Existing M61 herd7 tests remain reviewed "
                            "model-level litmus evidence without source or compiler binding."),
        milestone=MilestoneMetadata(
            lane="M87_1_atomic_primitive_feasibility", deployment_split="shared_tooling",
            required_judges=("herd7",),
            claims=(ClaimStage("ATOMIC_OPERATION_FUNCTIONAL_CORRECTNESS_PROVED", 2),
                    ClaimStage("RUST_ATOMIC_LITMUS_CORRESPONDENCE_PROVED", 3),
                    ClaimStage("RUST_ATOMIC_LOWERING_CORRESPONDENCE_VALIDATED", 4),
                    ClaimStage("WEAK_MEMORY_IMPLEMENTATION_REFINEMENT_PROVED", 5)),
            claims_forbidden=("PHYSICAL_SILICON_MEMORY_MODEL_PROVED",
                              "VERIFIED_COMPILER_PROVED"),
            assumptions=("M61 litmus abstraction remains independently reviewed",
                         "candidate scan is non-evidentiary",
                         "qualified compiler lowering is required only after an atomic candidate exists"),
            deployment_profiles=("microkernel", "monolith", "unikernel"),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/m87_atomic_feasibility.json",
                "examples/formalkernel/kernel/weak_memory.json",
                "pipeline/atomic_feasibility.py"),
            maturity_from="model-level-litmus", maturity_to="implementation-refinement",
            maturity_requires_step=5, current_step=1, step_status="complete",
            current_maturity="parked-no-production-atomic-transition",
            completed_claims=()),
    ),
    CapabilitySpec(
        name="m88_1_information_flow_scope",
        description="Define a scoped two-run information-flow hyperproperty.",
        epistemic_boundary=("Z3 proves one-step two-run noninterference over the reviewed M49/M50/M65 "
                            "scope. Timing, termination, traces, declassification, implementation, "
                            "hardware, and microarchitectural channels remain excluded."),
        milestone=MilestoneMetadata(
            lane="M88_1_information_flow_scope", deployment_split="microkernel_boundary",
            required_judges=("Z3",),
            claims=(ClaimStage("SERVER_POLICY_TWO_RUN_NONINTERFERENCE_PROVED", 2),
                    ClaimStage("SERVER_POLICY_TRACE_NONINTERFERENCE_PROVED", 3),
                    ClaimStage("DECLASSIFICATION_POLICY_PROVED", 4)),
            claims_forbidden=("TIMING_NONINTERFERENCE_PROVED",
                              "MICROARCHITECTURAL_NONINTERFERENCE_PROVED",
                              "CAPABILITY_TOKEN_UNFORGEABILITY_PROVED",
                              "INFORMATION_FLOW_NONINTERFERENCE_PROVED",
                              "INFORMATION_FLOW_IMPLEMENTATION_REFINEMENT_PROVED"),
            assumptions=("identical public inputs in both runs",
                         "high/low partition is human-reviewed before proof",
                         "termination-insensitive and timing-insensitive scope",
                         "a qualified self-composition judge is required from step 2"),
            deployment_profiles=("microkernel",),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/m88_information_flow_scope.candidate.json",
                "examples/formalkernel/kernel/m88_information_flow_scope.reviewed.json",
                "examples/formalkernel/kernel/m88_information_flow.validation.json",
                "examples/formalkernel/kernel/m88_information_flow.trace.validation.json",
                "examples/formalkernel/kernel/m88_declassification.candidate.json",
                "examples/formalkernel/kernel/m88_declassification.reviewed.json",
                "examples/formalkernel/kernel/m88_declassification.validation.json",
                "examples/formalkernel/kernel/server_capabilities.json",
                "examples/formalkernel/kernel/syscalls.json",
                "examples/formalkernel/kernel/ipc.json",
                "pipeline/hyperproperty_evidence.py",
                "pipeline/information_flow.py"),
            maturity_from="bounded-capability-policy", maturity_to="relational-model-proof",
            maturity_requires_step=4, current_step=4, step_status="complete",
            current_maturity="scoped-model-confidentiality-complete",
            completed_claims=("SERVER_POLICY_TWO_RUN_NONINTERFERENCE_PROVED",
                              "SERVER_POLICY_TRACE_NONINTERFERENCE_PROVED",
                              "DECLASSIFICATION_POLICY_PROVED")),
    ),
    CapabilitySpec(
        name="m89_1_capability_authority_algebra",
        description="Parameterized capability creation, delegation, and revocation algebra.",
        epistemic_boundary=("TLAPS proves authority attenuation, closed creation provenance, "
                            "transitive revocation, persistence, unrelated-branch framing, and "
                            "stale-generation rejection for arbitrary finite capability universes. "
                            "Generations are unbounded naturals; fixed-width wraparound, token "
                            "bit-pattern unforgeability, hardware enforcement, and production "
                            "implementation refinement remain outside this claim."),
        milestone=MilestoneMetadata(
            lane="M89_1_capability_authority_algebra", deployment_split="shared_security_model",
            required_judges=("TLAPS", "Z3"),
            claims=(ClaimStage("CAPABILITY_AUTHORITY_ALGEBRA_PROVED", 2),
                    ClaimStage("CAPABILITY_TOKEN_CREATION_CLOSED_PROVED", 3),
                    ClaimStage("CAPABILITY_REVOCATION_SAFETY_PROVED", 4),
                    ClaimStage("SERVER_AUTHORITY_SECURITY_MODEL_PROVED", 5)),
            claims_forbidden=("CAPABILITY_TOKEN_UNFORGEABILITY_PROVED",
                              "CAPABILITY_HARDWARE_ENFORCEMENT_PROVED",
                              "CAPABILITY_IMPLEMENTATION_REFINEMENT_PROVED",
                              "INFORMATION_FLOW_IMPLEMENTATION_REFINEMENT_PROVED"),
            assumptions=("root mint authority is human policy",
                         "principals, objects, and rights are arbitrary finite nonempty sets",
                         "implementation representation is outside the model"),
            deployment_profiles=("microkernel",),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/m89_capability_authority.candidate.json",
                "examples/formalkernel/kernel/m89_capability_authority.reviewed.json",
                "examples/formalkernel/kernel/m89_capability_authority.validation.json",
                "examples/formalkernel/kernel/capability/CapabilityAuthorityRefinement.tla",
                "examples/formalkernel/kernel/m89_capability_revocation.validation.json",
                "examples/formalkernel/kernel/capability/CapabilityRevocationRefinement.tla",
                "examples/formalkernel/kernel/m89_server_authority_composition.validation.json",
                "examples/formalkernel/kernel/server_capabilities.json",
                "examples/formalkernel/kernel/syscalls.json",
                "examples/formalkernel/kernel/ipc.json",
                "examples/formalkernel/kernel/m88_information_flow_scope.reviewed.json",
                "examples/formalkernel/kernel/m88_declassification.reviewed.json",
                "pipeline/capability_authority_model.py",
                "pipeline/capability_authority_verification.py",
                "pipeline/capability_revocation_verification.py",
                "pipeline/server_authority_composition.py"),
            maturity_from="bounded-capability-policy", maturity_to="parameterized-authority-algebra",
            maturity_requires_step=5, current_step=5, step_status="complete",
            current_maturity="model-authority-security-complete",
            completed_claims=("CAPABILITY_AUTHORITY_ALGEBRA_PROVED",
                              "CAPABILITY_TOKEN_CREATION_CLOSED_PROVED",
                              "CAPABILITY_REVOCATION_SAFETY_PROVED",
                              "SERVER_AUTHORITY_SECURITY_MODEL_PROVED")),
    ),
    CapabilitySpec(
        name="m90_1_canonical_evidence_manifest",
        description="Canonical proof-carrying-build evidence dependency manifest.",
        epistemic_boundary=("The canonical manifest binds sources, reviewed models, profiles, "
                            "claims, judges, assumptions, pending gaps, forbidden claims, local "
                            "tool patches, and human promotions. No binary exists at M90.1, so "
                            "artifact identity validation and all compiler/semantic claims remain "
                            "locked."),
        milestone=MilestoneMetadata(
            lane="M90_1_canonical_evidence_manifest",
            deployment_split="profile_specific_evidence_root",
            required_judges=(),
            claims=(ClaimStage("PROOF_CARRYING_BINARY_VALIDATED", 2),),
            claims_forbidden=("COMPILER_REFINEMENT_CHAIN_PROVED",
                              "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED",
                              "CAPABILITY_TOKEN_UNFORGEABILITY_PROVED",
                              "CAPABILITY_HARDWARE_ENFORCEMENT_PROVED"),
            assumptions=("the final deployable binary is not built at M90.1",
                         "artifact identity is not machine-code semantic refinement",
                         "human sealing remains outside agent-accessible interfaces"),
            deployment_profiles=("microkernel",),
            hardware_profiles=("n150", "r52"),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/m90_kernel_evidence_bundle.json",
                "examples/formalkernel/kernel/m90_evidence_root.candidate.json",
                "pipeline/proof_carrying_build.py"),
            maturity_from="evidence-bundle", maturity_to="proof-carrying-binary",
            maturity_requires_step=2, current_step=2, step_status="complete",
            current_maturity="canonical-evidence-manifest",
            completed_claims=()),
    ),
    CapabilitySpec(
        name="m90_2_target_elf_evidence_binding",
        description="Exact AArch64 ELF and applicable evidence-closure binding.",
        epistemic_boundary=("Binds one exact QEMU AArch64 ELF to its declared build inputs "
                            "and two dependency-closed applicable claims. This is artifact "
                            "identity and evidence applicability, not Rust-to-ELF semantic "
                            "refinement, target functional correctness, or release approval."),
        milestone=MilestoneMetadata(
            lane="M90_2_target_elf_evidence_binding",
            deployment_split="qemu_aarch64_microkernel_binary",
            required_judges=("Rustc",),
            claims=(ClaimStage("PROOF_CARRYING_BINARY_VALIDATED", 2),),
            claims_forbidden=("COMPILER_REFINEMENT_CHAIN_PROVED",
                              "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED",
                              "TARGET_BINARY_FUNCTIONAL_CORRECTNESS_PROVED",
                              "CAPABILITY_TOKEN_UNFORGEABILITY_PROVED",
                              "CAPABILITY_HARDWARE_ENFORCEMENT_PROVED"),
            assumptions=("rustc and rust-lld are identity-bound but not verified",
                         "the QEMU AArch64 ELF is not evidence of physical execution",
                         "release sealing remains a human-only action"),
            deployment_profiles=("microkernel",),
            hardware_profiles=("formalkernel-demo",),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/m90_build_config.json",
                "examples/formalkernel/kernel/m90_binary_evidence.json",
                "examples/formalkernel/boot/m90-qemu-aarch64.elf",
                "pipeline/proof_carrying_binary.py"),
            maturity_from="canonical-evidence-manifest",
            maturity_to="proof-carrying-binary", maturity_requires_step=2,
            current_step=2, step_status="complete",
            current_maturity="proof-carrying-binary",
            completed_claims=("PROOF_CARRYING_BINARY_VALIDATED",)),
    ),
    CapabilitySpec(
        name="m90_3_evidence_invalidation",
        description="Typed, transitive, and minimal evidence invalidation semantics.",
        epistemic_boundary=("Validates the deterministic dependency engine and its causal "
                            "downgrade behavior over the exact M90.2 QEMU evidence DAG. It "
                            "does not prove compiler semantics, binary behavior, or that "
                            "unmodeled dependencies cannot exist."),
        milestone=MilestoneMetadata(
            lane="M90_3_evidence_invalidation",
            deployment_split="qemu_aarch64_evidence_operations",
            required_judges=("Rustc",),
            claims=(ClaimStage("EVIDENCE_DEPENDENCY_CLOSURE_VALIDATED", 3),
                    ClaimStage("EVIDENCE_INVALIDATION_SEMANTICS_VALIDATED", 3)),
            claims_forbidden=("COMPILER_REFINEMENT_CHAIN_PROVED",
                              "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED",
                              "TARGET_BINARY_FUNCTIONAL_CORRECTNESS_PROVED"),
            assumptions=("the declared M90.2 dependency graph is complete for its two claims",
                         "validation covers deterministic mutation classes, not all future nodes",
                         "human release approval remains outside the downgrade engine"),
            deployment_profiles=("microkernel",),
            hardware_profiles=("formalkernel-demo",),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/m90_binary_evidence.json",
                "examples/formalkernel/kernel/m90_invalidation.validation.json",
                "pipeline/evidence_invalidation.py"),
            maturity_from="proof-carrying-binary",
            maturity_to="dependency-sensitive-evidence-lattice",
            maturity_requires_step=3, current_step=3, step_status="complete",
            current_maturity="dependency-sensitive-evidence-lattice",
            completed_claims=("EVIDENCE_DEPENDENCY_CLOSURE_VALIDATED",
                              "EVIDENCE_INVALIDATION_SEMANTICS_VALIDATED")),
    ),
    CapabilitySpec(
        name="m90_4_reproducible_build_observation",
        description="Independent clean-build and evidence-root reproducibility observation.",
        epistemic_boundary=("Observes identical raw ELF bytes, parsed structure, applicable "
                            "closure, and canonical evidence roots across two clean staged "
                            "builds. Finite observations are empirical and do not prove future "
                            "build determinism or compiler correctness."),
        milestone=MilestoneMetadata(
            lane="M90_4_reproducible_build_observation",
            deployment_split="qemu_aarch64_reproducible_build",
            required_judges=("Rustc",),
            claims=(ClaimStage("REPRODUCIBLE_BINARY_BUILD_OBSERVED", 4),
                    ClaimStage("REPRODUCIBLE_EVIDENCE_ROOT_OBSERVED", 4)),
            claims_forbidden=("REPRODUCIBLE_BUILD_PROVED",
                              "COMPILER_REFINEMENT_CHAIN_PROVED",
                              "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED"),
            assumptions=("two clean builds are observations rather than a universal theorem",
                         "temporary output path spelling is excluded only from the canonical evidence root",
                         "raw ELF bytes and structural digests are never normalized"),
            deployment_profiles=("microkernel",),
            hardware_profiles=("formalkernel-demo",),
            artifact_hash_bindings=(
                "examples/formalkernel/kernel/m90_build_config.json",
                "examples/formalkernel/kernel/m90_binary_evidence.json",
                "examples/formalkernel/kernel/m90_reproducibility.validation.json",
                "pipeline/reproducible_build.py"),
            maturity_from="dependency-sensitive-evidence-lattice",
            maturity_to="reproducible-build-observed",
            maturity_requires_step=4, current_step=4, step_status="complete",
            current_maturity="reproducible-build-observed",
            completed_claims=("REPRODUCIBLE_BINARY_BUILD_OBSERVED",
                              "REPRODUCIBLE_EVIDENCE_ROOT_OBSERVED")),
    ),
    CapabilitySpec(
        name="m90_5_human_release_sealing",
        description="Human-controlled exact-hash deployment evidence sealing.",
        epistemic_boundary=("A human supplied both accepted hashes and the release identity "
                            "through the CLI-only trust action. The resulting unkeyed content "
                            "seal is release authorization, never signer identity or a "
                            "correctness proof."),
        milestone=MilestoneMetadata(
            lane="M90_5_human_release_sealing",
            deployment_split="qemu_aarch64_human_release",
            required_judges=("Rustc",),
            claims=(ClaimStage("SEALED_DEPLOYMENT_EVIDENCE", 5),),
            claims_forbidden=("SEALED_DEPLOYMENT_EVIDENCE_VIA_MCP",
                              "COMPILER_REFINEMENT_CHAIN_PROVED",
                              "TARGET_BINARY_FUNCTIONAL_CORRECTNESS_PROVED",
                              "END_TO_END_REFINEMENT_CHAIN_ESTABLISHED"),
            assumptions=("the content seal is unkeyed and is not a signer identity",
                         "a human must explicitly accept both hashes and the release identity",
                         "hardware-backed signing and remote attestation are deferred to M108"),
            deployment_profiles=("microkernel",),
            hardware_profiles=("formalkernel-demo",),
            artifact_hash_bindings=(
                "pipeline/deployment_sealing.py",
                "examples/formalkernel/releases/formalkernel-m90-qemu-aarch64-2026.08.21.sealed.json"),
            maturity_from="reproducible-build-observed",
            maturity_to="human-authorized-release", maturity_requires_step=5,
            current_step=5, step_status="complete",
            current_maturity="proof-carrying-deployment-frozen",
            completed_claims=("SEALED_DEPLOYMENT_EVIDENCE",)),
    ),
    CapabilitySpec(
        name="m91_1_riscv_platform_feasibility",
        description="Reviewed RV64 architecture models and exact production QEMU deployment evidence.",
        epistemic_boundary=("Binds reviewed RV64 host and guest models separately from an exact "
                            "production RV64 ELF. The current binary compiles only reviewed boot "
                            "composition, so every M91 architecture theorem remains model-only and "
                            "inapplicable to that ELF. QEMU, compiler, and silicon semantics are not proved."),
        milestone=MilestoneMetadata(
            lane="M91_1_riscv_platform_feasibility",
            deployment_split="fk_lab_riscv64_candidate",
            required_judges=("TLC", "Deterministic Sv39 walker"),
            claims=(ClaimStage("RISCV_PRIVILEGE_TRANSITION_MODEL_PROVED", 2),
                    ClaimStage("RISCV_SPATIAL_ISOLATION_PROVED", 3),
                    ClaimStage("RISCV_INTERRUPT_ROUTING_MODEL_PROVED", 4),
                    ClaimStage("RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED", 5),
                    ClaimStage("RISCV_G_STAGE_ISOLATION_PROVED", 6),
                    ClaimStage("RISCV_GUEST_INTERRUPT_ROUTING_MODEL_PROVED", 7),
                    ClaimStage("RISCV_GUEST_ISOLATION_MODEL_PROVED", 8),
                    ClaimStage("PROOF_CARRYING_BINARY_VALIDATED", 9)),
            claims_forbidden=("RISCV_PHYSICAL_EXECUTION_PROVED",
                              "RISCV_HARDWARE_CONFORMANCE_PROVED",
                              "RISCV_HARDWARE_PRIVILEGE_TRANSITION_PROVED",
                              "RISCV_COMPILED_TRAP_VECTOR_REFINEMENT_PROVED",
                              "RISCV_HARDWARE_PAGE_WALK_PROVED",
                              "RISCV_TLB_COHERENCE_PROVED",
                              "RISCV_COMPILED_MMU_REFINEMENT_PROVED",
                              "RISCV_PHYSICAL_SPATIAL_ISOLATION_PROVED",
                              "RISCV_HARDWARE_INTERRUPT_DELIVERY_PROVED",
                              "RISCV_AIA_IMPLEMENTATION_REFINEMENT_PROVED",
                              "RISCV_PHYSICAL_INTERRUPT_ROUTING_PROVED",
                              "RISCV_VS_INTERRUPT_ROUTING_PROVED",
                              "RISCV_INTERRUPT_LATENCY_BOUND_PROVED",
                              "RISCV_GUEST_DEVICE_DMA_ISOLATION_PROVED",
                              "RISCV_DIRECT_DEVICE_ASSIGNMENT_PROVED",
                              "RISCV_IOMMU_GUEST_MSI_REMAP_PROVED",
                              "RISCV_IOMMU_PHYSICAL_ENFORCEMENT_PROVED"),
            assumptions=("normative specifications are URL/release pinned but not vendored",
                         "the theorem models control state rather than QEMU or silicon semantics",
                         "AIA/IMSIC and H-extension implementation correspondence remain pending"),
            deployment_profiles=("microkernel",),
            hardware_profiles=("riscv64-qemu",),
            artifact_hash_bindings=(
                "examples/formalkernel/profiles/riscv64-qemu.reviewed.json",
                "examples/formalkernel/kernel/m91_riscv_feasibility.json",
                "examples/formalkernel/kernel/riscv_privilege_transition.json",
                "examples/formalkernel/kernel/riscv_privilege_transition.validation.json",
                "examples/formalkernel/kernel/riscv_sv39.json",
                "examples/formalkernel/kernel/riscv_sv39_plan.json",
                "examples/formalkernel/kernel/riscv_sv39_plan.reviewed.json",
                "examples/formalkernel/kernel/riscv_sv39.validation.json",
                "examples/formalkernel/kernel/riscv_aia.json",
                "examples/formalkernel/kernel/riscv_aia_policy.json",
                "examples/formalkernel/kernel/riscv_aia_policy.reviewed.json",
                "examples/formalkernel/kernel/riscv_aia.qualification.json",
                "examples/formalkernel/kernel/riscv_aia.validation.json",
                "examples/formalkernel/kernel/riscv_hs_vs.json",
                "examples/formalkernel/kernel/riscv_hs_vs_policy.json",
                "examples/formalkernel/kernel/riscv_hs_vs_policy.reviewed.json",
                "examples/formalkernel/kernel/riscv_hs_vs.qualification.json",
                "examples/formalkernel/kernel/riscv_hs_vs.validation.json",
                "pipeline/riscv_guest_privilege.py",
                "examples/formalkernel/kernel/riscv_gstage.json",
                "examples/formalkernel/kernel/riscv_gstage_plan.json",
                "examples/formalkernel/kernel/riscv_gstage_plan.reviewed.json",
                "examples/formalkernel/kernel/riscv_gstage.qualification.json",
                "examples/formalkernel/kernel/riscv_gstage.validation.json",
                "pipeline/riscv_gstage.py",
                "examples/formalkernel/kernel/riscv_vs_imsic.json",
                "examples/formalkernel/kernel/riscv_vs_imsic_policy.json",
                "examples/formalkernel/kernel/riscv_vs_imsic_policy.reviewed.json",
                "examples/formalkernel/kernel/riscv_vs_imsic.qualification.json",
                "examples/formalkernel/kernel/riscv_vs_imsic.validation.json",
                "examples/formalkernel/kernel/riscv_vs_imsic_qemu.json",
                "pipeline/riscv_guest_interrupt.py",
                "examples/formalkernel/kernel/riscv_guest_isolation_composition.json",
                "examples/formalkernel/kernel/riscv_guest_isolation_composition.validation.json",
                "pipeline/riscv_guest_isolation_composition.py",
                "examples/formalkernel/boot/src/riscv64_main.rs",
                "examples/formalkernel/boot/layout-riscv64.ld",
                "examples/formalkernel/boot/m91-qemu-riscv64.elf",
                "examples/formalkernel/kernel/m91_riscv_build_config.json",
                "examples/formalkernel/kernel/m91_riscv_binary_evidence.json",
                "examples/formalkernel/kernel/m91_riscv_boot.validation.json",
                "examples/formalkernel/kernel/m91_riscv_invalidation.validation.json",
                "examples/formalkernel/kernel/m91_riscv_reproducibility.validation.json",
                "examples/formalkernel/releases/formalkernel-m91-qemu-riscv64-2026.08.22.sealed.json",
                "pipeline/riscv_deployment.py",
                "pipeline/riscv_feasibility.py",
                "pipeline/riscv_privilege_transition.py",
                "pipeline/riscv_sv39.py"),
            maturity_from="roadmap", maturity_to="reviewed-riscv-platform",
            maturity_requires_step=2, current_step=9, step_status="complete",
            current_maturity="sealed-rv64-deployment-evidence-frozen",
            completed_claims=("RISCV_PRIVILEGE_TRANSITION_MODEL_PROVED",
                              "RISCV_SPATIAL_ISOLATION_PROVED",
                              "RISCV_INTERRUPT_ROUTING_MODEL_PROVED",
                              "RISCV_GUEST_PRIVILEGE_TRANSITION_MODEL_PROVED",
                              "RISCV_G_STAGE_ISOLATION_PROVED",
                              "RISCV_GUEST_INTERRUPT_ROUTING_MODEL_PROVED",
                              "RISCV_GUEST_ISOLATION_MODEL_PROVED",
                              "PROOF_CARRYING_BINARY_VALIDATED")),
    ),
    CapabilitySpec(
        name="m91_riscv_iommu",
        description="RISC-V IOMMU configuration lane parked without an emulated device.",
        epistemic_boundary=("QEMU 8.2.2 exposes no architectural RISC-V IOMMU device; "
                            "absence blocks only this lane and mints no IOMMU claim."),
        milestone=MilestoneMetadata(
            lane="M91_riscv_iommu", deployment_split="fk_lab_riscv64_qemu",
            required_judges=("RISC-V IOMMU device:pending",),
            claims=(ClaimStage("RISCV_IOMMU_CONFIGURATION_PROVED", 1),),
            claims_forbidden=("RISCV_IOMMU_PHYSICAL_ENFORCEMENT_PROVED",),
            assumptions=("a suitable emulator build or physical target is required",),
            deployment_profiles=("microkernel",), hardware_profiles=("riscv64-qemu",),
            artifact_hash_bindings=("examples/formalkernel/kernel/m91_riscv_feasibility.json",),
            maturity_from="roadmap", maturity_to="iommu-configuration-evidence",
            maturity_requires_step=1, current_step=0, step_status="pending",
            current_maturity="parked-no-qemu-iommu-device", completed_claims=()),
    ),
    CapabilitySpec(name="promote_domain", description="Human acceptance of reviewed evidence.",
                   cli_command="promote-domain", trust_action=True),
    CapabilitySpec(name="promote_queue_model",
                   description="Human acceptance of the M86.3 queue model.",
                   cli_command="promote-queue-model", trust_action=True),
    CapabilitySpec(name="promote_information_flow_scope",
                   description="Human acceptance of the M88 high/low scope.",
                   cli_command="promote-information-flow-scope", trust_action=True),
    CapabilitySpec(name="promote_declassification_policy",
                   description="Human acceptance of the M88 release policy.",
                   cli_command="promote-declassification-policy", trust_action=True),
    CapabilitySpec(name="promote_capability_authority",
                   description="Human acceptance of the M89 authority algebra.",
                   cli_command="promote-capability-authority", trust_action=True),
    CapabilitySpec(name="seal_deployment_evidence",
                   description="Human exact-hash authorization of an M90 release envelope.",
                   cli_command="seal-deployment-evidence", trust_action=True),
    CapabilitySpec(name="promote_riscv_platform",
                   description="Human acceptance of the M91.1 RISC-V platform profile.",
                   cli_command="promote-riscv-platform", trust_action=True),
    CapabilitySpec(name="promote_riscv_sv39_plan",
                   description="Human acceptance of the M91.3 Sv39 mapping plan.",
                   cli_command="promote-riscv-sv39-plan", trust_action=True),
    CapabilitySpec(name="promote_riscv_aia_policy",
                   description="Human acceptance of the M91.4 AIA routing policy.",
                   cli_command="promote-riscv-aia-policy", trust_action=True),
    CapabilitySpec(name="promote_riscv_guest_policy",
                   description="Human acceptance of the M91.5a HS/VS guest policy.",
                   cli_command="promote-riscv-guest-policy", trust_action=True),
    CapabilitySpec(name="promote_riscv_gstage_plan",
                   description="Human acceptance of the M91.5b G-stage plan.",
                   cli_command="promote-riscv-gstage-plan", trust_action=True),
    CapabilitySpec(name="promote_riscv_guest_interrupt_policy",
                   description="Human acceptance of the M91.5c VS IMSIC guest-file policy.",
                   cli_command="promote-riscv-guest-interrupt-policy", trust_action=True),
    CapabilitySpec(name="verify_riscv_deployment",
                   description="Build, boot, inventory, and reproduce the M91.6 RV64 ELF.",
                   cli_command="verify-riscv-deployment"),
    CapabilitySpec(name="seal_riscv_deployment_evidence",
                   description="Human exact-hash authorization of an M91.6 RV64 release.",
                   cli_command="seal-riscv-deployment-evidence", trust_action=True),
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
