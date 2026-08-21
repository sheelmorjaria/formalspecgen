# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M43/M46: the multi-architecture kernel evidence lattice.

One kernel, many architecture profiles. The architecture-agnostic claims
(lock-free linearizability over the C witness) are judged ONCE; the
physical claims (barrier correspondence, WCET, DMA isolation) run PER
PROFILE and mint scope-tagged entries — ``BARRIER_CORRESPONDENCE_PROVED
scope x86_tso`` and ``scope armv8_sc`` come from the same sources under
two human-owned profiles.

M46: a manifest may declare ``subsystems`` (subdirectories, each with
its own kernel.json) — the lanes run per subsystem and entries carry
their subsystem — plus a ``composition`` artifact judged by the
deterministic precondition-flow gate (``kernel_composition``), minting
SYSTEM_COMPOSITION_PROVED once, arch-agnostic.

Fail-closed discipline: a REAL violation in any lane fails the whole
bundle by name (a scope is never silently dropped); an ABSENT judge
(esbmc missing on this host) degrades that one entry to judge_pending —
never minted. Profile defects (no memory_model for the weak-memory
lane, no timing for WCET) fail closed: the human owns the profile.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path

import yaml

from .certification_matrix import verify_certification_traceability
from .deployment_profile import BOUNDARY_LANES, verify_deployment_profile
from .dma_isolation import dma_isolation
from .elf_loader import verify_elf_load
from .exception_transition import verify_exception_evidence
from .ipc_nameserver import verify_ipc_table
from .kani_refinement import verify_rust_refinement
from .kernel_composition import verify_composition
from .lockfree import verify_lockfree, verify_mpsc
from .mmu_isolation import verify_spatial_isolation
from .multicore_interference import enumerate_interference_channels
from .microarch_policy import verify_microarch_policy
from .n150_port import verify_n150_port
from .pq_tls_pool import verify_pq_tls_pool
from .pq_wcet import verify_pq_wcet
from .realtime import wcet_bound
from .r52_port import verify_r52_tcm_port
from .r52_smmu import verify_r52_smmu
from .rcu_verification import verify_rcu_bounded
from .scheduler_liveness import verify_scheduler_liveness_evidence
from .server_capabilities import verify_server_capabilities
from .syscall_boundary import verify_syscall_boundary
from .tcp_resource import verify_tcp_resource_evidence
from .tls_handshake import verify_tls_handshake_evidence
from .tool_qualification import verify_tool_qualification_evidence
from .unikernel_profile import verify_unikernel_build
from .vfs_crash import verify_vfs_crash_evidence
from .weak_memory import (MEMORY_MODELS, barrier_correspondence,
                          herd7_model_check)


def _refuse(code: str, message: str) -> dict:
    return {"status": "KERNEL_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_kernel(kernel_dir: str | Path,
                  profiles: list[str | Path],
                  manifest_name: str = "kernel.json") -> dict:
    """Run the M36–M39 lanes per subsystem, per profile, plus the M46
    composition gate when the manifest declares one. The manifest NAME
    selects the deployment profile: kernel.json (microkernel), monolith.json,
    or unikernel.json — one source tree, three honest bundles."""
    root = Path(kernel_dir)
    if not root.is_dir():
        return _refuse("kernel_dir_missing", str(root))
    manifest_path = root / manifest_name
    if not manifest_path.is_file():
        return _refuse("kernel_manifest_missing",
                       f"{manifest_name} declares the lanes (weak_memory, "
                       "lockfree, wcet, dma) — the lattice never guesses "
                       "which sources carry which obligations")
    try:
        manifest = _load_json(manifest_path)
    except (OSError, ValueError) as exc:
        return _refuse("kernel_manifest_invalid", str(exc))
    # M54: the deployment profile is checked FIRST — a monolithic
    # manifest carrying boundary artifacts is a contradiction, and
    # no lane runs until it is resolved
    profile_check = verify_deployment_profile(manifest)
    if profile_check["status"] != "DEPLOYMENT_PROFILE_OK":
        return _refuse(profile_check["code"], profile_check["message"])
    if not profiles:
        return _refuse("profiles_missing",
                       "at least one human-owned hardware profile is "
                       "required — physical scopes are never guessed")

    claims: list[dict] = []
    boundaries: list[dict] = []
    failures: list[dict] = []
    seen: set[tuple] = set()

    def mint(claim: str, scope: str, profile: str | None, source: str,
             judge: str = "deterministic_gate",
             subsystem: str | None = None,
             evidence: dict | None = None) -> None:
        key = (claim, scope, subsystem)
        if key in seen:
            return
        seen.add(key)
        entry = {"claim": claim, "scope": scope, "profile": profile,
                 "source": source, "judge": judge}
        if subsystem is not None:
            entry["subsystem"] = subsystem
        if evidence is not None:
            entry["evidence"] = evidence
        claims.append(entry)

    def pending(claim: str, scope: str, profile: str | None, source: str,
                judge: str, subsystem: str | None = None) -> None:
        """Record an absent judge — the claim is named but never minted."""
        key = (claim, scope, subsystem, "pending")
        if key in seen:
            return
        seen.add(key)
        entry = {"claim": claim, "scope": scope, "profile": profile,
                 "source": source, "status": "judge_pending",
                 "judge_pending": judge}
        if subsystem is not None:
            entry["subsystem"] = subsystem
        claims.append(entry)

    def fail(entry: dict) -> None:
        failures.append(entry)

    # --- M66: stripped, feature-gated single-EL1 build ---------------
    unikernel_build = manifest.get("unikernel_build")
    if profile_check["deployment"] == "unikernel":
        verdict = verify_unikernel_build(root / str(unikernel_build))
        if verdict["status"] == "UNIKERNEL_BUILD_PROVED":
            mint("UNIKERNEL_BUILD_PROVED", "cargo_feature_unikernel_el1", None,
                 str(unikernel_build), judge="cargo", evidence=verdict)
        elif verdict["status"] == "judge_pending":
            pending("UNIKERNEL_BUILD_PROVED", "cargo_feature_unikernel_el1",
                    None, str(unikernel_build), "cargo")
        else:
            fail({"claim": "UNIKERNEL_BUILD_PROVED",
                  "source": str(unikernel_build), "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    # --- subsystem resolution: flat manifest or declared subdirs -----
    subsystems: list[tuple[str | None, Path, dict]] = []
    declared = manifest.get("subsystems")
    if declared is None:
        subsystems.append((None, root, manifest))
    else:
        if not isinstance(declared, list) or not declared:
            return _refuse("subsystems_invalid",
                           "subsystems must be a non-empty list of "
                           "subdirectory names")
        for name in declared:
            sub_root = root / str(name)
            if not sub_root.is_dir():
                return _refuse("subsystem_dir_missing", str(sub_root))
            sub_manifest_path = sub_root / "kernel.json"
            if not sub_manifest_path.is_file():
                return _refuse("kernel_manifest_missing",
                               f"subsystem {name!r} has no kernel.json")
            try:
                subsystems.append((str(name), sub_root,
                                   _load_json(sub_manifest_path)))
            except (OSError, ValueError) as exc:
                return _refuse("kernel_manifest_invalid",
                               f"subsystem {name!r}: {exc}")

    # --- architecture-agnostic: the lock-free witness, judged once ---
    for sub_name, sub_root, sub_manifest in subsystems:
        for name in sub_manifest.get("lockfree", []):
            verdict = verify_lockfree(sub_root / name)
            if verdict["status"] == "LOCK_FREE_LINEARIZABILITY_PROVED":
                mint("LOCK_FREE_LINEARIZABILITY_PROVED",
                     "concurrent_interleaving_bmc", None, name,
                     judge="esbmc", subsystem=sub_name)
            elif verdict.get("code") == "esbmc_unavailable":
                pending("LOCK_FREE_LINEARIZABILITY_PROVED",
                        "concurrent_interleaving_bmc", None, name,
                        "esbmc", subsystem=sub_name)
            else:
                fail({"claim": "LOCK_FREE_LINEARIZABILITY_PROVED",
                      "subsystem": sub_name,
                      "source": name, "code": verdict.get("code"),
                      "message": verdict.get("message", verdict["status"])})

        # --- M50: the MPSC endpoint witness (the name-server lane) ---
        for name in sub_manifest.get("mpsc", []):
            verdict = verify_mpsc(sub_root / name)
            if verdict["status"] == "MPSC_BOUNDED_PARTITION_PROVED":
                mint("MPSC_BOUNDED_PARTITION_PROVED",
                     "partitioned_producer_interleaving_bmc", None, name,
                     judge="esbmc", subsystem=sub_name)
            elif verdict.get("code") == "esbmc_unavailable":
                pending("MPSC_BOUNDED_PARTITION_PROVED",
                        "partitioned_producer_interleaving_bmc", None,
                        name, "esbmc", subsystem=sub_name)
            else:
                fail({"claim": "MPSC_BOUNDED_PARTITION_PROVED",
                      "subsystem": sub_name,
                      "source": name, "code": verdict.get("code"),
                      "message": verdict.get("message", verdict["status"])})

        formal = sub_manifest.get("formal_domain")
        if formal is not None:
            try:
                reviewed_path = (sub_root / formal["reviewed"]).resolve()
                validation_path = (sub_root / formal["validation"]).resolve()
                refinement_path = (sub_root / formal["refinement"]).resolve()
                source_path = (sub_root / formal["source"]).resolve()
                from .v2_refinement import load_bound_reviewed_domain
                reviewed = load_bound_reviewed_domain(
                    reviewed_path, validation_path)
                refinement = yaml.safe_load(
                    refinement_path.read_text(encoding="utf-8"))
                source_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
                bindings = refinement["bindings"]
                valid = (
                    refinement.get("status") == "VERIFIED"
                    and refinement.get("production") is True
                    and bindings["accepted_candidate_sha256"] ==
                    reviewed.accepted_candidate_sha256
                    and bindings["accepted_evidence_sha256"] ==
                    reviewed.accepted_evidence_sha256
                    and bindings["implementation_sha256"] == source_hash
                    and refinement.get("hardware_judge", {}).get("result") ==
                    "VERIFIED"
                    and set(refinement.get("claims", [])) == {
                        "SOURCE_MODEL_REFINEMENT",
                        "HARDWARE_MEMORY_BOUND_PROVED"})
            except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
                fail({"claim": "FORMAL_DOMAIN_BUNDLE", "subsystem": sub_name,
                      "code": "formal_domain_invalid", "message": str(exc)})
            else:
                if not valid:
                    fail({"claim": "FORMAL_DOMAIN_BUNDLE", "subsystem": sub_name,
                          "code": "formal_domain_binding_mismatch"})
                else:
                    mint("BOUNDED_ARCHITECTURE_EVIDENCE",
                         "reviewed_v2_tlc", None, str(validation_path),
                         judge="tlc", subsystem=sub_name)
                    mint("SOURCE_MODEL_REFINEMENT",
                         "v2_atomic_contract_refinement", None,
                         str(source_path), judge="prusti", subsystem=sub_name)
                    mint("HARDWARE_MEMORY_BOUND_PROVED",
                         "profile_bound_static_pool", None,
                         str(source_path), judge="z3", subsystem=sub_name)

        crash_journal = sub_manifest.get("crash_journal")
        if crash_journal is not None:
            try:
                journal = _load_json(sub_root / str(crash_journal))
                evidence = _load_json(sub_root / journal["validation"])
                verdict = verify_vfs_crash_evidence(journal, evidence)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                fail({"claim": "FILESYSTEM_CRASH_ATOMICITY_PROVED",
                      "subsystem": sub_name, "code": "VFS_CRASH_ARTIFACT_INVALID",
                      "message": str(exc)})
            else:
                if verdict["status"] == "VFS_CRASH_EVIDENCE_BOUND":
                    mint("FILESYSTEM_CRASH_ATOMICITY_PROVED",
                         "declared_persistence_contract", None,
                         str(crash_journal), judge="tlc", subsystem=sub_name,
                         evidence=verdict)
                    boundaries.append({
                        "claim": "PHYSICAL_CRASH_INJECTION_PENDING",
                        "scope": "device_fua_torn_write_fault_injection",
                        "status": "judge_pending", "profile": None,
                        "subsystem": sub_name,
                        "judge_pending": "crashmonkey_style_physical_injection",
                        "physical_fua_semantics_proved": False,
                    })
                else:
                    fail({"claim": "FILESYSTEM_CRASH_ATOMICITY_PROVED",
                          "subsystem": sub_name, "source": str(crash_journal),
                          "code": verdict.get("code")})

        adapter_name = sub_manifest.get("external_adapter")
        if adapter_name is not None:
            adapter_path = sub_root / str(adapter_name)
            try:
                adapter_code = adapter_path.read_text(encoding="utf-8")
                from .rust_support import check_rust_syntax, lint_rust
                syntax = check_rust_syntax(adapter_code)
                blockers = [item for item in lint_rust(adapter_code)
                            if item.get("severity") == "error"]
            except (OSError, ValueError) as exc:
                fail({"claim": "UNVERIFIED_EXTERNAL_ADAPTER",
                      "subsystem": sub_name, "code": "adapter_unreadable",
                      "message": str(exc)})
            else:
                if "UNVERIFIED EXTERNAL BOUNDARY" not in adapter_code:
                    fail({"claim": "UNVERIFIED_EXTERNAL_ADAPTER",
                          "subsystem": sub_name,
                          "code": "external_boundary_marker_missing"})
                elif syntax.get("status") != "RUST_CHECKED" or blockers:
                    fail({"claim": "UNVERIFIED_EXTERNAL_ADAPTER",
                          "subsystem": sub_name,
                          "code": "adapter_static_check_failed",
                          "message": syntax.get("output", "")})
                else:
                    microkernel = profile_check["deployment"] == "microkernel"
                    boundary = {
                        "claim": ("UNVERIFIED_EXTERNAL_ADAPTER" if microkernel
                                  else "UNVERIFIED_IN_KERNEL_DRIVER"),
                        "scope": ("external_device_behavior" if microkernel
                                  else "in_kernel_device_behavior"),
                        "profile": None, "source": str(adapter_name),
                        "status": "boundary", "judge": "none",
                        "subsystem": sub_name,
                        "source_sha256": hashlib.sha256(
                            adapter_code.encode()).hexdigest(),
                        "external_io_safety_proved": False,
                        "driver_recovery_proved": False,
                        "in_kernel_fault_can_crash_kernel": not microkernel,
                        "confinement_claims": ([
                            "DMA_ISOLATION_PROVED",
                            "SYSCALL_BOUNDARY_PROVED",
                            "IPC_ENDPOINT_TABLE_PROVED"] if microkernel else []),
                    }
                    if microkernel:
                        claims.append(boundary)
                    else:
                        boundaries.append(boundary)

        handshake_name = sub_manifest.get("tls_handshake")
        if handshake_name is not None:
            handshake_path = sub_root / str(handshake_name)
            try:
                handshake = _load_json(handshake_path)
                handshake_source = (sub_root / handshake["source"]).read_bytes()
                handshake_evidence = _load_json(
                    sub_root / handshake["validation"])
                verdict = verify_tls_handshake_evidence(
                    handshake, handshake_source, handshake_evidence)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                fail({"claim": "BOUNDED_ARCHITECTURE_EVIDENCE",
                      "subsystem": sub_name, "code": "TLS_HANDSHAKE_ARTIFACT_INVALID",
                      "message": str(exc)})
            else:
                if verdict["status"] == "TLS_HANDSHAKE_EVIDENCE_BOUND":
                    mint("BOUNDED_ARCHITECTURE_EVIDENCE",
                         "tls_handshake_tlc", None, str(handshake_name),
                         judge="tlc", subsystem=sub_name)
                    boundaries.append({
                        "claim": "TLS_HANDSHAKE_REFINEMENT_PENDING",
                        "scope": "mbedtls_and_liboqs_implementation",
                        "profile": None, "source": str(handshake_name),
                        "status": "boundary", "judge": "none",
                        "subsystem": sub_name,
                        "cryptographic_strength_proved": False,
                        "transcript_authenticity_proved": False,
                        "mbedtls_implementation_refinement_proved": False,
                    })
                else:
                    fail({"claim": "BOUNDED_ARCHITECTURE_EVIDENCE",
                          "subsystem": sub_name, "source": str(handshake_name),
                          "code": verdict.get("code"),
                          "message": verdict.get("message", "")})

        tcp_resource_name = sub_manifest.get("tcp_resource")
        if tcp_resource_name is not None:
            try:
                tcp = _load_json(sub_root / str(tcp_resource_name))
                tcp_evidence = _load_json(sub_root / tcp["validation"])
                verdict = verify_tcp_resource_evidence(tcp, tcp_evidence)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                fail({"claim": "TCP_RESOURCE_CONTAINMENT_PROVED",
                      "subsystem": sub_name,
                      "code": "TCP_RESOURCE_ARTIFACT_INVALID",
                      "message": str(exc)})
            else:
                if verdict["status"] == "TCP_RESOURCE_EVIDENCE_BOUND":
                    mint("TCP_RESOURCE_CONTAINMENT_PROVED",
                         "bounded_adversarial_network_and_partitioned_quotas",
                         None, str(tcp_resource_name), judge="tlc",
                         subsystem=sub_name, evidence=verdict)
                    boundaries.append({
                        "claim": "TCP_PROTOCOL_REFINEMENT_PENDING",
                        "scope": "rfc9293_rfc5961_and_native_stack",
                        "status": "judge_pending", "profile": None,
                        "subsystem": sub_name,
                        "judge_pending": "tcp_implementation_refinement",
                        "rfc9293_conformance_proved": False,
                        "rfc5961_conformance_proved": False,
                    })
                else:
                    fail({"claim": "TCP_RESOURCE_CONTAINMENT_PROVED",
                          "subsystem": sub_name,
                          "source": str(tcp_resource_name),
                          "code": verdict.get("code")})

        liveness_name = sub_manifest.get("scheduler_liveness")
        if liveness_name is not None:
            try:
                liveness_artifact = _load_json(sub_root / liveness_name)
                liveness_evidence = _load_json(
                    sub_root / liveness_artifact["validation"])
                verdict = verify_scheduler_liveness_evidence(
                    liveness_artifact, sub_root, liveness_evidence)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                fail({"claim": "SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED",
                      "subsystem": sub_name,
                      "code": "SCHEDULER_LIVENESS_ARTIFACT_INVALID",
                      "message": str(exc)})
            else:
                if verdict["status"] == "SCHEDULER_LIVENESS_EVIDENCE_BOUND":
                    mint("SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED",
                         "tlc_per_task_under_weak_scheduler_fairness", None,
                         str(liveness_name), judge="tlc", subsystem=sub_name,
                         evidence={
                             "source_sha256": verdict["source_sha256"],
                             "generated_tla_sha256": verdict[
                                 "generated_tla_sha256"],
                             "task_count": verdict["task_count"],
                             "policy": verdict["policy"],
                             "distinct_states": verdict["distinct_states"],
                             "fairness": verdict["fairness"],
                             "unbounded_task_liveness_proved": False,
                             "hardware_timer_fairness_proved": False,
                             "source_model_refinement_proved": False,
                         })
                else:
                    fail({"claim": "SCHEDULER_STARVATION_FREEDOM_MODEL_PROVED",
                          "subsystem": sub_name, "source": str(liveness_name),
                          "code": verdict.get("code"),
                          "message": verdict.get("message", "")})

    loaded: list[tuple[str, dict]] = []
    for profile_path in profiles:
        path = Path(profile_path)
        try:
            loaded.append((path.stem, _load_json(path)))
        except (OSError, ValueError) as exc:
            return _refuse("profile_unreadable", f"{path}: {exc}")

    # --- M67: profile-bound R52 ITCM/DTCM placement -----------------
    r52_port_name = manifest.get("r52_port")
    if r52_port_name is not None:
        r52_profiles = [profile for _name, profile in loaded
                        if profile.get("target") == "r52"]
        if len(r52_profiles) != 1:
            return _refuse("R52_PROFILE_REQUIRED",
                           "the R52 port requires exactly one r52 hardware profile")
        verdict = verify_r52_tcm_port(root / str(r52_port_name), r52_profiles[0])
        if verdict["status"] == "R52_TCM_PLACEMENT_PROVED":
            mint(verdict["claim"], "declared_r52_itcm_dtcm_placement", "r52",
                 str(r52_port_name), evidence=verdict)
            boundaries.append({
                "claim": "R52_PHYSICAL_EXECUTION_PENDING",
                "scope": "physical_cortex_r52_board", "status": "judge_pending",
                "judge_pending": "physical_cortex_r52_board", "profile": "r52",
                "physical_boot_proved": False, "measured_wcet_proved": False,
            })
        else:
            fail({"claim": "R52_TCM_PLACEMENT_PROVED", "profile": "r52",
                  "source": str(r52_port_name), "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    # --- M68: reviewed SMMU streams correspond to DMA contracts -----
    r52_smmu_name = manifest.get("r52_smmu")
    if r52_smmu_name is not None:
        r52_profiles = [profile for _name, profile in loaded
                        if profile.get("target") == "r52"]
        if len(r52_profiles) != 1:
            return _refuse("R52_PROFILE_REQUIRED",
                           "the R52 SMMU gate requires exactly one r52 profile")
        verdict = verify_r52_smmu(root / str(r52_smmu_name), r52_profiles[0])
        if verdict["status"] == "SMMU_CONFIGURATION_CORRESPONDENCE_PROVED":
            mint(verdict["claim"], "r52_smmu_stream_dma_correspondence", "r52",
                 str(r52_smmu_name), evidence=verdict)
            boundaries.append({
                "claim": "R52_PHYSICAL_SMMU_VALIDATION_PENDING",
                "scope": "malicious_device_dma_fault_injection",
                "status": "judge_pending", "profile": "r52",
                "judge_pending": "physical_r52_smmu_fault_injection",
                "external_io_safety_proved": False,
            })
        else:
            fail({"claim": "SMMU_CONFIGURATION_CORRESPONDENCE_PROVED",
                  "profile": "r52", "source": str(r52_smmu_name),
                  "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    # --- M69: x86_64 image layout and VT-d configuration -----------
    n150_port_name = manifest.get("n150_port")
    if n150_port_name is not None:
        n150_profiles = [profile for _name, profile in loaded
                         if profile.get("target") == "n150"]
        if len(n150_profiles) != 1:
            return _refuse("N150_PROFILE_REQUIRED",
                           "the N150 port requires exactly one n150 profile")
        verdict = verify_n150_port(root / str(n150_port_name), n150_profiles[0])
        if verdict["status"] == "N150_PLATFORM_CONFIGURATION_PROVED":
            mint(verdict["claim"], "n150_x86_64_layout_vtd_correspondence",
                 "n150", str(n150_port_name), evidence=verdict)
            boundaries.append({
                "claim": "N150_PHYSICAL_EXECUTION_PENDING",
                "scope": "physical_intel_n150", "status": "judge_pending",
                "profile": "n150", "judge_pending": "physical_intel_n150",
                "physical_boot_proved": False, "physical_vtd_proved": False,
                "physical_tso_conformance_proved": False,
            })
        else:
            fail({"claim": "N150_PLATFORM_CONFIGURATION_PROVED",
                  "profile": "n150", "source": str(n150_port_name),
                  "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    # --- M74: declared microarchitectural mitigation policy ---------
    microarch_policy_name = manifest.get("microarch_policy")
    if microarch_policy_name is not None:
        n150_profiles = [profile for _name, profile in loaded
                         if profile.get("target") == "n150"]
        if len(n150_profiles) != 1:
            return _refuse(
                "N150_PROFILE_REQUIRED",
                "the mitigation-policy gate requires exactly one n150 profile")
        verdict = verify_microarch_policy(
            root / str(microarch_policy_name), n150_profiles[0])
        if verdict["status"] == "MICROARCH_MITIGATION_POLICY_PROVED":
            mint("MICROARCH_MITIGATION_POLICY_PROVED",
                 "declared_cpuid_microcode_mitigation_completeness", "n150",
                 str(microarch_policy_name), judge="z3", evidence=verdict)
            mint("MITIGATION_WCET_BUDGET_PROVED",
                 "declared_mitigation_cycle_cost_budget", "n150",
                 str(microarch_policy_name),
                 judge="deterministic_cost_equation", evidence=verdict)
            boundaries.extend((
                {"claim": "RUNTIME_MICROARCH_PROFILE_VALIDATION_PENDING",
                 "scope": "runtime_cpuid_and_microcode_revision", "profile": "n150",
                 "status": "judge_pending",
                 "judge_pending": "authenticated_runtime_platform_probe",
                 "runtime_cpuid_validated": False,
                 "runtime_microcode_validated": False},
                {"claim": "MEASURED_MITIGATION_WCET_PENDING",
                 "scope": "physical_mitigation_latency", "profile": "n150",
                 "status": "judge_pending",
                 "judge_pending": "target_cycle_measurement",
                 "measured_cost_validated": False},
                {"claim": "SPECULATIVE_NONINTERFERENCE_PENDING",
                 "scope": "physical_microarchitectural_information_flow",
                 "profile": "n150", "status": "judge_pending",
                 "judge_pending": "microarchitectural_noninterference_judge",
                 "speculative_noninterference_proved": False},
            ))
        elif verdict["status"] == "judge_pending":
            pending("MICROARCH_MITIGATION_POLICY_PROVED",
                    "declared_cpuid_microcode_mitigation_completeness", "n150",
                    str(microarch_policy_name), verdict["judge_pending"])
            pending("MITIGATION_WCET_BUDGET_PROVED",
                    "declared_mitigation_cycle_cost_budget", "n150",
                    str(microarch_policy_name), verdict["judge_pending"])
        else:
            fail({"claim": "MICROARCH_MITIGATION_POLICY_PROVED",
                  "profile": "n150", "source": str(microarch_policy_name),
                  "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    # --- M71.5: enumerate shared-hardware interference channels -----
    interference_name = manifest.get("multicore_interference")
    if interference_name is not None:
        verdict = enumerate_interference_channels(
            root / str(interference_name), [profile for _name, profile in loaded])
        if verdict["status"] == "MULTICORE_INTERFERENCE_CHANNELS_ENUMERATED":
            mint(verdict["claim"], "profile_bound_shared_hardware_inventory",
                 None, str(interference_name), evidence=verdict)
            boundaries.append({
                "claim": "TARGET_WCET_INTERFERENCE_BOUND_PENDING",
                "scope": "authenticated_target_measurements",
                "status": "judge_pending", "profile": None,
                "judge_pending": "authenticated_target_interference_measurements",
                "target_wcet_interference_bound_validated": False,
            })
        else:
            fail({"claim": "MULTICORE_INTERFERENCE_CHANNELS_ENUMERATED",
                  "source": str(interference_name), "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    # --- M71: parameterized RCU invariant + bounded C witness -------
    rcu_name = manifest.get("rcu")
    if rcu_name is not None:
        verdict = verify_rcu_bounded(root / str(rcu_name))
        if verdict["status"] == "RCU_RECLAMATION_SAFETY_PROVED":
            mint(verdict["claim"], verdict["scope"], None, str(rcu_name),
                 judge=verdict["judge"], evidence=verdict)
            boundaries.append({
                "claim": "RCU_IMPLEMENTATION_REFINEMENT_PENDING",
                "scope": "source_model_irq_nmi_callback_pressure",
                "status": "judge_pending", "profile": None,
                "judge_pending": verdict["judge_pending"],
                "implementation_refinement_proved": False,
            })
        elif verdict["status"] == "judge_pending":
            pending("RCU_RECLAMATION_SAFETY_PROVED",
                    "parameterized_grace_period_invariant", None,
                    str(rcu_name), verdict["judge_pending"])
        else:
            fail({"claim": "RCU_RECLAMATION_SAFETY_PROVED",
                  "source": str(rcu_name), "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    herd_models = None
    if manifest.get("weak_memory_models") is not None:
        try:
            herd_models = _load_json(root / manifest["weak_memory_models"])
        except (OSError, ValueError, TypeError) as exc:
            return _refuse("weak_memory_models_invalid", str(exc))
    herd_results: dict[str, dict] = {}

    for profile_name, profile in loaded:
        target = profile.get("target", profile_name)
        for sub_name, sub_root, sub_manifest in subsystems:
            memory_model = profile.get("memory_model")
            for name in sub_manifest.get("weak_memory", []):
                if not memory_model:
                    return _refuse(
                        "profile_field_missing",
                        f"profile {target} declares no memory_model — the "
                        "weak-memory scope is a human declaration")
                if memory_model not in MEMORY_MODELS:
                    return _refuse("profile_field_missing",
                                   f"profile {target}: unknown memory_model "
                                   f"{memory_model!r}")
                verdict = barrier_correspondence(sub_root / name,
                                                 memory_model)
                if verdict["status"] == "BARRIER_CORRESPONDENCE_PROVED":
                    mint("BARRIER_CORRESPONDENCE_PROVED", memory_model,
                         target, name, subsystem=sub_name)
                    if herd_models is None:
                        pending("WEAK_MEMORY_SAFETY_PROVED", memory_model,
                                target, name, verdict.get(
                                    "judge_pending", "herd7_or_rc11"),
                                subsystem=sub_name)
                    else:
                        spec = herd_models.get(memory_model)
                        if not isinstance(spec, dict) or not all(
                                key in spec for key in ("litmus", "sha256")):
                            fail({"claim": "WEAK_MEMORY_SAFETY_PROVED",
                                  "profile": target,
                                  "code": "weak_memory_model_missing",
                                  "message": f"no hash-bound herd7 input for {memory_model}"})
                            continue
                        if memory_model not in herd_results:
                            herd_results[memory_model] = herd7_model_check(
                                root / spec["litmus"], memory_model,
                                expected_sha256=spec["sha256"])
                        herd = herd_results[memory_model]
                        if herd["status"] == "WEAK_MEMORY_SAFETY_PROVED":
                            mint("WEAK_MEMORY_SAFETY_PROVED", memory_model,
                                 target, spec["litmus"], judge="herd7",
                                 subsystem=sub_name, evidence={
                                     "litmus_sha256": herd["litmus_sha256"],
                                     "output_sha256": herd["output_sha256"],
                                     "observation": herd["observation"],
                                     "epistemic_boundary": herd[
                                         "epistemic_boundary"],
                                 })
                        elif herd["status"] == "judge_pending":
                            pending("WEAK_MEMORY_SAFETY_PROVED", memory_model,
                                    target, spec["litmus"], "herd7",
                                    subsystem=sub_name)
                        else:
                            fail({"claim": "WEAK_MEMORY_SAFETY_PROVED",
                                  "profile": target, "source": spec["litmus"],
                                  "code": herd.get("code"),
                                  "message": herd.get("message", "")})
                else:
                    fail({"claim": "BARRIER_CORRESPONDENCE_PROVED",
                          "profile": target, "subsystem": sub_name,
                          "source": name, "code": verdict.get("code"),
                          "message": verdict.get("message", "")})

            profile_timing = profile.get("timing", {})
            for name, file_timing in sub_manifest.get("wcet", {}).items():
                timing = {**profile_timing, **(file_timing or {})}
                if "max_cycles" not in timing:
                    return _refuse("profile_field_missing",
                                   f"profile {target} declares no "
                                   "timing.max_cycles — a deadline is a "
                                   "human declaration")
                if profile.get("cost_model"):
                    timing["cost_model"] = {
                        **(timing.get("cost_model") or {}),
                        **profile["cost_model"]}
                verdict = wcet_bound(sub_root / name, timing)
                if verdict["status"] == "WCET_BOUND_PROVEN":
                    mint("WCET_BOUND_PROVEN",
                         f"static_cfg_cost_model_{target}", target, name,
                         subsystem=sub_name)
                else:
                    fail({"claim": "WCET_BOUND_PROVED", "profile": target,
                          "subsystem": sub_name, "source": name,
                          "code": verdict.get("code"),
                          "message": verdict.get("message", "")})

            memory_map = (profile.get("memory_map")
                          or sub_manifest.get("memory_map"))
            contracts = (profile.get("dma_contracts")
                         or sub_manifest.get("dma_contracts"))
            for name in sub_manifest.get("dma", []):
                if not memory_map or not contracts:
                    return _refuse("profile_field_missing",
                                   f"profile {target} declares no "
                                   "memory_map/dma_contracts — the IOMMU "
                                   "correspondence needs the physical map")
                verdict = dma_isolation(sub_root / name, memory_map,
                                        contracts)
                if verdict["status"] == "DMA_ISOLATION_PROVED":
                    mint("DMA_ISOLATION_PROVED",
                         f"deterministic_range_disjointness_{target}",
                         target, name, subsystem=sub_name)
                else:
                    fail({"claim": "DMA_ISOLATION_PROVED", "profile": target,
                          "subsystem": sub_name, "source": name,
                          "code": verdict.get("code"),
                          "message": verdict.get("message", "")})

            pq_name = sub_manifest.get("pq_tls")
            if pq_name is not None:
                pq_path = sub_root / str(pq_name)
                try:
                    pq = _load_json(pq_path)
                    pq_source_name = pq["source"]
                    pq_source = (sub_root / str(pq_source_name)).read_text(encoding="utf-8")
                    pq_hash = hashlib.sha256(pq_source.encode()).hexdigest()
                    from .rust_support import check_rust_syntax, lint_rust
                    syntax = check_rust_syntax(pq_source)
                    blockers = [item for item in lint_rust(pq_source)
                                if item.get("severity") == "error"]
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    fail({"claim": "HARDWARE_MEMORY_BOUND_PROVED",
                          "profile": target, "subsystem": sub_name,
                          "code": "PQ_TLS_ARTIFACT_INVALID", "message": str(exc)})
                    continue
                if pq.get("source_sha256") != pq_hash:
                    fail({"claim": "HARDWARE_MEMORY_BOUND_PROVED",
                          "profile": target, "subsystem": sub_name,
                          "code": "PQ_TLS_SOURCE_HASH_MISMATCH"})
                    continue
                if syntax.get("status") != "RUST_CHECKED" or blockers:
                    fail({"claim": "HARDWARE_MEMORY_BOUND_PROVED",
                          "profile": target, "subsystem": sub_name,
                          "code": "PQ_TLS_STATIC_CHECK_FAILED",
                          "message": syntax.get("output", "")})
                    continue
                verdict = verify_pq_tls_pool(pq, profile)
                if verdict["status"] == "PQ_TLS_POOL_BOUND_PROVED":
                    mint("HARDWARE_MEMORY_BOUND_PROVED",
                         f"pq_tls_session_pool_{target}", target,
                         str(pq_name), judge="z3", subsystem=sub_name)
                elif verdict.get("code") == "z3_unavailable":
                    pending("HARDWARE_MEMORY_BOUND_PROVED",
                            f"pq_tls_session_pool_{target}", target,
                            str(pq_name), "z3", subsystem=sub_name)
                else:
                    fail({"claim": "HARDWARE_MEMORY_BOUND_PROVED",
                          "profile": target, "subsystem": sub_name,
                          "source": str(pq_name), "code": verdict.get("code"),
                          "message": verdict.get("message", "")})

            pq_wcet_name = sub_manifest.get("pq_wcet")
            if pq_wcet_name is not None:
                try:
                    pq_wcet_artifact = _load_json(sub_root / str(pq_wcet_name))
                    workload = (sub_root / pq_wcet_artifact["source"]).read_bytes()
                    scheduler_path = (sub_root / pq_wcet_artifact["microkernel"][
                        "scheduler_source"]).resolve()
                    verdict = verify_pq_wcet(
                        pq_wcet_artifact, workload, scheduler_path, profile,
                        profile_check["deployment"])
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    fail({"claim": "PQ_WCET", "profile": target,
                          "subsystem": sub_name, "code": "PQ_WCET_ARTIFACT_INVALID",
                          "message": str(exc)})
                    continue
                if verdict["status"] == "PQ_PREEMPTION_BOUND_PROVED":
                    mint("PQ_PREEMPTION_BOUND_PROVED", verdict["scope"], target,
                         str(pq_wcet_name), judge="static_wcet", subsystem=sub_name)
                elif verdict["status"] == "PQ_COOPERATIVE_WCET_BOUND_PROVED":
                    mint("PQ_COOPERATIVE_WCET_BOUND_PROVED", verdict["scope"],
                         target, str(pq_wcet_name), subsystem=sub_name)
                else:
                    fail({"claim": "PQ_WCET", "profile": target,
                          "subsystem": sub_name, "source": str(pq_wcet_name),
                          "code": verdict.get("code"),
                          "message": verdict.get("message", "")})

    for sub_name, _sub_root, sub_manifest in subsystems:
        pq_name = sub_manifest.get("pq_tls")
        if pq_name is not None:
            boundaries.append({
                "claim": "UNVERIFIED_EXTERNAL_ADAPTER",
                "scope": "post_quantum_cryptographic_implementation",
                "profile": None, "source": "liboqs", "status": "boundary",
                "judge": "none", "subsystem": sub_name,
                "cryptographic_strength_proved": False,
                "liboqs_implementation_proved": False,
                "claims_proved": ["HARDWARE_MEMORY_BOUND_PROVED"],
                "note": "M58 proves session-pool capacity and ERR_MEM admission only",
            })
        if sub_manifest.get("pq_wcet") is not None:
            microkernel = profile_check["deployment"] == "microkernel"
            boundaries.append({
                "claim": ("HARDWARE_INTERRUPT_DELIVERY_PENDING" if microkernel
                          else "PQ_PREEMPTIVE_ISOLATION_NOT_AVAILABLE"),
                "scope": "pq_scheduler_silicon_boundary",
                "profile": None, "source": str(sub_manifest["pq_wcet"]),
                "status": "boundary", "judge": "none", "subsystem": sub_name,
                "hardware_interrupt_delivery_proved": False,
                "preemptive_isolation_proved": False,
                "declared_el0_preemption_model_proved": microkernel,
                "cooperative_yield_required": not microkernel,
            })

    # --- M46: the orchestrator's precondition flow, judged once ------
    composition_artifact = manifest.get("composition")
    if composition_artifact is not None:
        composition_path = root / str(composition_artifact)
        if not composition_path.is_file():
            return _refuse("composition_artifact_missing",
                           str(composition_path))
        try:
            artifact = _load_json(composition_path)
        except (OSError, ValueError) as exc:
            return _refuse("composition_artifact_invalid", str(exc))
        verdict = verify_composition(artifact)
        if verdict["status"] == "SYSTEM_COMPOSITION_PROVED":
            mint("SYSTEM_COMPOSITION_PROVED",
                 "deterministic_precondition_flow", None,
                 str(composition_artifact))
        else:
            fail({"claim": "SYSTEM_COMPOSITION_PROVED",
                  "source": str(composition_artifact),
                  "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    # --- M48: spatial isolation, per profile's physical map -----------
    mmu_artifact = manifest.get("mmu")
    if mmu_artifact is not None:
        mmu_path = root / str(mmu_artifact)
        if not mmu_path.is_file():
            return _refuse("mmu_artifact_missing", str(mmu_path))
        try:
            mmu = _load_json(mmu_path)
        except (OSError, ValueError) as exc:
            return _refuse("mmu_artifact_invalid", str(exc))
        mappings = mmu.get("mappings")
        for profile_name, profile in loaded:
            target = profile.get("target", profile_name)
            memory_map = (profile.get("mmu_map")
                          or mmu.get("memory_map"))
            if not memory_map:
                return _refuse("profile_field_missing",
                               f"profile {target} declares no mmu_map "
                               "and the artifact has no default — the "
                               "physical map is a human declaration")
            verdict = verify_spatial_isolation(memory_map, mappings)
            if verdict["status"] == "SPATIAL_ISOLATION_PROVED":
                mint("SPATIAL_ISOLATION_PROVED",
                     f"deterministic_range_disjointness_{target}",
                     target, str(mmu_artifact))
            else:
                fail({"claim": "SPATIAL_ISOLATION_PROVED",
                      "profile": target, "source": str(mmu_artifact),
                      "code": verdict.get("code"),
                      "message": verdict.get("message", "")})

    # --- M49: the syscall boundary, per profile's physical map ---------
    syscall_artifact = manifest.get("syscalls")
    if syscall_artifact is not None:
        sys_path = root / str(syscall_artifact)
        if not sys_path.is_file():
            return _refuse("syscalls_artifact_missing", str(sys_path))
        try:
            sys_artifact = _load_json(sys_path)
        except (OSError, ValueError) as exc:
            return _refuse("syscalls_artifact_invalid", str(exc))
        for profile_name, profile in loaded:
            target = profile.get("target", profile_name)
            memory_map = (profile.get("mmu_map")
                          or sys_artifact.get("memory_map"))
            if not memory_map:
                return _refuse("profile_field_missing",
                               f"profile {target} declares no mmu_map "
                               "and the syscall artifact has no default "
                               "— the physical map is a human "
                               "declaration")
            verdict = verify_syscall_boundary({**sys_artifact,
                                               "memory_map": memory_map})
            if verdict["status"] == "SYSCALL_BOUNDARY_PROVED":
                mint("SYSCALL_BOUNDARY_PROVED",
                     f"deterministic_dispatch_table_{target}",
                     target, str(syscall_artifact))
            else:
                fail({"claim": "SYSCALL_BOUNDARY_PROVED",
                      "profile": target, "source": str(syscall_artifact),
                      "code": verdict.get("code"),
                      "message": verdict.get("message", "")})

    # --- M50: the IPC name table, routed through the boundary ---------
    ipc_artifact = manifest.get("ipc")
    if ipc_artifact is not None:
        ipc_path = root / str(ipc_artifact)
        if not ipc_path.is_file():
            return _refuse("ipc_artifact_missing", str(ipc_path))
        try:
            ipc = _load_json(ipc_path)
        except (OSError, ValueError) as exc:
            return _refuse("ipc_artifact_invalid", str(exc))
        # the M49 lane already refused a missing/invalid dispatch-table
        # artifact behind the same manifest key; if the key is absent
        # here, the gate itself refuses (ENDPOINT_SYSCALL_TABLE_MISSING)
        syscall_name = manifest.get("syscalls")
        syscall_artifact = None
        if syscall_name is not None:
            syscall_artifact = _load_json(root / str(syscall_name))
        verdict = verify_ipc_table(ipc, syscall_artifact)
        if verdict["status"] == "IPC_ENDPOINT_TABLE_PROVED":
            mint("IPC_ENDPOINT_TABLE_PROVED",
                 "deterministic_capacity_partition", None,
                 str(ipc_artifact))
        else:
            fail({"claim": "IPC_ENDPOINT_TABLE_PROVED",
                  "source": str(ipc_artifact),
                  "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    # --- M53: the Kani refinement lane — the image's own Rust -------
    kani_result = None
    kani_dir = manifest.get("kani_proofs")
    if kani_dir is not None:
        verdict = verify_rust_refinement(root / str(kani_dir))
        kani_result = verdict
        if verdict["status"] == "RUST_WITNESS_REFINEMENT_PROVED":
            mint("RUST_WITNESS_REFINEMENT_PROVED",
                 "bounded_nondet_operation_sequences", None,
                 str(kani_dir), judge="kani")
        elif verdict.get("code") == "kani_unavailable":
            pending("RUST_WITNESS_REFINEMENT_PROVED",
                    "bounded_nondet_operation_sequences", None,
                    str(kani_dir), "kani")
        else:
            fail({"claim": "RUST_WITNESS_REFINEMENT_PROVED",
                  "source": str(kani_dir),
                  "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    # --- M64: fixed-capacity EL0 heap proved by the path-bound Kani crate
    heap_name = manifest.get("user_heap")
    if heap_name is not None:
        try:
            heap = _load_json(root / str(heap_name))
            heap_source = root / heap["source"]
            proof_source = (root / heap["proof_source"]).resolve()
            source_hash = hashlib.sha256(heap_source.read_bytes()).hexdigest()
            proof_hash = hashlib.sha256(proof_source.read_bytes()).hexdigest()
            source_text = heap_source.read_text(encoding="utf-8")
            valid = (
                source_hash == heap["source_sha256"]
                and proof_hash == heap["proof_sha256"]
                and heap["heap_blocks"] * heap["block_bytes"] ==
                heap["heap_bytes"] == 4096
                and "pub const HEAP_BLOCKS: usize = 16;" in source_text
                and "pub const BLOCK_BYTES: usize = 256;" in source_text
                and "user_heap_capacity_invariant" in
                proof_source.read_text(encoding="utf-8")
                and kani_result is not None
                and kani_result.get("status") ==
                "RUST_WITNESS_REFINEMENT_PROVED")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return _refuse("user_heap_artifact_invalid", str(exc))
        if valid:
            mint("USER_HEAP_CAPACITY_PROVED",
                 "kani_fixed_el0_heap_pool", None, str(heap_name),
                 judge="kani", evidence={
                     "source_sha256": source_hash,
                     "proof_sha256": proof_hash,
                     "heap_blocks": heap["heap_blocks"],
                     "block_bytes": heap["block_bytes"],
                     "heap_bytes": heap["heap_bytes"],
                     "exhaustion": heap["exhaustion"],
                     "physical_frame_assignment_proved": False,
                 })
        else:
            fail({"claim": "USER_HEAP_CAPACITY_PROVED",
                  "source": str(heap_name),
                  "code": "USER_HEAP_BINDING_MISMATCH",
                  "message": "heap constants, source, proof, or Kani result drifted"})

    capabilities_name = manifest.get("server_capabilities")
    if capabilities_name is not None:
        verdict = verify_server_capabilities(root / str(capabilities_name))
        if verdict["status"] == "SERVER_CAPABILITY_NONINTERFERENCE_PROVED":
            mint(verdict["claim"], "z3_bounded_server_capability_matrix", None,
                 str(capabilities_name), judge="z3", evidence=verdict)
        elif verdict["status"] == "judge_pending":
            pending("SERVER_CAPABILITY_NONINTERFERENCE_PROVED",
                    "z3_bounded_server_capability_matrix", None,
                    str(capabilities_name), "z3")
        else:
            fail({"claim": "SERVER_CAPABILITY_NONINTERFERENCE_PROVED",
                  "source": str(capabilities_name), "code": verdict.get("code")})

    # --- M62: bounded EL1/EL0 exception transition model ------------
    exception_artifact = manifest.get("exception_transition")
    if exception_artifact is not None:
        arm_profiles = [(name, profile) for name, profile in loaded
                        if profile.get("memory_model") == "armv8_sc"]
        if not arm_profiles:
            return _refuse(
                "exception_transition_profile_missing",
                "the EL1/EL0 ERET model requires an AArch64 profile")
        exception_path = root / str(exception_artifact)
        try:
            exception_model = _load_json(exception_path)
            exception_evidence = _load_json(
                root / exception_model["validation"])
            verdict = verify_exception_evidence(
                exception_model, root, exception_evidence)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return _refuse("exception_transition_artifact_invalid", str(exc))
        if verdict["status"] == "EXCEPTION_TRANSITION_EVIDENCE_BOUND":
            arm_name, arm_profile = arm_profiles[0]
            arm_target = arm_profile.get("target", arm_name)
            mint("EXCEPTION_LEVEL_TRANSITION_MODEL_PROVED",
                 "tlc_aarch64_el1_el0_control_state", arm_target,
                 str(exception_artifact), judge="tlc", evidence={
                     "bindings": verdict["bindings"],
                     "generated_tla_sha256": verdict[
                         "generated_tla_sha256"],
                     "tlc_version": verdict["tlc_version"],
                     "distinct_states": verdict["distinct_states"],
                     "hardware_eret_semantics_proved": False,
                     "compiled_vector_refinement_proved": False,
                 })
        else:
            fail({"claim": "EXCEPTION_LEVEL_TRANSITION_MODEL_PROVED",
                  "source": str(exception_artifact),
                  "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    # --- M57: bounded ELF64 layout + M48 permission correspondence --
    loader_artifact = manifest.get("elf_loader")
    if loader_artifact is not None:
        loader_path = root / str(loader_artifact)
        if not loader_path.is_file():
            return _refuse("elf_loader_artifact_missing", str(loader_path))
        try:
            loader = _load_json(loader_path)
            source_name = loader["source"]
            source_path = root / str(source_name)
            source = source_path.read_text(encoding="utf-8")
            source_hash = hashlib.sha256(source.encode()).hexdigest()
            from .rust_support import check_rust_syntax, lint_rust
            syntax = check_rust_syntax(source)
            blockers = [item for item in lint_rust(source)
                        if item.get("severity") == "error"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return _refuse("elf_loader_artifact_invalid", str(exc))
        if loader.get("source_sha256") != source_hash:
            fail({"claim": "ELF_SEGMENT_LAYOUT_PROVED",
                  "source": str(source_name),
                  "code": "ELF_LOADER_SOURCE_HASH_MISMATCH",
                  "message": "the load plan is not bound to the exact Rust parser bytes"})
        elif loader.get("input_capability") != "vfs.read" or not any(
                name == "vfs" and sub_manifest.get("formal_domain") is not None
                for name, _sub_root, sub_manifest in subsystems):
            fail({"claim": "ELF_SEGMENT_LAYOUT_PROVED",
                  "source": str(loader_artifact),
                  "code": "ELF_VFS_BINDING_MISSING",
                  "message": "the loader must consume the production VFS read capability"})
        elif syntax.get("status") != "RUST_CHECKED" or blockers:
            fail({"claim": "ELF_SEGMENT_LAYOUT_PROVED",
                  "source": str(source_name),
                  "code": "ELF_LOADER_STATIC_CHECK_FAILED",
                  "message": syntax.get("output", "")})
        else:
            mint("ELF_SEGMENT_LAYOUT_PROVED", "bounded_elf64_aarch64_parser",
                 None, str(source_name))
            for profile_name, profile in loaded:
                target = profile.get("target", profile_name)
                memory_map = profile.get("mmu_map")
                if not memory_map:
                    return _refuse("profile_field_missing",
                                   f"profile {target} declares no mmu_map for the ELF loader")
                verdict = verify_elf_load(loader, memory_map)
                if verdict["status"] == "ELF_LOAD_PROVED":
                    mint("ELF_PERMISSION_CORRESPONDENCE_PROVED",
                         f"elf_flags_to_m48_permissions_{target}", target,
                         str(loader_artifact))
                else:
                    fail({"claim": "ELF_PERMISSION_CORRESPONDENCE_PROVED",
                          "profile": target, "source": str(loader_artifact),
                          "code": verdict.get("code"),
                          "message": verdict.get("message", "")})
    elif profile_check["deployment"] in {"monolithic", "unikernel"}:
        omission_prefix = ("UNIKERNEL" if profile_check["deployment"] == "unikernel"
                           else "EL0")
        boundaries.append({
            "claim": f"{omission_prefix}_PROCESS_LOADER_OMITTED",
            "scope": "single_address_space",
            "status": "boundary", "judge": "none", "profile": None,
            "hardware_exception_level_transition_proved": False,
            "note": "the monolith never loads a separate EL0 process; no loader, UXN/AP, or ERET claim is minted",
        })
        boundaries.append({
            "claim": "EXCEPTION_LEVEL_TRANSITION_MODEL_OMITTED",
            "scope": "single_exception_level",
            "status": "boundary", "judge": "none", "profile": None,
            "hardware_exception_level_transition_proved": False,
            "note": "the monolith has no EL1-to-EL0 privilege transition",
        })
        boundaries.append({
            "claim": "EL0_USER_HEAP_OMITTED", "scope": "single_address_space",
            "status": "boundary", "judge": "none", "profile": None,
            "note": "the monolith has no separately confined EL0 heap grant",
        })
        boundaries.append({"claim": "SERVER_CAPABILITY_BOUNDARY_OMITTED",
                           "scope": "single_address_space", "status": "boundary",
                           "judge": "none", "profile": None})
        if profile_check["deployment"] == "unikernel":
            boundaries.append({
                "claim": "UNIKERNEL_BOUNDARIES_STRIPPED",
                "scope": "single_el1_image", "status": "boundary",
                "judge": "deterministic_gate", "profile": None,
                "omitted_lanes": sorted(BOUNDARY_LANES),
                "runtime_behavior_proved": False,
            })

    # --- M75: independently checked qualification-support corpus -----
    qualification_name = manifest.get("tool_qualification")
    if qualification_name is not None and not failures:
        verdict = verify_tool_qualification_evidence(
            root / str(qualification_name),
            Path(__file__).resolve().parent / "qualification_oracle.py")
        if verdict["status"] == "TOOL_QUALIFICATION_EVIDENCE_READY":
            mint(verdict["claim"], "reviewed_golden_vector_corpus_only", None,
                 str(qualification_name), judge=verdict["judge"], evidence=verdict)
            boundaries.append({
                "claim": "DO330_EXTERNAL_QUALIFICATION_PENDING",
                "scope": "context_specific_external_authority_review",
                "status": "judge_pending", "profile": None,
                "judge_pending": "independent_qualification_authority",
                "do330_qualified": False,
                "general_transformation_correctness_proved": False,
            })
        else:
            fail({"claim": "TOOL_QUALIFICATION_EVIDENCE_READY",
                  "source": str(qualification_name), "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    # --- M70: complete traceability, explicitly not certification ----
    certification_name = manifest.get("certification_traceability")
    if certification_name is not None and not failures:
        verdict = verify_certification_traceability(
            root / str(certification_name), profile_check["deployment"],
            claims, boundaries)
        if verdict["status"] == "CERTIFICATION_TRACEABILITY_COMPLETE":
            mint(verdict["claim"], "requirements_to_evidence_bundle", None,
                 str(certification_name), evidence=verdict)
        elif verdict["status"] == "CERTIFICATION_TRACEABILITY_PENDING":
            pending("CERTIFICATION_TRACEABILITY_COMPLETE",
                    "requirements_to_evidence_bundle", None,
                    str(certification_name), "missing_evidence")
        else:
            fail({"claim": "CERTIFICATION_TRACEABILITY_COMPLETE",
                  "source": str(certification_name), "code": verdict.get("code"),
                  "message": verdict.get("message", "")})

    if failures:
        return {"status": "KERNEL_VERIFICATION_FAILED", "claim": "NO_PROOF",
                "code": failures[0].get("code"), "failures": failures,
                "claims": claims, "boundaries": boundaries}
    return {"status": "KERNEL_EVIDENCE_BUNDLE",
            "claim": "KERNEL_EVIDENCE_BUNDLE",
            "deployment": manifest["deployment"],
            "manifest": manifest_name,
            "profiles": [name for name, _ in loaded], "claims": claims,
            "boundaries": boundaries,
            "note": profile_check["note"]}
