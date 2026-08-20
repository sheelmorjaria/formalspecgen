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

from .deployment_profile import verify_deployment_profile
from .dma_isolation import dma_isolation
from .elf_loader import verify_elf_load
from .ipc_nameserver import verify_ipc_table
from .kani_refinement import verify_rust_refinement
from .kernel_composition import verify_composition
from .lockfree import verify_lockfree, verify_mpsc
from .mmu_isolation import verify_spatial_isolation
from .pq_tls_pool import verify_pq_tls_pool
from .pq_wcet import verify_pq_wcet
from .realtime import wcet_bound
from .syscall_boundary import verify_syscall_boundary
from .tls_handshake import verify_tls_handshake_evidence
from .weak_memory import MEMORY_MODELS, barrier_correspondence


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
    selects the deployment profile (M54): kernel.json (microkernel) or
    monolith.json — one source tree, two honest bundles."""
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
             subsystem: str | None = None) -> None:
        key = (claim, scope, subsystem)
        if key in seen:
            return
        seen.add(key)
        entry = {"claim": claim, "scope": scope, "profile": profile,
                 "source": source, "judge": judge}
        if subsystem is not None:
            entry["subsystem"] = subsystem
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

    loaded: list[tuple[str, dict]] = []
    for profile_path in profiles:
        path = Path(profile_path)
        try:
            loaded.append((path.stem, _load_json(path)))
        except (OSError, ValueError) as exc:
            return _refuse("profile_unreadable", f"{path}: {exc}")

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
                    pending("WEAK_MEMORY_SAFETY_PROVED", memory_model,
                            target, name,
                            verdict.get("judge_pending", "herd7_or_rc11"),
                            subsystem=sub_name)
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
    kani_dir = manifest.get("kani_proofs")
    if kani_dir is not None:
        verdict = verify_rust_refinement(root / str(kani_dir))
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
    elif profile_check["deployment"] == "monolithic":
        boundaries.append({
            "claim": "EL0_PROCESS_LOADER_OMITTED",
            "scope": "single_address_space",
            "status": "boundary", "judge": "none", "profile": None,
            "hardware_exception_level_transition_proved": False,
            "note": "the monolith never loads a separate EL0 process; no loader, UXN/AP, or ERET claim is minted",
        })

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
