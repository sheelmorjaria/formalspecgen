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
from pathlib import Path

from .dma_isolation import dma_isolation
from .ipc_nameserver import verify_ipc_table
from .kernel_composition import verify_composition
from .lockfree import verify_lockfree, verify_mpsc
from .mmu_isolation import verify_spatial_isolation
from .realtime import wcet_bound
from .syscall_boundary import verify_syscall_boundary
from .weak_memory import MEMORY_MODELS, barrier_correspondence


def _refuse(code: str, message: str) -> dict:
    return {"status": "KERNEL_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_kernel(kernel_dir: str | Path,
                  profiles: list[str | Path]) -> dict:
    """Run the M36–M39 lanes per subsystem, per profile, plus the M46
    composition gate when the manifest declares one."""
    root = Path(kernel_dir)
    if not root.is_dir():
        return _refuse("kernel_dir_missing", str(root))
    manifest_path = root / "kernel.json"
    if not manifest_path.is_file():
        return _refuse("kernel_manifest_missing",
                       "kernel.json declares the lanes (weak_memory, "
                       "lockfree, wcet, dma) — the lattice never guesses "
                       "which sources carry which obligations")
    try:
        manifest = _load_json(manifest_path)
    except (OSError, ValueError) as exc:
        return _refuse("kernel_manifest_invalid", str(exc))
    if not profiles:
        return _refuse("profiles_missing",
                       "at least one human-owned hardware profile is "
                       "required — physical scopes are never guessed")

    claims: list[dict] = []
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

    if failures:
        return {"status": "KERNEL_VERIFICATION_FAILED", "claim": "NO_PROOF",
                "code": failures[0].get("code"), "failures": failures,
                "claims": claims}
    return {"status": "KERNEL_EVIDENCE_BUNDLE",
            "claim": "KERNEL_EVIDENCE_BUNDLE",
            "profiles": [name for name, _ in loaded], "claims": claims}
