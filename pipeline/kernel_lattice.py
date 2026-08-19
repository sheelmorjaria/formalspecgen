# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M43: the multi-architecture kernel evidence lattice.

One kernel, many architecture profiles. The architecture-agnostic claims
(lock-free linearizability over the C witness) are judged ONCE; the
physical claims (barrier correspondence, WCET, DMA isolation) run PER
PROFILE and mint scope-tagged entries — ``BARRIER_CORRESPONDENCE_PROVED
scope x86_tso`` and ``scope armv8_sc`` come from the same sources under
two human-owned profiles.

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
from .lockfree import verify_lockfree
from .realtime import wcet_bound
from .weak_memory import MEMORY_MODELS, barrier_correspondence


def _refuse(code: str, message: str) -> dict:
    return {"status": "KERNEL_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_kernel(kernel_dir: str | Path,
                  profiles: list[str | Path]) -> dict:
    """Run the M36–M39 gates over one kernel manifest, per profile."""
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
             judge: str = "deterministic_gate") -> None:
        key = (claim, scope)
        if key in seen:
            return
        seen.add(key)
        claims.append({"claim": claim, "scope": scope, "profile": profile,
                       "source": source, "judge": judge})

    def pending(claim: str, scope: str, profile: str | None, source: str,
                judge: str) -> None:
        """Record an absent judge — the claim is named but never minted."""
        key = (claim, scope, "pending")
        if key in seen:
            return
        seen.add(key)
        claims.append({"claim": claim, "scope": scope, "profile": profile,
                       "source": source, "status": "judge_pending",
                       "judge_pending": judge})

    def fail(entry: dict) -> None:
        failures.append(entry)

    # --- architecture-agnostic: the lock-free witness, judged once ------
    for name in manifest.get("lockfree", []):
        verdict = verify_lockfree(root / name)
        if verdict["status"] == "LOCK_FREE_LINEARIZABILITY_PROVED":
            mint("LOCK_FREE_LINEARIZABILITY_PROVED",
                 "concurrent_interleaving_bmc", None, name, judge="esbmc")
        elif verdict.get("code") == "esbmc_unavailable":
            pending("LOCK_FREE_LINEARIZABILITY_PROVED",
                    "concurrent_interleaving_bmc", None, name, "esbmc")
        else:
            fail({"claim": "LOCK_FREE_LINEARIZABILITY_PROVED",
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
        memory_model = profile.get("memory_model")
        for name in manifest.get("weak_memory", []):
            if not memory_model:
                return _refuse(
                    "profile_field_missing",
                    f"profile {target} declares no memory_model — the "
                    "weak-memory scope is a human declaration")
            if memory_model not in MEMORY_MODELS:
                return _refuse("profile_field_missing",
                               f"profile {target}: unknown memory_model "
                               f"{memory_model!r}")
            verdict = barrier_correspondence(root / name, memory_model)
            if verdict["status"] == "BARRIER_CORRESPONDENCE_PROVED":
                mint("BARRIER_CORRESPONDENCE_PROVED", memory_model,
                     target, name)
                pending("WEAK_MEMORY_SAFETY_PROVED", memory_model,
                        target, name,
                        verdict.get("judge_pending", "herd7_or_rc11"))
            else:
                fail({"claim": "BARRIER_CORRESPONDENCE_PROVED",
                      "profile": target, "source": name,
                      "code": verdict.get("code"),
                      "message": verdict.get("message", "")})

        profile_timing = profile.get("timing", {})
        for name, file_timing in manifest.get("wcet", {}).items():
            timing = {**profile_timing, **(file_timing or {})}
            if "max_cycles" not in timing:
                return _refuse("profile_field_missing",
                               f"profile {target} declares no "
                               "timing.max_cycles — a deadline is a human "
                               "declaration")
            if profile.get("cost_model"):
                timing["cost_model"] = {**(timing.get("cost_model") or {}),
                                        **profile["cost_model"]}
            verdict = wcet_bound(root / name, timing)
            if verdict["status"] == "WCET_BOUND_PROVEN":
                mint("WCET_BOUND_PROVEN",
                     f"static_cfg_cost_model_{target}", target, name)
            else:
                fail({"claim": "WCET_BOUND_PROVEN", "profile": target,
                      "source": name, "code": verdict.get("code"),
                      "message": verdict.get("message", "")})

        memory_map = profile.get("memory_map") or manifest.get("memory_map")
        contracts = (profile.get("dma_contracts")
                     or manifest.get("dma_contracts"))
        for name in manifest.get("dma", []):
            if not memory_map or not contracts:
                return _refuse("profile_field_missing",
                               f"profile {target} declares no "
                               "memory_map/dma_contracts — the IOMMU "
                               "correspondence needs the physical map")
            verdict = dma_isolation(root / name, memory_map, contracts)
            if verdict["status"] == "DMA_ISOLATION_PROVED":
                mint("DMA_ISOLATION_PROVED",
                     f"deterministic_range_disjointness_{target}",
                     target, name)
            else:
                fail({"claim": "DMA_ISOLATION_PROVED", "profile": target,
                      "source": name, "code": verdict.get("code"),
                      "message": verdict.get("message", "")})

    if failures:
        return {"status": "KERNEL_VERIFICATION_FAILED", "claim": "NO_PROOF",
                "code": failures[0].get("code"), "failures": failures,
                "claims": claims}
    return {"status": "KERNEL_EVIDENCE_BUNDLE",
            "claim": "KERNEL_EVIDENCE_BUNDLE",
            "profiles": [name for name, _ in loaded], "claims": claims}
