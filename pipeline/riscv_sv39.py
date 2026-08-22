# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M91.3 exact Sv39 descriptor and deterministic software-walk gate."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .riscv_privilege_transition import verify_riscv_privilege_evidence

CLAIM = "RISCV_SPATIAL_ISOLATION_PROVED"
SCOPE = "reviewed_qemu_virt_sv39_descriptor_and_walk_model"
PAGE_SIZE = 4096
MASK64 = (1 << 64) - 1


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fail(code: str, message: str = "") -> dict[str, Any]:
    return {"status": "RISCV_SV39_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def _load_bound(root: Path, binding: Any, code: str) -> tuple[dict, str]:
    if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
        raise ValueError(f"{code}_BINDING_INVALID")
    path = (root / binding["path"]).resolve()
    if root.resolve() not in path.parents or not path.is_file():
        raise ValueError(f"{code}_PATH_INVALID")
    digest = _sha(path.read_bytes())
    if digest != binding["sha256"]:
        raise ValueError(f"{code}_HASH_MISMATCH")
    return json.loads(path.read_text(encoding="utf-8")), digest


def _canonical(va: int) -> bool:
    if not isinstance(va, int) or va < 0 or va > MASK64:
        return False
    high = va >> 39
    return high == ((1 << 25) - 1 if (va >> 38) & 1 else 0)


def _pte_value(ppn: int, flags: dict[str, bool]) -> int:
    bits = {"V": 0, "R": 1, "W": 2, "X": 3, "U": 4, "G": 5, "A": 6, "D": 7}
    return (ppn << 10) | sum((1 << bit) for name, bit in bits.items()
                             if flags.get(name, False))


def _walk(plan: dict, va: int) -> dict[str, Any] | None:
    if not _canonical(va):
        return None
    tables = {int(table["ppn"]): table for table in plan["tables"]}
    ppn = int(plan["root_ppn"])
    for level in (2, 1, 0):
        table = tables.get(ppn)
        if table is None or int(table.get("level", -1)) != level:
            return None
        index = (va >> (12 + 9 * level)) & 0x1FF
        entries = {int(entry["index"]): entry for entry in table.get("entries", [])}
        entry = entries.get(index)
        if entry is None or not entry.get("flags", {}).get("V", False):
            return None
        if int(entry.get("encoded", -1)) != _pte_value(int(entry["ppn"]), entry["flags"]):
            return None
        leaf = entry["flags"].get("R", False) or entry["flags"].get("X", False)
        if leaf:
            if entry["flags"].get("W", False) and not entry["flags"].get("R", False):
                return None
            page_bits = 12 + 9 * level
            return {"pa": (int(entry["ppn"]) << 12) | (va & ((1 << page_bits) - 1)),
                    "flags": entry["flags"], "level": level}
        if entry["flags"].get("W", False) or entry["flags"].get("U", False):
            return None
        ppn = int(entry["ppn"])
    return None


def verify_sv39_isolation(artifact: dict[str, Any], root: str | Path) -> dict[str, Any]:
    root_path = Path(root).resolve()
    try:
        profile, profile_hash = _load_bound(root_path, artifact.get("reviewed_profile"),
                                            "RISCV_PROFILE")
        transition_artifact, _ = _load_bound(root_path, artifact.get("transition_artifact"),
                                             "RISCV_TRANSITION_ARTIFACT")
        transition_evidence, transition_hash = _load_bound(
            root_path, artifact.get("transition_evidence"), "RISCV_TRANSITION_EVIDENCE")
        plan, plan_hash = _load_bound(root_path, artifact.get("mapping_plan"),
                                     "RISCV_SV39_PLAN")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return _fail(str(exc))
    transition = verify_riscv_privilege_evidence(
        transition_artifact, root_path, transition_evidence)
    if transition.get("status") != "RISCV_PRIVILEGE_TRANSITION_EVIDENCE_BOUND":
        return _fail("RISCV_TRANSITION_DEPENDENCY_UNPROVED")
    if (profile.get("status") != "REVIEWED_RISCV_PLATFORM_PROFILE"
            or profile.get("page_table_mode") != "Sv39"):
        return _fail("RISCV_PROFILE_NOT_REVIEWED_SV39")
    try:
        root_ppn = int(plan["root_ppn"])
        if plan.get("status") != "REVIEWED_RISCV_SV39_MAPPING_PLAN":
            return _fail("RISCV_SV39_MAPPING_PLAN_HUMAN_REVIEW_REQUIRED")
        expected_satp = (8 << 60) | root_ppn
        if int(plan["satp"]) != expected_satp:
            return _fail("RISCV_SATP_ROOT_MISMATCH")
        dram = profile["memory_map"]["dram"]
        dram_start, dram_end = int(dram["base"]), int(dram["base"]) + int(dram["size"])
        for table in plan["tables"]:
            pa = int(table["ppn"]) << 12
            if pa < dram_start or pa + PAGE_SIZE > dram_end:
                return _fail("RISCV_PAGE_TABLE_OUTSIDE_REVIEWED_DRAM")
        protected = [(int(r["start"]), int(r["end"])) for r in plan["protected_frames"]]
        checked = []
        for mapping in plan["mappings"]:
            va = int(mapping["va"])
            resolved = _walk(plan, va)
            if mapping["class"] == "guard":
                if resolved is not None:
                    return _fail("RISCV_GUARD_REGION_MAPPED")
                checked.append({"class": "guard", "va": va, "resolved": False})
                continue
            if resolved is None:
                return _fail("RISCV_DECLARED_MAPPING_UNRESOLVED")
            expected = mapping["permissions"]
            actual = {key: bool(resolved["flags"].get(key, False)) for key in ("R", "W", "X", "U")}
            if resolved["pa"] != int(mapping["pa"]) or actual != expected:
                return _fail("RISCV_WALK_PLAN_CORRESPONDENCE_FAILED")
            if actual["W"] and actual["X"]:
                return _fail("RISCV_USER_WX_VIOLATION" if actual["U"] else
                             "RISCV_SUPERVISOR_WX_VIOLATION")
            if mapping["class"].startswith("kernel") and actual["U"]:
                return _fail("RISCV_KERNEL_PAGE_USER_ACCESSIBLE")
            if actual["U"] and any(start <= resolved["pa"] < end for start, end in protected):
                return _fail("RISCV_USER_MAPPING_PROTECTED_FRAME")
            checked.append({"class": mapping["class"], "va": va,
                            "pa": resolved["pa"], "permissions": actual})
        for va in plan.get("invalid_virtual_addresses", []):
            if _canonical(int(va)) or _walk(plan, int(va)) is not None:
                return _fail("RISCV_NONCANONICAL_ADDRESS_ACCEPTED")
    except (KeyError, TypeError, ValueError) as exc:
        return _fail("RISCV_SV39_PLAN_INVALID", str(exc))
    return {
        "status": "RISCV_SV39_SPATIAL_ISOLATION_PROVED", "claim": CLAIM,
        "judge": "deterministic_sv39_walker", "scope": SCOPE,
        "reviewed_profile_sha256": profile_hash,
        "mapping_plan_sha256": plan_hash,
        "transition_evidence_sha256": transition_hash,
        "satp": int(plan["satp"]), "root_ppn": root_ppn,
        "mappings_checked": checked,
        "properties": ["EXACT_DESCRIPTOR_ENCODING", "SV39_WALK_CORRESPONDENCE",
                       "SUPERVISOR_USER_SEPARATION", "USER_W_X",
                       "GUARD_UNMAPPED", "NONCANONICAL_REJECTED",
                       "REVIEWED_SATP_ROOT_REQUIRED"],
        "hardware_page_walk_proved": False, "tlb_coherence_proved": False,
        "compiled_mmu_refinement_proved": False,
        "physical_spatial_isolation_proved": False,
    }


def verify_sv39_evidence(artifact: dict[str, Any], root: str | Path,
                         evidence: dict[str, Any]) -> dict[str, Any]:
    current = verify_sv39_isolation(artifact, root)
    stable = {key: value for key, value in current.items() if key not in ()}
    if current.get("claim") != CLAIM or evidence != stable:
        return _fail("RISCV_SV39_EVIDENCE_BINDING_MISMATCH")
    return {"status": "RISCV_SV39_EVIDENCE_BOUND", "claim": CLAIM,
            "scope": SCOPE, "mapping_plan_sha256": current["mapping_plan_sha256"],
            "transition_evidence_sha256": current["transition_evidence_sha256"]}


def write_sv39_evidence(path: str | Path, evidence: dict[str, Any]) -> None:
    if evidence.get("claim") != CLAIM:
        raise ValueError("RISCV_SV39_PUBLICATION_REFUSED")
    Path(path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
