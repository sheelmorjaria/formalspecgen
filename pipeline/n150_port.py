# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M69 static Intel N150 x86_64 layout and VT-d correspondence gate."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _fail(code: str, message: str = "") -> dict:
    return {"status": "N150_PORT_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def _overlaps(left: list[int], right: list[int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def verify_n150_port(artifact_path: str | Path, profile: dict) -> dict:
    """Bind the x86 layout and VT-d table to the reviewed N150 profile."""
    path = Path(artifact_path)
    try:
        raw = path.read_bytes()
        artifact = json.loads(raw)
        linker = (path.parent / artifact["linker_script"]).resolve()
        linker_bytes = linker.read_bytes()
        devices = artifact["vtd"]["devices"]
        protected = artifact["vtd"]["protected_ranges"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _fail("N150_PORT_ARTIFACT_INVALID", str(exc))
    if profile.get("target") != "n150" or profile.get("memory_model") != "x86_tso":
        return _fail("N150_PROFILE_MISMATCH")
    linker_text = linker_bytes.decode("utf-8", errors="strict")
    linker_hash = hashlib.sha256(linker_bytes).hexdigest()
    if artifact.get("linker_sha256") != linker_hash:
        return _fail("N150_LINKER_HASH_MISMATCH")
    if not all(token in linker_text for token in
               ("ENTRY(_start)", "0x00100000", "0x00200000", "ALIGN(4096)")):
        return _fail("N150_LINKER_LAYOUT_MISMATCH")
    kernel_pool = profile.get("memory_map", {}).get("kernel_pools", {}).get(
        "kstack_pool")
    if protected != {"kstack_pool": kernel_pool}:
        return _fail("N150_VTD_PROTECTED_RANGE_MISMATCH")
    contracts = profile.get("dma_contracts")
    if not isinstance(contracts, dict) or set(devices) != set(contracts):
        return _fail("N150_VTD_DEVICE_SET_MISMATCH")
    requester_ids: set[str] = set()
    for name, contract in contracts.items():
        device = devices.get(name)
        if not isinstance(device, dict) or device.get("allowed_dma") != contract:
            return _fail("N150_VTD_DMA_CONTRACT_MISMATCH", name)
        requester = device.get("requester_id")
        if not isinstance(requester, str) or not requester or requester in requester_ids:
            return _fail("N150_VTD_REQUESTER_ID_INVALID", name)
        requester_ids.add(requester)
        if _overlaps(contract, kernel_pool):
            return _fail("N150_VTD_DMA_OVERLAPS_KERNEL", name)
    tests = artifact.get("physical_tests")
    if tests != {"boot_observed": None, "vtd_fault_observed": None,
                 "tso_litmus_on_silicon_observed": None}:
        return _fail("N150_PHYSICAL_PROTOCOL_INVALID")
    return {
        "status": "N150_PLATFORM_CONFIGURATION_PROVED",
        "claim": "N150_PLATFORM_CONFIGURATION_PROVED",
        "judge": "deterministic_gate",
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "linker_sha256": linker_hash,
        "requester_ids": sorted(requester_ids),
        "memory_model": "x86_tso",
        "physical_boot_proved": False,
        "physical_vtd_proved": False,
        "physical_tso_conformance_proved": False,
        "judge_pending": "physical_intel_n150",
    }
