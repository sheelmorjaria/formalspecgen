# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M68 R52 SMMU configuration correspondence and physical-test boundary."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _fail(code: str, message: str = "") -> dict:
    return {"status": "R52_SMMU_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def _valid_span(value: object) -> bool:
    return (isinstance(value, list) and len(value) == 2
            and all(isinstance(item, int) and not isinstance(item, bool)
                    for item in value) and value[0] < value[1])


def _overlaps(left: list[int], right: list[int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def verify_r52_smmu(artifact_path: str | Path, profile: dict) -> dict:
    """Prove reviewed SMMU windows correspond to the R52 DMA contracts."""
    path = Path(artifact_path)
    try:
        raw = path.read_bytes()
        artifact = json.loads(raw)
        streams = artifact["streams"]
        protected = artifact["protected_ranges"]
        physical_test = artifact["physical_test"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _fail("R52_SMMU_ARTIFACT_INVALID", str(exc))
    if profile.get("target") != "r52" or artifact.get("target") != "r52":
        return _fail("R52_SMMU_PROFILE_MISMATCH")
    contracts = profile.get("dma_contracts")
    pool = profile.get("memory_map", {}).get("kernel_pools", {}).get("tcm_kernel")
    if protected != {"tcm_kernel": pool} or not _valid_span(pool):
        return _fail("R52_SMMU_PROTECTED_RANGE_MISMATCH")
    if not isinstance(contracts, dict) or set(streams) != set(contracts):
        return _fail("R52_SMMU_STREAM_SET_MISMATCH")
    stream_ids: set[int] = set()
    for device, contract in contracts.items():
        stream = streams.get(device)
        if not isinstance(stream, dict) or stream.get("allowed_dma") != contract:
            return _fail("R52_SMMU_DMA_CONTRACT_MISMATCH", device)
        stream_id = stream.get("stream_id")
        if not isinstance(stream_id, int) or isinstance(stream_id, bool) \
                or stream_id < 0 or stream_id in stream_ids:
            return _fail("R52_SMMU_STREAM_ID_INVALID", device)
        stream_ids.add(stream_id)
        if not _valid_span(contract) or _overlaps(contract, pool):
            return _fail("R52_SMMU_DMA_OVERLAPS_TCM", device)
    if artifact.get("fault_response") != "abort_and_log":
        return _fail("R52_SMMU_FAULT_RESPONSE_INVALID")
    if physical_test != {
            "operation": "device_dma_write_into_tcm_kernel",
            "expected": "translation_fault_no_memory_change",
            "observed": None}:
        return _fail("R52_SMMU_PHYSICAL_PROTOCOL_INVALID")
    return {
        "status": "SMMU_CONFIGURATION_CORRESPONDENCE_PROVED",
        "claim": "SMMU_CONFIGURATION_CORRESPONDENCE_PROVED",
        "judge": "deterministic_gate",
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "stream_ids": sorted(stream_ids),
        "dma_contracts": contracts,
        "protected_ranges": protected,
        "physical_dma_block_proved": False,
        "external_io_safety_proved": False,
        "judge_pending": "physical_r52_smmu_fault_injection",
    }
