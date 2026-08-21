# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M71.5 shared-hardware interference inventory gate."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


CHANNELS = {"cache", "memory_bandwidth", "interconnect", "dma",
            "interrupts", "smt"}
_STATUSES = {"bounded_by_architecture", "measurement_pending",
             "fault_injection_pending", "not_applicable",
             "firmware_validation_pending"}


def _fail(code: str, message: str = "") -> dict:
    return {"status": "MULTICORE_INTERFERENCE_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def enumerate_interference_channels(path: str | Path,
                                    profiles: list[dict]) -> dict:
    """Require every target to classify every reviewed interference channel."""
    artifact_path = Path(path)
    try:
        raw = artifact_path.read_bytes()
        artifact = json.loads(raw)
        targets = artifact["targets"]
        schema = artifact["validated_measurement_schema"]["required"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _fail("INTERFERENCE_ARTIFACT_INVALID", str(exc))
    profile_targets = {profile.get("target") for profile in profiles}
    if set(targets) != profile_targets or None in profile_targets:
        return _fail("INTERFERENCE_TARGET_SET_MISMATCH")
    required_measurement = {"target_serial", "workload_sha256",
                            "raw_samples_sha256", "max_inflation_ppm",
                            "reviewer_signature"}
    if set(schema) != required_measurement:
        return _fail("INTERFERENCE_MEASUREMENT_SCHEMA_INVALID")
    rows = []
    for target in sorted(targets):
        target_data = targets[target]
        channels = target_data.get("channels")
        if not isinstance(target_data.get("core_count"), int) \
                or target_data["core_count"] < 2:
            return _fail("INTERFERENCE_CORE_COUNT_INVALID", target)
        if not isinstance(channels, dict) or set(channels) != CHANNELS:
            return _fail("INTERFERENCE_CHANNEL_SET_INCOMPLETE", target)
        for channel, disposition in channels.items():
            if not isinstance(disposition, dict) \
                    or not isinstance(disposition.get("control"), str) \
                    or disposition.get("status") not in _STATUSES:
                return _fail("INTERFERENCE_DISPOSITION_INVALID",
                             f"{target}:{channel}")
            rows.append({"target": target, "channel": channel,
                         "control": disposition["control"],
                         "status": disposition["status"]})
        if target_data.get("wcet_interference_measurement") is not None:
            return _fail("UNAUTHENTICATED_INTERFERENCE_MEASUREMENT",
                         "physical results require the independent evidence-ingestion lane")
    return {
        "status": "MULTICORE_INTERFERENCE_CHANNELS_ENUMERATED",
        "claim": "MULTICORE_INTERFERENCE_CHANNELS_ENUMERATED",
        "judge": "deterministic_gate",
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "targets": sorted(targets), "rows": rows,
        "channel_count": len(rows),
        "target_wcet_interference_bound_validated": False,
        "physical_multicore_timing_proved": False,
        "judge_pending": "authenticated_target_interference_measurements",
    }
