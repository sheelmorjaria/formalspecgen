# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M67 deterministic Cortex-R52 TCM placement gate."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


def _fail(code: str, message: str = "") -> dict:
    return {"status": "R52_PORT_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def verify_r52_tcm_port(artifact_path: str | Path, profile: dict) -> dict:
    """Bind the R52 profile's kernel pool to reviewed ITCM/DTCM regions."""
    path = Path(artifact_path)
    try:
        raw = path.read_bytes()
        artifact = json.loads(raw)
        linker = (path.parent / artifact["linker_script"]).resolve()
        linker_bytes = linker.read_bytes()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _fail("R52_PORT_ARTIFACT_INVALID", str(exc))
    if profile.get("target") != "r52" or profile.get("memory_model") != "armv8_sc":
        return _fail("R52_PROFILE_MISMATCH")
    regions = artifact.get("tcm_regions")
    expected = {"itcm": [0, 16384], "dtcm": [16384, 32768]}
    if regions != expected:
        return _fail("R52_TCM_MAP_MISMATCH")
    pool = profile.get("memory_map", {}).get("kernel_pools", {}).get("tcm_kernel")
    if pool != regions["dtcm"]:
        return _fail("R52_KERNEL_POOL_OUTSIDE_DTCM")
    linker_text = linker_bytes.decode("utf-8", errors="strict")
    required = (
        re.search(r"ITCM\s*\(rx\).*ORIGIN\s*=\s*0x00000000.*LENGTH\s*=\s*16K",
                  linker_text),
        re.search(r"DTCM\s*\(rw\).*ORIGIN\s*=\s*0x00004000.*LENGTH\s*=\s*16K",
                  linker_text),
        "> ITCM" in linker_text,
        "> DTCM" in linker_text,
    )
    if not all(required):
        return _fail("R52_LINKER_TCM_PLACEMENT_MISMATCH")
    linker_hash = hashlib.sha256(linker_bytes).hexdigest()
    if artifact.get("linker_sha256") != linker_hash:
        return _fail("R52_LINKER_HASH_MISMATCH")
    return {
        "status": "R52_TCM_PLACEMENT_PROVED",
        "claim": "R52_TCM_PLACEMENT_PROVED",
        "judge": "deterministic_gate",
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "linker_sha256": linker_hash,
        "itcm_bytes": 16384,
        "dtcm_bytes": 16384,
        "kernel_pool": pool,
        "physical_boot_proved": False,
        "measured_wcet_proved": False,
        "soc_address_conformance_proved": False,
        "judge_pending": "physical_cortex_r52_board",
    }
