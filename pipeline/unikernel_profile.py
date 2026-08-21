# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M66 feature-gated, single-EL1 unikernel build judge."""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path


def _fail(code: str, message: str = "") -> dict:
    return {"status": "UNIKERNEL_BUILD_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def verify_unikernel_build(manifest_path: str | Path) -> dict:
    """Build the exact no-std crate with its mandatory unikernel feature."""
    cargo_manifest = Path(manifest_path).resolve()
    source = cargo_manifest.parent / "src" / "lib.rs"
    try:
        manifest_bytes = cargo_manifest.read_bytes()
        source_bytes = source.read_bytes()
    except OSError as exc:
        return _fail("UNIKERNEL_SOURCE_MISSING", str(exc))
    manifest_text = manifest_bytes.decode("utf-8", errors="strict")
    source_text = source_bytes.decode("utf-8", errors="strict")
    required = (
        'unikernel = []' in manifest_text,
        '#![no_std]' in source_text,
        'cfg(not(feature = "unikernel"))' in source_text,
        "EXECUTION_LEVEL: u8 = 1" in source_text,
    )
    if not all(required):
        return _fail("UNIKERNEL_PROFILE_CONTRACT_MISMATCH")
    cargo = shutil.which("cargo")
    if cargo is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "cargo_unavailable", "judge_pending": "cargo"}
    with tempfile.TemporaryDirectory(prefix="formalkernel-unikernel-") as target:
        try:
            run = subprocess.run(
                [cargo, "build", "--manifest-path", str(cargo_manifest),
                 "--features", "unikernel", "--target-dir", target],
                capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return _fail("UNIKERNEL_BUILD_EXECUTION_FAILED", str(exc))
    if run.returncode != 0:
        return _fail("UNIKERNEL_CARGO_BUILD_FAILED", run.stderr)
    return {
        "status": "UNIKERNEL_BUILD_PROVED",
        "claim": "UNIKERNEL_BUILD_PROVED",
        "judge": "cargo",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "feature": "unikernel",
        "execution_level": "EL1",
        "mmu_present": False,
        "syscalls_present": False,
        "ipc_present": False,
        "runtime_behavior_proved": False,
        "bootable_image_proved": False,
    }
