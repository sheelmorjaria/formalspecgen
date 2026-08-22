# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M91.1 fail-closed RISC-V platform and trust-root feasibility scan."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .proof_carrying_binary import _resolve_tool


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _tool(name: str, version_args: list[str]) -> dict[str, Any]:
    resolved_path = _resolve_tool(name) if name in {"rustc", "rust-lld"} else None
    resolved = str(resolved_path) if resolved_path else shutil.which(name)
    if not resolved:
        return {"name": name, "status": "ABSENT", "path": None,
                "sha256": None, "version": None}
    path = Path(resolved)
    try:
        run = subprocess.run([resolved, *version_args], capture_output=True,
                             text=True, timeout=10, check=False)
        version = (run.stdout or run.stderr).strip().splitlines()[0]
    except (OSError, subprocess.TimeoutExpired, IndexError):
        version = None
    return {"name": name, "status": "READY", "path": str(path),
            "sha256": _sha(path.read_bytes()), "version": version}


def _rust_target(target: str) -> dict[str, Any]:
    rustup = shutil.which("rustup")
    if not rustup:
        return {"target": target, "status": "RUSTUP_ABSENT"}
    run = subprocess.run([rustup, "target", "list", "--installed"],
                         capture_output=True, text=True, timeout=10, check=False)
    installed = target in run.stdout.splitlines()
    return {"target": target,
            "status": "INSTALLED" if installed else "TARGET_STANDARD_LIBRARY_ABSENT"}


def _qemu_machine_probe(qemu: dict[str, Any], machine: str) -> dict[str, Any]:
    if qemu["status"] != "READY":
        return {"machine": machine, "status": "QEMU_RISCV64_ABSENT",
                "aia": "UNPROBED", "h_extension": "UNPROBED",
                "iommu": "UNPROBED"}
    machines = subprocess.run([qemu["path"], "-machine", "help"], capture_output=True,
                              text=True, timeout=10, check=False)
    options = subprocess.run([qemu["path"], "-machine", f"{machine},help"],
                             capture_output=True, text=True, timeout=10, check=False)
    devices = subprocess.run([qemu["path"], "-device", "help"], capture_output=True,
                             text=True, timeout=10, check=False)
    with tempfile.TemporaryDirectory(prefix="m91-qemu-probe-", dir="/tmp") as directory:
        dtb = Path(directory) / "virt.dtb"
        probe = subprocess.run(
            [qemu["path"], "-machine", f"{machine},dumpdtb={dtb}",
             "-cpu", "rv64", "-display", "none", "-serial", "none"],
            capture_output=True, timeout=10, check=False)
        raw_dtb = dtb.read_bytes() if probe.returncode == 0 and dtb.is_file() else b""
    return {
        "machine": machine,
        "status": "AVAILABLE" if machine in machines.stdout else "MACHINE_ABSENT",
        "aclint": "AVAILABLE_CONFIGURABLE" if "aclint=<bool>" in options.stdout else "UNAVAILABLE",
        "aia": ("AVAILABLE_APLIC_IMSIC_CONFIGURABLE"
                if "aplic-imsic" in options.stdout else "UNAVAILABLE"),
        "h_extension": ("AVAILABLE_IN_RV64_CPU_MODEL"
                        if b"rv64imafdch_" in raw_dtb else "UNAVAILABLE_OR_UNCONFIRMED"),
        "iommu": ("RISCV_IOMMU_DEVICE_AVAILABLE" if "riscv-iommu" in devices.stdout
                  else "RISCV_IOMMU_DEVICE_ABSENT"),
    }


def _validate_profile(profile: dict[str, Any]) -> list[str]:
    failures = []
    if profile.get("schema_version") != 1 or profile.get("status") != \
            "HUMAN_REVIEW_PENDING":
        failures.append("profile_schema")
    if profile.get("isa") != "RV64GC" or profile.get("page_table_mode") != "Sv39":
        failures.append("isa_or_page_table_mode")
    if profile.get("privilege_modes") != ["M", "S", "U"]:
        failures.append("privilege_modes")
    regions = profile.get("memory_map", {})
    intervals = []
    for name, region in regions.items():
        start, size = region.get("base"), region.get("size")
        if not isinstance(start, int) or not isinstance(size, int) or size <= 0:
            failures.append(f"memory_map:{name}")
            continue
        intervals.append((start, start + size, name))
    for index, left in enumerate(intervals):
        for right in intervals[index + 1:]:
            if max(left[0], right[0]) < min(left[1], right[1]):
                failures.append(f"memory_overlap:{left[2]}:{right[2]}")
    specs = profile.get("normative_specifications", [])
    if not specs or any(not item.get("official_url") or not item.get("release")
                        for item in specs):
        failures.append("normative_spec_identity")
    if any(item.get("content_sha256") is not None for item in specs):
        failures.append("unvendored_spec_hash_overclaim")
    return sorted(failures)


def inspect_riscv_feasibility(project_root: str | Path,
                              profile_path: str | Path) -> dict[str, Any]:
    """Inspect exact local support without minting an architecture claim."""
    root = Path(project_root).resolve()
    path = Path(profile_path).resolve()
    try:
        profile = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "RISCV_FEASIBILITY_INPUT_INVALID", "claim": "NO_PROOF",
                "message": str(exc)}
    failures = _validate_profile(profile)
    if failures:
        return {"status": "RISCV_PROFILE_CANDIDATE_INVALID", "claim": "NO_PROOF",
                "failures": failures}
    qemu = _tool("qemu-system-riscv64", ["--version"])
    rustc = _tool("rustc", ["--version"])
    rust_lld = _tool("rust-lld", ["-flavor", "gnu", "--version"])
    cross_gcc = _tool("riscv64-linux-gnu-gcc", ["--version"])
    objdump = _tool("riscv64-linux-gnu-objdump", ["--version"])
    target = _rust_target(profile["rust_target"])
    machine = _qemu_machine_probe(qemu, profile["qemu_machine"])
    blockers = []
    if target["status"] != "INSTALLED":
        blockers.append("riscv64_rust_target_standard_library")
    if qemu["status"] != "READY":
        blockers.append("qemu_system_riscv64")
    if rust_lld["status"] != "READY":
        blockers.append("rust_lld")
    if objdump["status"] != "READY":
        blockers.append("riscv64_disassembler")
    return {
        "status": "RISCV_PLATFORM_FEASIBILITY_RECORDED",
        "claim": "NO_PROOF", "lane": "M91.1_riscv_platform_feasibility",
        "profile_candidate": {
            "path": path.relative_to(root).as_posix(),
            "sha256": _sha(path.read_bytes()), "review_status": "HUMAN_REVIEW_PENDING"},
        "toolchain": {"rustc": rustc, "rust_lld": rust_lld,
                      "cross_gcc": cross_gcc, "objdump": objdump,
                      "rust_target": target},
        "emulator": {"qemu": qemu, "machine_probe": machine},
        "normative_trust_roots": profile["normative_specifications"],
        "blockers": sorted(blockers),
        "claims_locked": [
            "RISCV_PRIVILEGE_TRANSITION_MODEL_PROVED",
            "RISCV_SPATIAL_ISOLATION_PROVED", "RISCV_INTERRUPT_ROUTING_PROVED",
            "RISCV_IOMMU_CONFIGURATION_PROVED", "PROOF_CARRYING_BINARY_VALIDATED"],
        "boundaries": [
            "normative documents are release/URL pinned but not content-hash bound until vendored",
            "QEMU and physical hardware behavior are unproved",
            "QEMU exposes configurable AIA/APLIC/IMSIC and an rv64 H-extension CPU model",
            "QEMU 8.2.2 does not expose a RISC-V IOMMU architecture device",
            "the candidate memory map is human-owned and not yet reviewed",
        ],
    }
