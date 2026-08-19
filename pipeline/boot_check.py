# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M47: the boot capstone's runtime-evidence lane.

A QEMU transcript is RUNTIME EVIDENCE, never proof — this lane's claim
ceiling is RUNTIME_SAMPLE, strictly below the deductive lanes. What it
judges deterministically from the transcript:

1. BOOT ORDER: the executed order (BOOT <step> lines, printed before
   each step runs) must equal the M46-proven order compiled into the
   image from composition.json. A mismatch means the image and the
   proven artifact have diverged.
2. RING BOUNDS: every reported high_water must be <= cap — the
   capacity invariant, empirically observed (it was PROVED for the
   witness by ESBMC; here we watch it hold on emulated silicon).
3. BACKPRESSURE OBSERVED: the net ring under burst must show
   dropped > 0 — the ERR_MEM path (drop, never overflow) actually
   executed. A flood with zero drops would mean the test never
   saturated the ring (vacuous evidence) and is refused.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

QEMU_BIN = shutil.which("qemu-system-aarch64")
_RUSTC = shutil.which("rustc")
RUSTC_BIN = _RUSTC if _RUSTC else (str(Path.home() / ".cargo/bin/rustc")
                                   if (Path.home() / ".cargo/bin/rustc").exists()
                                   else None)
_LLD_GLOB = ".rustup/toolchains/stable-*/lib/rustlib/" \
            "x86_64-unknown-linux-gnu/bin/rust-lld"


def _fail(code: str, message: str, **extra) -> dict:
    return {"status": "BOOT_RUNTIME_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message, **extra}


def parse_transcript(transcript: str, composition: dict) -> dict:
    """Judge a UART transcript against the proven boot artifact."""
    executed = re.findall(r"^BOOT (\S+)", transcript, re.M)
    proven = [str(step["name"]) for step in composition.get("steps", [])]
    if not executed:
        return _fail("no_boot_output",
                     "transcript contains no BOOT lines — the image "
                     "produced no evidence")
    if executed != proven:
        return _fail("boot_order_mismatch",
                     f"executed {executed} but the proven composition "
                     f"order is {proven} — image and artifact diverged")

    rings = {}
    for match in re.finditer(
            r"^(NET|SCHED) posted=(\d+) dropped=(\d+) consumed=(\d+)"
            r"(?: picked=(\d+))? high_water=(\d+) cap=(\d+)",
            transcript, re.M):
        ring = match.group(1)
        rings[ring] = {
            "posted": int(match.group(2)),
            "dropped": int(match.group(3)),
            "consumed": int(match.group(4) or 0),
            "picked": int(match.group(5) or 0),
            "high_water": int(match.group(6)),
            "cap": int(match.group(7)),
        }
    if "NET" not in rings:
        return _fail("no_ring_evidence",
                     "transcript has no NET ring counters — the flood "
                     "evidence is missing")
    for name, ring in rings.items():
        if ring["high_water"] > ring["cap"]:
            return _fail("RING_BOUND_EXCEEDED",
                         f"{name} high_water {ring['high_water']} > cap "
                         f"{ring['cap']} — the capacity invariant FAILED "
                         "at runtime; the deductive claim is contradicted")
    if rings["NET"]["dropped"] == 0:
        return _fail("backpressure_not_exercised",
                     "the net ring flooded with zero drops — the burst "
                     "never saturated CAP, so the ERR_MEM path was not "
                     "exercised (vacuous evidence)")
    if "PANIC" in transcript:
        return _fail("kernel_panicked", "the image hit its panic handler")
    if "MMU_ON" in transcript:
        # M48: the image enabled the MMU — the isolation trap must
        # follow, or the runtime evidence is incomplete (named, never
        # silently dropped)
        fault = re.search(r"FAULT far=(0x[0-9a-f]+)", transcript)
        if not fault:
            return _fail("mmu_trap_not_observed",
                         "MMU_ON printed but no FAULT line followed — "
                         "the isolation probe's trap was not observed; "
                         "the runtime sample is incomplete",
                         rings=rings)
        rings["NET"]["mmu_fault_far"] = fault.group(1)
        rings["NET"]["mmu_trap_observed"] = True
    user_syscall_observed = False
    user_syscall_id = None
    user_fault_far = None
    if "USER_ON" in transcript:
        # M49: the image dropped to EL0 with an unverified user image —
        # BOTH halves of the boundary sample must be present: the
        # syscall answered AND the EL0 kernel-access trapped
        syscall = re.search(r"SYSCALL (0x[0-9a-f]+) \S+ from EL0",
                            transcript)
        if not syscall:
            return _fail("user_syscall_not_observed",
                         "USER_ON printed but no SYSCALL line followed — "
                         "the unverified image never requested service "
                         "through the table; the runtime sample is "
                         "incomplete",
                         rings=rings)
        user_trap = re.search(r"USER_TRAP far=(0x[0-9a-f]+)", transcript)
        if not user_trap:
            return _fail("user_trap_not_observed",
                         "USER_ON printed but no USER_TRAP line followed "
                         "— the EL0 store into kernel memory was not "
                         "observed trapped; the runtime sample is "
                         "incomplete",
                         rings=rings)
        user_syscall_observed = True
        user_syscall_id = syscall.group(1)
        user_fault_far = user_trap.group(1)
    ipc_ring = None
    ipc_syscall_observed = False
    if "IPC_ON" in transcript:
        # M50: the MPSC endpoint's runtime sample — BOTH producers must
        # be visible (the user's syscall AND the counters with the
        # bound held and every arrival accounted)
        ipc = re.search(
            r"IPC lanes=(\d+) posted=(\d+) dropped=(\d+) "
            r"consumed=(\d+) high_water=(\d+) cap=(\d+)", transcript)
        if not ipc:
            return _fail("ipc_not_observed",
                         "IPC_ON printed but no IPC counters followed — "
                         "the MPSC runtime sample is incomplete",
                         rings=rings)
        if "SYSCALL 0x65 ipc_send from EL0" not in transcript:
            return _fail("ipc_syscall_not_observed",
                         "IPC_ON printed but the user process never sent "
                         "through the endpoint — the sample would show "
                         "the kernel producer only (one-sided evidence)",
                         rings=rings)
        ipc_syscall_observed = True
        ipc_ring = {"lanes": int(ipc.group(1)),
                    "posted": int(ipc.group(2)),
                    "dropped": int(ipc.group(3)),
                    "consumed": int(ipc.group(4)),
                    "high_water": int(ipc.group(5)),
                    "cap": int(ipc.group(6))}
        if ipc_ring["high_water"] > ipc_ring["cap"]:
            return _fail(
                "IPC_BOUND_EXCEEDED",
                f"IPC high_water {ipc_ring['high_water']} > cap "
                f"{ipc_ring['cap']} — the ESBMC-proved partition bound "
                "FAILED at runtime; the deductive claim is contradicted",
                rings=rings)
    return {
        "status": "BOOT_RUNTIME_CONFIRMED",
        # runtime evidence, honestly ceilinged BELOW the proof lanes:
        "claim": "BOOT_ORDER_AND_BOUNDS_RUNTIME_SAMPLE",
        "claim_ceiling": "RUNTIME_SAMPLE",
        "scope": "qemu_virt_aarch64_uart_transcript",
        "judge": "deterministic_transcript_parser",
        "boot_order_confirmed": proven,
        "rings": rings,
        "mmu_trap_observed": rings["NET"].pop("mmu_trap_observed", False),
        "user_syscall_observed": user_syscall_observed,
        "user_syscall_id": user_syscall_id,
        "user_fault_far": user_fault_far,
        "ipc": ipc_ring,
        "ipc_syscall_observed": ipc_syscall_observed,
        "note": "runtime observation of the M46-proven boot order and "
                "the ESBMC-proved capacity bound — evidence, NOT an "
                "additional proof; LOCK_FREE_LINEARIZABILITY_PROVED and "
                "SYSTEM_COMPOSITION_PROVED remain the deductive claims",
    }


def build_boot_image(boot_dir: str | Path) -> dict:
    """Compile the no_std image for QEMU virt (rustc + rust-lld)."""
    boot = Path(boot_dir)
    lld = sorted(Path.home().glob(_LLD_GLOB))
    if not RUSTC_BIN or not lld:
        return _fail("toolchain_unavailable",
                     "boot build needs rustc and rust-lld (rustup "
                     "toolchain) — the image cannot be compiled here")
    try:
        run = subprocess.run(
            [RUSTC_BIN, "--edition", "2021",
             "--target", "aarch64-unknown-none-softfloat",
             "--crate-type", "bin", f"-Clinker={lld[0]}",
             f"-Clink-arg=-T{boot / 'layout.ld'}", "-Cpanic=abort",
             "-Copt-level=0", "-o", str(boot / "formalkernel.elf"),
             str(boot / "src/main.rs")],
            capture_output=True, text=True, timeout=180)
    except (subprocess.TimeoutExpired, TimeoutError, OSError):
        return _fail("rustc_timeout", "image build did not finish")
    if run.returncode != 0:
        return _fail("rustc_failed", run.stderr[-300:])
    return {"status": "IMAGE_BUILT", "elf": str(boot / "formalkernel.elf")}


def run_qemu_boot(elf: str | Path, timeout_seconds: int = 15) -> dict:
    """Boot the image on QEMU virt and return the transcript verdict."""
    if not QEMU_BIN:
        return _fail("qemu_unavailable",
                     "qemu-system-aarch64 not installed — install with: "
                     "sudo apt-get install -y qemu-system-arm")
    try:
        run = subprocess.run(
            [QEMU_BIN, "-M", "virt", "-cpu", "cortex-a72", "-nographic",
             "-no-reboot", "-kernel", str(elf)],
            capture_output=True, text=True,
            timeout=timeout_seconds, input="")
    except subprocess.TimeoutExpired as exc:
        # the kernel halts in wfe after printing — a timeout with a
        # complete transcript is the EXPECTED exit shape
        transcript = (exc.stdout or "")
        if isinstance(transcript, bytes):
            transcript = transcript.decode("utf-8", "replace")
        return {"transcript": transcript, "timed_out": True}
    except (TimeoutError, OSError) as exc:
        return _fail("qemu_crashed", str(exc))
    return {"transcript": run.stdout or "", "timed_out": False}
