# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M47: the boot capstone — transcript judging + image build."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.boot_check import build_boot_image, parse_transcript

BOOT_DIR = Path(__file__).resolve().parent.parent / \
    "examples/formalkernel/boot"
COMPOSITION = json.loads(
    (BOOT_DIR.parent / "kernel/composition.json").read_text())

GOOD = """FormalKernel boot (QEMU virt aarch64)
BOOT timer_init
BOOT pool_init
BOOT scheduler_start
BOOT net_start
FLOOD start
NET posted=7 dropped=9 consumed=7 high_water=4 cap=4
SCHED posted=3 picked=3 dropped=0 high_water=3 cap=4
HALT
"""


def shutil_which(binary):
    import shutil
    return shutil.which(binary)


def _cross_target_ready() -> bool:
    """The aarch64-unknown-none-softfloat CORE LIBRARY must be present
    (rustup target add ...). CI runners have rustc but not the cross
    target's core — the build would fail with "can't find crate for
    `core`" (E0463), which is availability, not a defect."""
    import glob
    import shutil
    import subprocess
    rustc = shutil.which("rustc")
    if not rustc:
        return False
    try:
        libdir = subprocess.run(
            [rustc, "--print", "target-libdir",
             "--target", "aarch64-unknown-none-softfloat"],
            capture_output=True, text=True,
            timeout=30).stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        return False
    return bool(libdir) and bool(glob.glob(libdir + "/libcore-*.rlib"))


def test_good_transcript_confirms_under_the_runtime_ceiling():
    verdict = parse_transcript(GOOD, COMPOSITION)
    assert verdict["status"] == "BOOT_RUNTIME_CONFIRMED"
    # the honest ceiling: runtime evidence is BELOW the proof lanes
    assert verdict["claim_ceiling"] == "RUNTIME_SAMPLE"
    assert verdict["scope"] == "qemu_virt_aarch64_uart_transcript"
    assert verdict["boot_order_confirmed"] == \
        ["timer_init", "pool_init", "scheduler_start", "net_start"]
    assert verdict["rings"]["NET"]["dropped"] == 9
    assert verdict["rings"]["NET"]["high_water"] == 4
    assert "NOT an additional proof" in verdict["note"]


def test_user_space_transcript_judges_under_the_runtime_ceiling():
    """M49: the EL0 drop's evidence is complete only when BOTH halves
    are present — the syscall answered AND the kernel-access trapped."""
    full = GOOD.replace(
        "HALT", "USER_ON el0\n"
                "SYSCALL 0x64 write_console from EL0\n"
                "USER_TRAP far=0x40200000 contained\nHALT")
    verdict = parse_transcript(full, COMPOSITION)
    assert verdict["status"] == "BOOT_RUNTIME_CONFIRMED"
    assert verdict["claim_ceiling"] == "RUNTIME_SAMPLE"
    assert verdict["user_syscall_observed"] is True
    assert verdict["user_syscall_id"] == "0x64"
    assert verdict["user_fault_far"] == "0x40200000"
    no_syscall = full.replace("SYSCALL 0x64 write_console from EL0\n", "")
    assert parse_transcript(no_syscall, COMPOSITION)["code"] == \
        "user_syscall_not_observed"
    no_trap = full.replace("USER_TRAP far=0x40200000 contained\n", "")
    assert parse_transcript(no_trap, COMPOSITION)["code"] == \
        "user_trap_not_observed"


def test_ipc_transcript_judges_both_producers():
    """M50: the MPSC sample is complete only when the user sent through
    the endpoint AND the counters close under the proved bound."""
    full = GOOD.replace(
        "HALT", "IPC_ON mpsc\nUSER_ON el0\n"
                "SYSCALL 0x65 ipc_send from EL0\n"
                "USER_TRAP far=0x40200000 contained\n"
                "IPC lanes=2 posted=2 dropped=1 consumed=2 "
                "high_water=2 cap=2\nHALT")
    verdict = parse_transcript(full, COMPOSITION)
    assert verdict["status"] == "BOOT_RUNTIME_CONFIRMED"
    assert verdict["ipc_syscall_observed"] is True
    assert verdict["ipc"]["high_water"] == verdict["ipc"]["cap"] == 2
    assert verdict["ipc"]["posted"] + verdict["ipc"]["dropped"] == 3
    no_line = full.replace("IPC lanes=2 posted=2 dropped=1 consumed=2 "
                           "high_water=2 cap=2\n", "")
    assert parse_transcript(no_line, COMPOSITION)["code"] == \
        "ipc_not_observed"
    kernel_only = full.replace(
        "SYSCALL 0x65 ipc_send from EL0\n",
        "SYSCALL 0x64 write_console from EL0\n")
    assert parse_transcript(kernel_only, COMPOSITION)["code"] == \
        "ipc_syscall_not_observed"
    overflow = full.replace("high_water=2 cap=2", "high_water=3 cap=2")
    assert parse_transcript(overflow, COMPOSITION)["code"] == \
        "IPC_BOUND_EXCEEDED"


def test_order_mismatch_and_missing_output_refuse():
    swapped = GOOD.replace("BOOT pool_init\nBOOT scheduler_start",
                           "BOOT scheduler_start\nBOOT pool_init")
    verdict = parse_transcript(swapped, COMPOSITION)
    assert verdict["code"] == "boot_order_mismatch"
    assert "diverged" in verdict["message"]
    assert parse_transcript("silence\n", COMPOSITION)["code"] == \
        "no_boot_output"
    assert parse_transcript("BOOT timer_init\n", COMPOSITION)["code"] == \
        "boot_order_mismatch"


def test_ring_bound_violation_is_the_worst_outcome():
    """high_water > cap is not a lane failure — it CONTRADICTS the
    ESBMC-proved invariant; the code names it as such."""
    overflow = GOOD.replace("NET posted=7 dropped=9 consumed=7 "
                            "high_water=4 cap=4",
                            "NET posted=16 dropped=0 consumed=16 "
                            "high_water=5 cap=4")
    verdict = parse_transcript(overflow, COMPOSITION)
    assert verdict["code"] == "RING_BOUND_EXCEEDED"
    assert "contradicted" in verdict["message"] or "FAILED" in \
        verdict["message"]


def test_vacuous_flood_and_residuals_refuse():
    no_drops = GOOD.replace("dropped=9", "dropped=0")
    verdict = parse_transcript(no_drops, COMPOSITION)
    assert verdict["code"] == "backpressure_not_exercised"
    assert "vacuous" in verdict["message"]

    no_rings = "\n".join(line for line in GOOD.splitlines()
                         if not line.startswith(("NET", "SCHED")))
    assert parse_transcript(no_rings, COMPOSITION)["code"] == \
        "no_ring_evidence"
    panicked = GOOD.replace("HALT", "PANIC")
    assert parse_transcript(panicked, COMPOSITION)["code"] == \
        "kernel_panicked"


@pytest.mark.skipif(not (BOOT_DIR / "layout.ld").exists(),
                    reason="boot example not present")
@pytest.mark.skipif(shutil_which("rustc") is None,
                    reason="rustc not installed")
@pytest.mark.skipif(not _cross_target_ready(),
                    reason="aarch64-unknown-none-softfloat core lib "
                           "not installed")
def test_image_builds_for_qemu_virt():
    """The no_std image compiles with rustc + rust-lld (no cross C
    toolchain) — real build, no emulator needed."""
    verdict = build_boot_image(BOOT_DIR)
    assert verdict["status"] == "IMAGE_BUILT", verdict
    elf = Path(verdict["elf"])
    assert elf.exists()
    header = elf.read_bytes()[:20]
    assert header[18] == 0xB7 and header[19] == 0x00   # e_machine AArch64
    # the generated boot order is IN the image's rodata
    strings = subprocess_strings(elf)
    for step in ("timer_init", "pool_init", "scheduler_start",
                 "net_start"):
        assert step in strings, f"{step} missing from the image"
    # and the image agrees with the artifact the M46 gate proved
    for step in [s["name"] for s in COMPOSITION["steps"]]:
        assert step in strings


def subprocess_strings(path: Path) -> str:
    import subprocess
    out = subprocess.run(["strings", str(path)], capture_output=True,
                         text=True, timeout=30)
    return out.stdout


@pytest.mark.skipif(shutil_which("rustc") is None,
                    reason="the rustc_failed/rustc_timeout residuals "
                           "restore the real rustc binary")
def test_residuals_fail_closed(tmp_path, monkeypatch):
    import subprocess
    from unittest.mock import patch
    from pipeline import boot_check

    # toolchain absent (CI): named refusal
    monkeypatch.setattr(boot_check, "RUSTC_BIN", None)
    assert boot_check.build_boot_image(tmp_path)["code"] == \
        "toolchain_unavailable"
    monkeypatch.setattr(boot_check, "RUSTC_BIN",
                        shutil_which_or_none())

    # broken source refuses by name
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "layout.ld").write_text("ENTRY(_start)\n", encoding="utf-8")
    (bad / "src").mkdir(exist_ok=True)
    (bad / "src" / "main.rs").write_text("this is not rust\n",
                                         encoding="utf-8")
    assert boot_check.build_boot_image(bad)["code"] == "rustc_failed"

    # build timeout: named
    monkeypatch.setattr(boot_check, "RUSTC_BIN", "/usr/bin/sleep")
    assert boot_check.build_boot_image(bad)["code"] == "rustc_failed"
    monkeypatch.setattr(boot_check, "RUSTC_BIN",
                        shutil_which_or_none())
    with patch("pipeline.boot_check.subprocess.run",
               side_effect=subprocess.TimeoutExpired("rustc", 5)):
        assert boot_check.build_boot_image(bad)["code"] == \
            "rustc_timeout"

    # qemu absent: the refusal names the install command
    monkeypatch.setattr(boot_check, "QEMU_BIN", None)
    verdict = boot_check.run_qemu_boot("/nonexistent.elf")
    assert verdict["code"] == "qemu_unavailable"
    assert "apt-get install" in verdict["message"]

    # qemu timeout WITH transcript: the expected halt shape (the
    # kernel parks in wfe after printing)
    monkeypatch.setattr(boot_check, "QEMU_BIN", "/usr/bin/true")
    expired = subprocess.TimeoutExpired(
        "qemu", 15, output=b"BOOT timer_init\nHALT")
    with patch("pipeline.boot_check.subprocess.run",
               side_effect=expired):
        out = boot_check.run_qemu_boot("/x.elf")
    assert out["timed_out"] is True
    assert "BOOT timer_init" in out["transcript"]

    # qemu crash: named
    with patch("pipeline.boot_check.subprocess.run",
               side_effect=OSError("segv")):
        assert boot_check.run_qemu_boot("/x.elf")["code"] == \
            "qemu_crashed"


def shutil_which_or_none():
    import shutil
    return shutil.which("rustc")


def test_qemu_clean_exit_returns_transcript(monkeypatch):
    """A QEMU that exits on its own (e.g. -no-reboot) yields its
    stdout without the timed_out marker."""
    import subprocess
    from unittest.mock import patch
    from pipeline import boot_check
    monkeypatch.setattr(boot_check, "QEMU_BIN", "/usr/bin/true")
    done = subprocess.CompletedProcess([], 0, stdout="HALT\n", stderr="")
    with patch("pipeline.boot_check.subprocess.run",
               return_value=done):
        out = boot_check.run_qemu_boot("/x.elf")
    assert out == {"transcript": "HALT\n", "timed_out": False}


@pytest.mark.skipif(shutil_which("qemu-system-aarch64") is None,
                    reason="qemu-system-aarch64 not installed")
@pytest.mark.skipif(not _cross_target_ready(),
                    reason="aarch64-unknown-none-softfloat core lib "
                           "not installed")
def test_real_boot_end_to_end():
    """The full capstone on live QEMU: build, boot, judge — the
    executed boot order must equal the M46-proven order and the ring
    bound must hold with drops observed, under the RUNTIME_SAMPLE
    ceiling."""
    import json as _json
    from pipeline.boot_check import run_qemu_boot
    built = build_boot_image(BOOT_DIR)
    assert built["status"] == "IMAGE_BUILT", built
    boot = run_qemu_boot(built["elf"], timeout_seconds=10)
    verdict = parse_transcript(boot["transcript"], COMPOSITION)
    assert verdict["status"] == "BOOT_RUNTIME_CONFIRMED", verdict
    assert verdict["claim_ceiling"] == "RUNTIME_SAMPLE"
    assert verdict["mmu_trap_observed"] is True
    assert verdict["rings"]["NET"]["mmu_fault_far"] == "0x41000000"
    # M49: the unverified EL0 image asked through the table, then its
    # direct store into kernel .text trapped at exactly that address
    assert verdict["user_syscall_observed"] is True
    assert verdict["user_syscall_id"] == "0x64"
    assert verdict["user_fault_far"] == "0x40200000"
    # M50: BOTH producers fed the endpoint; the bound held exactly
    assert verdict["ipc_syscall_observed"] is True
    ipc = verdict["ipc"]
    assert ipc["lanes"] == 2
    assert ipc["high_water"] == ipc["cap"] == 2
    assert ipc["posted"] == 2 and ipc["dropped"] == 1
    assert ipc["posted"] + ipc["dropped"] == 3   # kernel's 2 + user's 1
    assert ipc["consumed"] == ipc["posted"]
    ring = verdict["rings"]["NET"]
    assert ring["high_water"] == ring["cap"] == 4
    assert ring["dropped"] == 9 and ring["posted"] == 7
    assert ring["posted"] + ring["dropped"] == 16   # every arrival
                                                    # accounted for
