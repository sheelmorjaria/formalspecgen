# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M34: HAL/MMIO register discipline on the Frama-C WP lane.

Grounded by probe against real Frama-C 33.0 (qed + Z3): the register as a
STRUCT BITFIELD proves (writing one field preserves the others, 6/6) and the
PADDR<->PPTR window round-trip proves through callee contracts (19/19);
raw bitwise RMW postconditions are probed UNPROVABLE (timeout/failure on
symbolic AND literal masks) and are refused; volatile leaves goals Unknown —
device semantics are the human-accepted assumption.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pipeline.hal_mmio import detect_hal, render_hal_source, verify_hal

UART_REGISTER = """typedef struct {
    unsigned enable : 1;
    unsigned mode   : 4;
    unsigned _pad   : 3;
} uart_ctrl_t;

volatile uart_ctrl_t *const UART = (volatile uart_ctrl_t *)0x40000000u;

void uart_set_mode(unsigned mode) {
    UART->mode = mode;
}
"""

WINDOW_HEADER = """/* the machine.h shape: derived single-offset window translation */
#define PADDR_BASE 0x80000000UL
#define PPTR_BASE 0xffffff8000000000UL
#define PPTR_BASE_OFFSET (PPTR_BASE - PADDR_BASE)

static unsigned long ptrFromPAddr(unsigned long paddr) {
    return paddr + PPTR_BASE_OFFSET;
}
"""

PLAIN_RMW = """typedef unsigned int u32;

void set_bits(u32 *reg, u32 mask, u32 value) {
    *reg = (*reg & ~mask) | value;
}
"""

POINTER_INIT = """int g = 1;
int *p = &g;
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _framac_installed() -> bool:
    from pipeline import config
    return bool(shutil.which(config.FRAMAC_BIN)
                or Path(config.FRAMAC_BIN).is_file())


def test_detects_register_window_and_volatile():
    """Phase 1: bitfield register structs, the window macro, and volatile
    MMIO pointers are detected — named bitfields with widths, anonymous
    padding skipped, the derived offset macro named."""
    detected = detect_hal(UART_REGISTER)
    assert detected["code"] == "HAL_STRUCTURE_DETECTED"
    assert detected["registers"] == [
        {"type": "uart_ctrl_t",
         "fields": [("enable", 1), ("mode", 4), ("_pad", 3)]}]
    assert detected["volatile_mmio"] is True
    assert detected["window"] is False

    # an anonymous struct with no tag and no typedef name has no usable
    # type for a witness — skipped, the named register still detects
    skipped_anonymous = detect_hal("struct { unsigned x : 3; };\n"
                                   + UART_REGISTER)
    assert skipped_anonymous["registers"] == detected["registers"]

    # a second register struct after the first — the scan keeps going
    two = detect_hal(UART_REGISTER
                     + "\ntypedef struct { unsigned gate : 2; } gate_t;\n")
    assert two["registers"] == detected["registers"] + [
        {"type": "gate_t", "fields": [("gate", 2)]}]

    # a NAMED struct with no bitfield members is scanned past, not a register
    plain_then_register = detect_hal("struct plain { int x; };\n"
                                     + UART_REGISTER)
    assert plain_then_register["registers"] == detected["registers"]

    window = detect_hal(WINDOW_HEADER)
    assert window["code"] == "HAL_STRUCTURE_DETECTED"
    assert window["registers"] == []
    assert window["window"] is True
    assert window["window_offset_macro"] == "PPTR_BASE_OFFSET"
    assert window["volatile_mmio"] is False


def test_plain_rmw_refused_with_probe_evidence():
    """The probed-unprovable boundary: raw bitwise RMW postconditions time
    out / fail in WP's integer encoding — refused with the evidence, never
    approximated. Pointer INITIALIZATION (`int *p = &g;`) is not an RMW."""
    refused = detect_hal(PLAIN_RMW)
    assert refused["code"] == "UNSUPPORTED_BOUNDARY"
    assert "PROBED UNPROVABLE" in refused["message"]
    assert "bitfield" in refused["message"]

    not_rmw = detect_hal(POINTER_INIT)
    assert not_rmw["code"] == "no_hal_structure"

    assert detect_hal("int f(void) { return 1; }")["code"] == \
        "no_hal_structure"


def test_render_carries_the_probed_witnesses():
    """Phase 2: the harness appends the probed witnesses — a NON-volatile
    register witness with the untouched-field contract instantiated from
    the detected widths, and the window round-trip over the USER macro."""
    detection = detect_hal(UART_REGISTER)
    rendered, offset_source = render_hal_source(UART_REGISTER, detection)
    assert "hal_enable_witness" in rendered
    assert "requires v < 2u;" in rendered           # 1-bit enable field
    assert "ensures reg->mode == \\old(reg->mode);" in rendered
    assert "ensures reg->_pad == \\old(reg->_pad);" in rendered
    assert "volatile" not in rendered.split("uart_set_mode")[1]

    both = UART_REGISTER + WINDOW_HEADER
    detection = detect_hal(both)
    rendered, offset_source = render_hal_source(both, detection)
    assert "hal_window_roundtrip_probed" in rendered
    assert "ensures \\result == paddr;" in rendered
    assert "PPTR_BASE_OFFSET" in rendered      # the user's own macro
    assert offset_source == "user_macro:PPTR_BASE_OFFSET"

    detection = detect_hal(WINDOW_HEADER)
    _, offset_source = render_hal_source(WINDOW_HEADER, detection)
    assert offset_source == "user_macro:PPTR_BASE_OFFSET"


@pytest.mark.skipif(not _framac_installed(), reason="real Frama-C not installed")
def test_real_frama_c_proves_register_discipline(tmp_path):
    """The probed core: real WP discharges the bitfield-separation witness
    fully (strict gate); volatile device semantics are recorded as the
    human-accepted assumption."""
    source = _write(tmp_path, "uart.h", UART_REGISTER)
    verdict = verify_hal(source)
    assert verdict["status"] == "HAL_VERIFICATION_PROVED", verdict
    assert verdict["claim"] == "HAL_REASONING_PROVED"
    assert verdict["bitfield_separation_proved"] is True
    assert verdict["proved_goals"] == verdict["total_goals"]
    assert verdict["device_semantics"] == "human_accepted_assumption"
    assert verdict["volatile_mmio_detected"] is True
    assert verdict["lanes"] == ["register_bitfield_separation"]


@pytest.mark.skipif(not _framac_installed(), reason="real Frama-C not installed")
def test_real_frama_c_proves_window_roundtrip(tmp_path):
    """The window lane: the single-offset round-trip is the identity —
    machine-proved over the user's own offset macro; hardware mapping
    linearity is the human-accepted assumption."""
    source = _write(tmp_path, "machine.h", WINDOW_HEADER)
    verdict = verify_hal(source)
    assert verdict["status"] == "HAL_VERIFICATION_PROVED", verdict
    assert verdict["window_roundtrip_proved"] is True
    assert verdict["mapping_linearity"] == "human_accepted_assumption"
    assert verdict["window_offset_source"] == "user_macro:PPTR_BASE_OFFSET"
    assert verdict["proved_goals"] == verdict["total_goals"]


@pytest.mark.skipif(not _framac_installed(), reason="real Frama-C not installed")
def test_real_frama_c_both_lanes_combined(tmp_path):
    """The seL4-shaped combined header drives both witnesses in one WP
    invocation — register discipline AND window round-trip proved."""
    source = _write(tmp_path, "hal.h", UART_REGISTER + WINDOW_HEADER)
    verdict = verify_hal(source)
    assert verdict["status"] == "HAL_VERIFICATION_PROVED", verdict
    assert verdict["lanes"] == ["register_bitfield_separation",
                                "window_translation_roundtrip"]
    assert verdict["proved_goals"] == verdict["total_goals"]


def test_out_of_lane_sources_fail_closed(tmp_path):
    """Non-C sources, missing files, and empty sources fail closed."""
    rust = _write(tmp_path, "L.rs", "pub struct N;")
    assert verify_hal(rust)["code"] == "UNSUPPORTED_BOUNDARY"
    assert verify_hal(tmp_path / "nope.c")["code"] == "input_unavailable"
    flat = _write(tmp_path, "flat.c", "int f(void) { return 1; }")
    assert verify_hal(flat)["code"] == "no_hal_structure"
    rmw = _write(tmp_path, "rmw.c", PLAIN_RMW)
    assert verify_hal(rmw)["code"] == "UNSUPPORTED_BOUNDARY"


def test_wp_residuals_fail_closed(tmp_path, monkeypatch):
    """Prover-availability and WP-output residual gates refuse distinctly.
    Hermetic — the prover binary is a stub file and subprocess.run is
    mocked (CI runners have no Frama-C)."""
    from subprocess import CompletedProcess
    from unittest.mock import patch

    from pipeline import config
    source = _write(tmp_path, "uart.h", UART_REGISTER)

    monkeypatch.setattr(config, "FRAMAC_BIN", "/nonexistent/frama-c")
    assert verify_hal(source)["code"] == "framac_unavailable"

    stub = tmp_path / "frama-c"
    stub.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(config, "FRAMAC_BIN", str(stub))

    with patch("subprocess.run", side_effect=TimeoutError("slow")):
        assert verify_hal(source)["code"] == "framac_timeout"

    def _wp(out: str):
        return CompletedProcess(args=[], returncode=0, stdout=out, stderr="")

    with patch("subprocess.run", return_value=_wp("user error: annot-error")):
        assert verify_hal(source)["code"] == "hal_render_failed"
    with patch("subprocess.run", return_value=_wp("frama-c printed nothing")):
        assert verify_hal(source)["code"] == "wp_no_goals"
    with patch("subprocess.run",
               return_value=_wp("Proved goals:    8    /  10\n[Fail]")):
        assert verify_hal(source)["code"] == "discipline_not_proved"
    with patch("subprocess.run",
               return_value=_wp("Proved goals:    8    /  10\n[Timeout]")):
        # strict gate: no probed-known frame timeouts on these shapes —
        # a timeout is a refusal, not an assumption
        assert verify_hal(source)["code"] == "discipline_not_proved"
