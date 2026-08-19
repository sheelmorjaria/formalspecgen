# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M39: DMA isolation — the deterministic IOMMU-correspondence gate."""
from __future__ import annotations

from pathlib import Path

from pipeline.dma_isolation import dma_isolation

DRIVER = """#include <stddef.h>
void *eth_setup(void) {
    return dma_map(eth, 0x100);
}
"""

OVERLAPPING = """void *bad_setup(void) {
    return dma_map(nic, 0x4000);
}
"""

MEMORY_MAP = {
    "kernel_pools": {"object_pool": [0x4000, 0x8000]},
    "devices": {"eth": [0x10000, 0x11000], "nic": [0x3000, 0x5000]},
}
CONTRACTS = {"eth": [0x10000, 0x10800], "nic": [0x3000, 0x3400]}


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_dma_isolation_proved(tmp_path):
    verdict = dma_isolation(_write(tmp_path, "eth.c", DRIVER),
                            MEMORY_MAP, CONTRACTS)
    assert verdict["status"] == "DMA_ISOLATION_PROVED"
    assert verdict["claim"] == "DMA_ISOLATION_PROVED"
    assert verdict["scope"] == "deterministic_range_disjointness"
    assert verdict["dma_calls_checked"] == 1
    assert verdict["judge_pending"] == "cn_or_kani_hardware_memory_model"


def test_overlapping_dma_fails_closed(tmp_path):
    """nic's contract straddles the kernel object pool: a 0x4000-byte
    mapping overlaps it — the driver cannot program the device to write
    kernel pools."""
    verdict = dma_isolation(_write(tmp_path, "bad.c", OVERLAPPING),
                            MEMORY_MAP, CONTRACTS)
    assert verdict["status"] == "DMA_VERIFICATION_FAILED"
    assert verdict["code"] == "DMA_ISOLATION_VIOLATED"
    assert verdict["claim"] == "NO_PROOF"
    assert "object_pool" in " ".join(verdict["violations"])


def test_residuals_fail_closed(tmp_path):
    assert dma_isolation(tmp_path / "nope.c", MEMORY_MAP,
                         CONTRACTS)["code"] == "input_unavailable"
    assert dma_isolation(_write(tmp_path, "L.rs", "fn f(){}"),
                         MEMORY_MAP, CONTRACTS)["code"] == \
        "UNSUPPORTED_BOUNDARY"
    incomplete = dma_isolation(_write(tmp_path, "e.c", DRIVER),
                               {"kernel_pools": {}}, CONTRACTS)
    assert incomplete["code"] == "memory_map_incomplete"
    no_contract = dma_isolation(_write(tmp_path, "e.c", DRIVER),
                                MEMORY_MAP, {})
    assert no_contract["code"] == "DMA_ISOLATION_VIOLATED"
    uncontracted = """void *x(void) {
        return dma_map(mystery, 0x100);
    }
    """
    verdict = dma_isolation(_write(tmp_path, "u.c", uncontracted),
                            MEMORY_MAP, CONTRACTS)
    assert verdict["code"] == "DMA_ISOLATION_VIOLATED"
    assert "DmaContract" in " ".join(verdict["violations"])
