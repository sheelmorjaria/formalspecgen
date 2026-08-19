# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M48: MMU spatial isolation — the frame map as a deterministic gate.

Address-space isolation is range arithmetic before it is hardware:
the human declares the physical memory map (kernel pools, DMA windows,
the user frame region — the same PhysicalMemoryMap family as M39), the
reviewer declares the intended mappings, and this gate proves the map
is isolating BEFORE any silicon sees it:

1. every mapped frame lies inside the declared USER_FRAMES region;
2. no mapped frame overlaps a kernel pool or DMA window;
3. no frame is double-mapped (aliasing two virtual addresses is a
   classic isolation break — refused by name);
4. the page-table pool usage stays within the M41-derived capacity
   (FRAME_EXHAUSTED is a capacity fact, not a guess).

Honest scope: ``SPATIAL_ISOLATION_PROVED`` is decidable arithmetic over
declared ranges — the same epistemic class as M39's
DMA_ISOLATION_PROVED. It is NOT a proof about hardware page-table
walkers; the live QEMU fault trap (boot image) provides the runtime
sample, ceilinged at RUNTIME_SAMPLE.
"""
from __future__ import annotations


def _fail(code: str, message: str, **extra) -> dict:
    return {"status": "MMU_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message, **extra}


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def _contains(outer: tuple[int, int], inner: tuple[int, int]) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def verify_spatial_isolation(memory_map: dict, mappings: list) -> dict:
    """Prove the declared user mappings cannot touch kernel memory.

    memory_map: {kernel_pools, dma_windows (optional), user_frames,
    page_table_pool: {capacity}} — the human-owned physical map.
    mappings: [{va, frame, size}] — the reviewer's intended map, each
    frame range [frame, frame+size).
    """
    pools = memory_map.get("kernel_pools")
    user = memory_map.get("user_frames")
    pt_pool = memory_map.get("page_table_pool")
    if not isinstance(pools, dict) or not pools:
        return _fail("memory_map_incomplete",
                     "kernel_pools ranges are required — isolation is "
                     "proved against declared kernel memory")
    if not isinstance(user, (list, tuple)) or len(user) != 2:
        return _fail("memory_map_incomplete",
                     "user_frames [start, end] is required — user "
                     "physical memory is a human declaration")
    if not isinstance(pt_pool, dict) or "capacity" not in pt_pool:
        return _fail("memory_map_incomplete",
                     "page_table_pool {capacity} is required — the "
                     "page-table pool bound comes from the M41 profile")
    dma_windows = memory_map.get("dma_windows") or {}
    user_span = (user[0], user[1])
    if user_span[0] >= user_span[1]:
        return _fail("memory_map_incomplete",
                     "user_frames must be [start, end] with start < end")

    for name, span in {**pools, **dma_windows}.items():
        if not (isinstance(span, (list, tuple)) and len(span) == 2
                and span[0] < span[1]):
            return _fail("memory_map_incomplete",
                         f"range for {name!r} must be [start, end] with "
                         "start < end")

    if not isinstance(mappings, list) or not mappings:
        return _fail("mappings_missing",
                     "no mappings declared — an empty map proves "
                     "nothing (vacuous), the gate refuses it")

    seen_frames: list[tuple[str, tuple[int, int]]] = []
    checked = 0
    for entry in mappings:
        if not isinstance(entry, dict) or "frame" not in entry:
            return _fail("mapping_field_missing",
                         "each mapping needs at least {frame}")
        try:
            frame = int(entry["frame"])
            size = int(entry.get("size", 0x1000))
        except (TypeError, ValueError):
            return _fail("mapping_field_missing",
                         "frame/size must be integers")
        if size <= 0:
            return _fail("mapping_field_missing",
                         "mapping size must be positive")
        request = (frame, frame + size)
        # the worst outcome is checked FIRST: a mapping that touches
        # kernel memory is an isolation BREAK, not merely misplaced
        for pool_name, pool in {**pools, **dma_windows}.items():
            if _overlaps(request, tuple(pool)):
                return _fail(
                    "KERNEL_MEMORY_MAPPED",
                    f"user mapping [{request[0]:#x}, {request[1]:#x}) "
                    f"overlaps {pool_name} "
                    f"[{pool[0]:#x}, {pool[1]:#x}) — spatial isolation "
                    "is broken", pool=pool_name)
        if not _contains(user_span, request):
            return _fail("FRAME_OUTSIDE_USER_REGION",
                         f"mapping at {frame:#x} ({size:#x} bytes) is "
                         f"outside user_frames "
                         f"[{user_span[0]:#x}, {user_span[1]:#x}) — a "
                         "user page may never point at non-user memory")
        for other_va, other in seen_frames:
            if _overlaps(request, other):
                return _fail(
                    "FRAME_DOUBLE_MAPPED",
                    f"frame range [{request[0]:#x}, {request[1]:#x}) is "
                    f"mapped at both va {other_va:#x} and "
                    f"{int(entry.get('va', 0)):#x} — aliasing is an "
                    "isolation break")
        seen_frames.append((int(entry.get("va", 0)), request))
        checked += 1

    if checked > pt_pool["capacity"]:
        return _fail("FRAME_EXHAUSTED",
                     f"{checked} mappings exceed the page-table pool "
                     f"capacity {pt_pool['capacity']} — the M41 profile "
                     "bound is a fact, not a guess")

    return {
        "status": "SPATIAL_ISOLATION_PROVED",
        "claim": "SPATIAL_ISOLATION_PROVED",
        "scope": "deterministic_range_disjointness",
        "judge": "deterministic_gate",
        "mappings_checked": checked,
        "user_frames": [user_span[0], user_span[1]],
        "kernel_pools": {k: list(v) for k, v in pools.items()},
        "dma_windows": {k: list(v) for k, v in dma_windows.items()},
        "page_table_pool_capacity": pt_pool["capacity"],
        "judge_pending": "hardware_page_table_walker",
        "note": "the declared map is isolating by decidable arithmetic; "
                "the silicon page-table walk is observed at runtime "
                "(QEMU fault trap), never proved here",
    }
