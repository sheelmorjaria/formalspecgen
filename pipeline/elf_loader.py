# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M57 bounded ELF layout and page-permission correspondence gate."""
from __future__ import annotations

from .mmu_isolation import verify_spatial_isolation

PF_X = 1
PF_W = 2
PF_R = 4
PAGE_SIZE = 4096


def _fail(code: str, message: str) -> dict:
    return {"status": "ELF_LOAD_VERIFICATION_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def _overlaps(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def verify_elf_load(artifact: dict, memory_map: dict) -> dict:
    """Verify one bounded ELF64/AArch64 load plan and its M48 mappings."""
    header = artifact.get("elf_header")
    if not isinstance(header, dict) or header.get("magic") != "7f454c46" \
            or header.get("class") != "ELF64" \
            or header.get("endian") != "little" \
            or header.get("type") != "ET_EXEC" \
            or header.get("machine") != "AARCH64":
        return _fail("ELF_HEADER_UNSUPPORTED",
                     "loader accepts only little-endian ELF64 AArch64 ET_EXEC")
    segments = artifact.get("segments")
    maximum = artifact.get("max_load_segments")
    file_size = artifact.get("file_size")
    entry = header.get("entry")
    if not isinstance(maximum, int) or maximum <= 0 or maximum > 4:
        return _fail("ELF_SEGMENT_BOUND_INVALID", "max_load_segments must be 1..4")
    if not isinstance(segments, list) or not segments or len(segments) > maximum:
        return _fail("ELF_SEGMENT_BOUND_EXCEEDED",
                     "load segment count is empty or exceeds its declared bound")
    if not isinstance(file_size, int) or file_size <= 0 or not isinstance(entry, int):
        return _fail("ELF_HEADER_INVALID", "file size and entry must be positive integers")

    virtual: list[tuple[int, int]] = []
    mappings = []
    executable_ranges = []
    for index, segment in enumerate(segments):
        required = {"offset", "file_size", "memory_size", "va", "frame", "flags"}
        if not isinstance(segment, dict) or not required <= set(segment):
            return _fail("ELF_SEGMENT_FIELD_MISSING", f"segment {index} is incomplete")
        values = [segment[name] for name in required]
        if not all(isinstance(value, int) and not isinstance(value, bool)
                   for value in values):
            return _fail("ELF_SEGMENT_FIELD_INVALID", f"segment {index} fields must be integers")
        offset, filesz, memsz = (segment["offset"], segment["file_size"],
                                  segment["memory_size"])
        va, frame, flags = segment["va"], segment["frame"], segment["flags"]
        if filesz < 0 or memsz <= 0 or filesz > memsz or offset < 0 \
                or va < 0 or frame < 0 or flags < 0 \
                or offset + filesz > file_size:
            return _fail("ELF_SEGMENT_SIZE_INVALID",
                         f"segment {index} exceeds file or memory bounds")
        if va % PAGE_SIZE or memsz % PAGE_SIZE:
            return _fail("ELF_SEGMENT_UNALIGNED",
                         f"segment {index} virtual span is not page aligned")
        if flags & ~(PF_R | PF_W | PF_X):
            return _fail("ELF_FLAGS_INVALID", f"segment {index} has unknown flags")
        if flags & PF_W and flags & PF_X:
            return _fail("ELF_WX_VIOLATION",
                         f"segment {index} is writable and executable")
        span = (va, va + memsz)
        if any(_overlaps(span, other) for other in virtual):
            return _fail("ELF_SEGMENT_OVERLAP", "virtual load segments overlap")
        virtual.append(span)
        executable = bool(flags & PF_X)
        writable = bool(flags & PF_W)
        if executable:
            executable_ranges.append(span)
        expected_ap = "EL0_RW" if writable else "EL0_RO"
        if segment.get("uxn") is not (not executable) or \
                segment.get("ap") != expected_ap or segment.get("user") is not True:
            return _fail("ELF_PERMISSION_MISMATCH",
                         f"segment {index} flags do not match UXN/AP/user mapping")
        mappings.append({"va": va, "frame": frame, "size": memsz})
    if not any(start <= entry < end for start, end in executable_ranges):
        return _fail("ELF_ENTRY_NOT_EXECUTABLE",
                     "entry point is outside every executable segment")
    spatial = verify_spatial_isolation(memory_map, mappings)
    if spatial.get("status") != "SPATIAL_ISOLATION_PROVED":
        return _fail(spatial.get("code", "ELF_SPATIAL_ISOLATION_FAILED"),
                     spatial.get("message", "ELF mappings are not isolating"))
    return {
        "status": "ELF_LOAD_PROVED",
        "claim": "ELF_LOAD_PROVED",
        "claims": ["ELF_SEGMENT_LAYOUT_PROVED",
                   "ELF_PERMISSION_CORRESPONDENCE_PROVED",
                   "SPATIAL_ISOLATION_PROVED"],
        "scope": "bounded_elf64_aarch64_load_plan",
        "segments_checked": len(segments),
        "max_load_segments": maximum,
        "entry": entry,
        "spatial_isolation": spatial,
        "judge": "deterministic_gate",
        "judge_pending": "hardware_page_table_walker_and_eret",
        "note": "ELF parsing/layout and permission correspondence are proved over the "
                "declared plan; hardware page walks and EL1-to-EL0 entry remain pending",
    }
