# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Hardware-aware capacity bounding: physical SRAM limits drive array bounds.

A bound like 1000 pulled from thin air is a heuristic. On a DO-178C / ISO 26262
target the capacity of every statically allocated pool must be derived from the
physical memory of the microcontroller and provably fit. This module loads a
hardware profile (``hardware_profile.json``) and turns it into deterministic
capacities, stack-depth limits, and fail-closed verdicts — the LLM never
chooses the number; the silicon does.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path


class HardwareProfileError(ValueError):
    """Raised with a fail-closed code when the target cannot hold the pool."""


@dataclass(frozen=True)
class Profile:
    target: str
    total_sram_bytes: int
    reserved_system_bytes: int
    max_stack_depth_bytes: int
    word_size_bytes: int
    # M41: the multi-architecture lattice keys off these; both stay
    # optional so M30-era profiles (stm32.json) keep loading unchanged.
    memory_model: str = ""
    sram_base_bytes: int = 0

    @property
    def usable_sram_bytes(self) -> int:
        return self.total_sram_bytes - self.reserved_system_bytes


def load_profile(path: str | Path) -> Profile:
    """Parse and validate a hardware profile; any defect fails closed."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        profile = Profile(
            target=str(raw["target"]),
            total_sram_bytes=int(raw["total_sram_bytes"]),
            reserved_system_bytes=int(raw["reserved_system_bytes"]),
            max_stack_depth_bytes=int(raw["max_stack_depth_bytes"]),
            word_size_bytes=int(raw.get("word_size_bytes", 4)),
            memory_model=str(raw.get("memory_model", "")),
            sram_base_bytes=int(raw.get("sram_base_bytes", 0)))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise HardwareProfileError(f"hardware_profile_unreadable: {exc}") from exc
    if profile.reserved_system_bytes >= profile.total_sram_bytes:
        raise HardwareProfileError(
            "hardware_profile_invalid: reserved system memory must leave usable SRAM")
    if profile.word_size_bytes <= 0:
        raise HardwareProfileError("hardware_profile_invalid: word size must be positive")
    return profile


def safe_capacity(profile: Profile, struct_size_bytes: int,
                   safety_margin: float = 0.9) -> int:
    """Maximum element count that fits usable SRAM within the safety margin.

    The margin leaves headroom for other allocations; the result is truncated
    (never rounded up) so the pool can only be smaller than the budget.
    """
    if struct_size_bytes <= 0:
        raise HardwareProfileError(
            "hardware_profile_invalid: struct size must be positive")
    budget = int(profile.usable_sram_bytes * safety_margin)
    if struct_size_bytes > budget:
        raise HardwareProfileError(
            "HARDWARE_MEMORY_EXCEEDED: struct of "
            f"{struct_size_bytes} bytes does not fit the {budget}-byte SRAM budget "
            f"of {profile.target}")
    return budget // struct_size_bytes


_JAVA_FIELD = re.compile(
    r"(?:public|private|protected)?\s*(?:static\s+|final\s+)*"
    r"(int|long|short|byte|boolean|double|float|char)\s+\w+\s*(?:=[^;]*)?;")
_FIELD_SIZES = {"int": 4, "long": 8, "short": 2, "byte": 1, "boolean": 1,
                "double": 8, "float": 4, "char": 2}


def derive_struct_size(source: str, word_size_bytes: int = 4) -> int:
    """Estimate a flat struct size from scalar Java fields, word-padded.

    Object references and nested structures are NOT counted — this is a
    lower-bound estimate for scalar pools; the reviewer supplies exact sizes
    when the struct carries references.
    """
    raw = sum(_FIELD_SIZES[match.group(1)]
              for match in _JAVA_FIELD.finditer(source))
    if raw == 0:
        return word_size_bytes
    return math.ceil(raw / word_size_bytes) * word_size_bytes


def stack_depth_ok(profile: Profile, frame_bytes: int, depth: int) -> bool:
    """Whether `depth` frames of `frame_bytes` fit the physical stack."""
    return frame_bytes > 0 and depth >= 0 and frame_bytes * depth \
        <= profile.max_stack_depth_bytes


# --- M41: the kernel subsystem pool table ---------------------------------
#
# One human-owned profile derives EVERY kernel pool (scheduler, VFS,
# network) at once, and the pools must not collide in SRAM. The math is
# deterministic; the profile is the human's trust root.


def derive_kernel_pools(profile: Profile,
                        subsystems: dict) -> dict:
    """Derive every kernel pool's capacity and SRAM window, fail-closed.

    ``subsystems`` maps a name to ``{"struct_size_bytes": N,
    "sram_base": ADDR?}`` — struct sizes are human declarations, windows
    are checked pairwise disjoint and (when the profile declares an SRAM
    origin) contained in usable SRAM. Windows are only minted for
    subsystems that declare ``sram_base``; capacity is minted for all.
    """
    def refused(code: str, message: str) -> dict:
        return {"status": "HARDWARE_PROFILE_REFUSED", "claim": "NO_PROOF",
                "code": code, "message": message}

    if not isinstance(subsystems, dict) or not subsystems:
        return refused("subsystems_missing",
                       "the kernel profile declares no subsystems — "
                       "capacities are never guessed")
    pools: dict[str, dict] = {}
    windows: list[tuple[str, int, int]] = []
    for name, spec in subsystems.items():
        if not isinstance(spec, dict) or "struct_size_bytes" not in spec:
            return refused("subsystem_field_missing",
                           f"subsystem {name} lacks struct_size_bytes — "
                           "a pool size is never guessed")
        try:
            struct_size = int(spec["struct_size_bytes"])
        except (TypeError, ValueError):
            return refused("subsystem_field_missing",
                           f"subsystem {name} struct_size_bytes is not an "
                           "integer")
        if struct_size <= 0:
            return refused("hardware_profile_invalid",
                           f"subsystem {name} struct size must be positive")
        if struct_size % profile.word_size_bytes:
            return refused("word_misaligned",
                           f"subsystem {name} struct of {struct_size} bytes "
                           f"is not {profile.word_size_bytes}-byte aligned "
                           f"on {profile.target}")
        try:
            capacity = safe_capacity(profile, struct_size)
        except HardwareProfileError as exc:
            code, _, message = str(exc).partition(": ")
            return refused(code, message)
        if "budget_bytes" in spec:
            # The reviewer's share declaration: how much of usable SRAM
            # this subsystem may take. The ceiling stays the physics; the
            # share is the architecture. Capacity never exceeds either.
            try:
                share = int(spec["budget_bytes"])
            except (TypeError, ValueError):
                return refused("subsystem_field_missing",
                               f"subsystem {name} budget_bytes is not an "
                               "integer")
            if share <= 0:
                return refused("hardware_profile_invalid",
                               f"subsystem {name} budget must be positive")
            capacity = min(capacity, share // struct_size)
        window = None
        if "sram_base" in spec:
            base = int(spec["sram_base"])
            window = (base, base + capacity * struct_size)
            windows.append((name, window[0], window[1]))
        pools[name] = {"safe_capacity": capacity,
                       "struct_size_bytes": struct_size,
                       "footprint_bytes": capacity * struct_size,
                       "window_bytes": list(window) if window else None}
    for i, (name_a, lo_a, hi_a) in enumerate(windows):
        for name_b, lo_b, hi_b in windows[i + 1:]:
            if lo_a < hi_b and lo_b < hi_a:
                return refused("sram_overlap",
                               f"kernel pools {name_a} and {name_b} overlap "
                               f"in SRAM ([{lo_a}, {hi_a}) vs [{lo_b}, "
                               f"{hi_b})) — the memory map is refused")
    if profile.sram_base_bytes:
        origin = profile.sram_base_bytes
        ceiling = origin + profile.usable_sram_bytes
        for name, lo, hi in windows:
            if lo < origin or hi > ceiling:
                return refused("pool_outside_sram",
                               f"kernel pool {name} window [{lo}, {hi}) is "
                               f"outside usable SRAM [{origin}, {ceiling}) "
                               f"of {profile.target}")
    return {"status": "HARDWARE_PROFILE_DERIVED",
            "claim": "HARDWARE_PROFILE_DERIVED",
            "scope": "deterministic_arithmetic",
            "ownership": "human_declared_hardware_profile",
            "target": profile.target,
            "memory_model": profile.memory_model or None,
            "usable_sram_bytes": profile.usable_sram_bytes,
            "safety_margin": 0.9,
            "pools": pools}
