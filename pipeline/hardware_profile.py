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
            word_size_bytes=int(raw.get("word_size_bytes", 4)))
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
