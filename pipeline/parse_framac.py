# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Normalize Frama-C/WP diagnostics into the shared verification-condition schema."""
from __future__ import annotations

import re

from .schemas import VC

_GOAL = re.compile(
    r"^\s*\[wp\]\s+(?:\[[^]]+\]\s+)?(?P<status>Failed|Unknown|Timeout|Valid|Proved)"
    r"(?:\s*[:.-]\s*|\s+)(?P<detail>.+?)\s*$",
    re.IGNORECASE,
)
_LOCATION = re.compile(r"(?P<file>[^\s:()]+\.[ch]):(?P<line>\d+)")
_FUNCTION = re.compile(r"(?:in function|function|method)\s+['`]?([A-Za-z_]\w*)", re.IGNORECASE)


def parse_framac_vcs(text: str) -> list[VC]:
    """Return only unproved WP goals; a summary alone never manufactures a VC."""
    output: list[VC] = []
    seen: set[tuple] = set()
    for line in text.splitlines():
        match = _GOAL.match(line)
        if not match or match["status"].lower() in {"valid", "proved"}:
            continue
        detail = match["detail"].strip()
        location = _LOCATION.search(line)
        method = _FUNCTION.search(line)
        category = _category(detail)
        file = location["file"] if location else "candidate.c"
        line_number = int(location["line"]) if location else 0
        key = (file, line_number, category, detail)
        if key in seen:
            continue
        seen.add(key)
        output.append(VC(file=file, line=line_number, category=category,
                         method=method.group(1) if method else None,
                         detail=detail, raw=line.rstrip()))
    return output


def _category(detail: str) -> str:
    lowered = detail.lower()
    for marker, category in (
        ("overflow", "ArithmeticOperationRange"),
        ("underflow", "ArithmeticOperationRange"),
        ("division by zero", "ArithmeticOperationRange"),
        ("precondition", "Precondition"),
        ("postcondition", "Postcondition"),
        ("loop invariant", "LoopInvariant"),
        ("valid", "PointerValidity"),
        ("bounds", "ArrayAccess"),
        ("assigns", "FrameCondition"),
        ("termination", "Termination"),
    ):
        if marker in lowered:
            return category
    return "FramaCVerification"
