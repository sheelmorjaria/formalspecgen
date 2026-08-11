# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Normalize Prusti/rustc diagnostics into the shared VC schema."""
import re

from .schemas import VC

_MESSAGE = re.compile(r"^error(?:\[[^]]+\])?:\s*(?:\[Prusti:[^]]+\]\s*)?(?P<message>.+)$")
_LOCATION = re.compile(r"^\s*-->\s+(?P<file>.+?):(?P<line>\d+):(?P<column>\d+)\s*$")


def parse_prusti_vcs(text: str) -> list[VC]:
    """Parse paired Rust diagnostic headers and source locations without guessing success."""
    pending = None
    output = []
    seen = set()
    for line in text.splitlines():
        message = _MESSAGE.match(line.rstrip())
        if message:
            pending = message["message"].strip()
            continue
        location = _LOCATION.match(line.rstrip())
        if not location or not pending:
            continue
        category = _category(pending)
        key = (location["file"], int(location["line"]), category, pending)
        if key not in seen:
            seen.add(key)
            output.append(VC(file=location["file"], line=int(location["line"]),
                             category=category, detail=pending,
                             raw=f"{pending} @ {location[0].strip()}"))
        pending = None
    return output


def _category(message: str) -> str:
    lowered = message.lower()
    categories = (
        ("postcondition", "Postcondition"),
        ("precondition", "Precondition"),
        ("loop invariant", "LoopInvariant"),
        ("overflow", "ArithmeticOperationRange"),
        ("underflow", "ArithmeticOperationRange"),
        ("index", "ArrayAccess"),
        ("bounds", "ArrayAccess"),
        ("panic", "PanicSafety"),
        ("termination", "Termination"),
        ("decreases", "Termination"),
    )
    for marker, category in categories:
        if marker in lowered:
            return category
    return "PrustiVerification"
