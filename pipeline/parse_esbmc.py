# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Normalize ESBMC diagnostics into the shared verification-condition schema."""
from __future__ import annotations

import re

from .schemas import VC

# Shape 1: the modern counterexample block
#   Violated property:
#     file counter.cpp line 10 function main
#     dereference failure: pointer NULL
_PROPERTY_LINE = re.compile(
    r"^\s*file\s+(?P<file>[^\s]+)\s+line\s+(?P<line>\d+)(?:\s+function\s+(?P<function>[^\s]+))?",
    re.IGNORECASE)
_PROPERTY_DETAIL = re.compile(r"^\s*(?P<detail>(?:dereference failure|arithmetic overflow|"
                              r"array bounds|.*check.*|.*violation.*|.+))\s*$",
                              re.IGNORECASE)
# Shape 2: the compact summary line
_SUMMARY = re.compile(
    r"(?:ERROR:|)(?:\s*)Verif(?:ication|ying) fail(?:ed|ure):?\s*(?P<detail>.+?)"
    r"(?:\s*\(line\s+(?P<line>\d+)\))?\s*$",
    re.IGNORECASE)
_FUNCTION_HINT = re.compile(r"function\s+(?P<function>[A-Za-z_]\w*)")

_MARKERS = (
    ("array bounds", "UndefinedNegativeIndex"),
    ("out-of-bounds", "UndefinedNegativeIndex"),
    ("bounds violated", "UndefinedNegativeIndex"),
    ("dereference", "PossiblyNull"),
    ("pointer null", "PossiblyNull"),
    ("null pointer", "PossiblyNull"),
    ("arithmetic overflow", "ArithmeticOperationRange"),
    ("overflow", "ArithmeticOperationRange"),
    ("division by zero", "ArithmeticOperationRange"),
)


def parse_esbmc_vcs(text: str) -> list[VC]:
    """Return unproved ESBMC properties; a successful run yields no VCs.

    ESBMC prints counterexamples as ``Violated property:`` blocks with a
    ``file ... line ... function ...`` locator, or compact summary lines of the
    shape ``Verification failed: <reason> (line N)``. Both shapes normalize into
    the shared VC schema; unmatched shapes are never guessed into success.
    """
    output: list[VC] = []
    seen: set[tuple] = set()
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.strip().lower().startswith("violated property:"):
            file, line_number, function, detail = "candidate.cpp", 0, None, None
            probe = index + 1
            while probe < len(lines) and not lines[probe].strip().startswith("Violated"):
                locator = _PROPERTY_LINE.search(lines[probe])
                if locator:
                    file = locator["file"]
                    line_number = int(locator["line"])
                    function = locator["function"]
                elif detail is None and lines[probe].strip():
                    detail = lines[probe].strip()
                probe += 1
            if detail is not None:
                category = _category(detail)
                key = (file, line_number, category, detail)
                if key not in seen:
                    seen.add(key)
                    output.append(VC(file=file, line=line_number, category=category,
                                     method=function, detail=detail, raw=line.rstrip()))
            index = probe
            continue
        summary = _SUMMARY.search(line)
        if summary and summary["detail"].strip():
            detail = summary["detail"].strip().rstrip(").").strip()
            line_number = int(summary["line"]) if summary["line"] else 0
            category = _category(detail)
            key = ("candidate.cpp", line_number, category, detail)
            if key not in seen:
                seen.add(key)
                output.append(VC(file="candidate.cpp", line=line_number, category=category,
                                 detail=detail, raw=line.rstrip()))
        index += 1
    return output


def _category(detail: str) -> str:
    lowered = detail.lower()
    for marker, category in _MARKERS:
        if marker in lowered:
            return category
    return "EsbmcVerification"
