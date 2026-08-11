# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Parse OpenJML `-esc` output into structured VCs (ported verbatim from formalspecDD).

Handles BOTH `verify:` line formats:
  spec-clause:  f:l: verify: The prover cannot establish an assertion (Postcondition: declfile:declline:) in method m
  range/check:  f:l: verify: The prover cannot establish an assertion (ArithmeticOperationRange) in method m: overflow in int s

Used here only on the optional ESC deep-check path; the primary validator is -check
(parse_check.py).
"""
import re
from .schemas import VC

_VC = re.compile(
    r'^(?P<file>.+):(?P<line>\d+): verify: The prover cannot establish an assertion '
    r'\((?P<cat>\w+)(?:: (?P<decl>[^)]*))?\) in method (?P<method>\w+)'
    r'(?:: (?P<detail>.*))?$'
)


def parse_vcs(text: str):
    seen, out = set(), []
    for ln in text.splitlines():
        m = _VC.match(ln.rstrip())
        if not m:
            continue
        key = (m["file"], m["line"], m["cat"], m["detail"] or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(VC(
            file=m["file"], line=int(m["line"]), category=m["cat"], method=m["method"],
            decl=m["decl"] or None, detail=m["detail"] or None, raw=ln.rstrip(),
        ))
    return out
