# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Helpers for the JML-annotated Java stub that is this project's spec artifact.

The stub is a Java skeleton (class + fields + method signatures, empty bodies) with
`//@`/`/*@*/` JML annotations. The native implementation pipeline consumes this artifact,
and validation uses real Java structure rather than a meaningless dummy class.

This module also owns clause extraction + clause diffing (shared by the eval harness and
the no-clobber refine flow).
"""
import re

_CLASS = re.compile(r'\bpublic\s+(?:final\s+|abstract\s+)?class\s+(\w+)')
# annotation lines for DISPLAY (//@ lines + /*@ ... */ block markers)
_JML_LINE = re.compile(r'^\s*//@|^\s*/\*@|^\s*\*@|\*@\s*/|^\s*//')
_SL = re.compile(r'^\s*//@\s*(.*?)\s*$')
_BLOCK = re.compile(r'/\*@(.*?)\*/', re.DOTALL)   # /*@ ... */ blocks, incl. single-line
# a clause must contain a JML contract keyword — this drops method signatures and stray
# modifier annotations (spec_public / pure) that the block regex would otherwise capture.
_KW = re.compile(r'\b(requires|ensures|invariant|assignable|signals|loop_invariant|'
                 r'decreases|forall|exists|product|sum|max|min|represents|accessible|'
                 r'measured_by|assert|assume|constraint|diverges|when)\b')


def class_name(stub: str):
    """Public class name, used to name the .java file (javac/openjml requires the match)."""
    m = _CLASS.search(stub)
    return m.group(1) if m else None


def normalize_line_clause_continuations(stub: str) -> str:
    """Promote ordinary ``//`` continuations inside an unfinished ``//@`` clause.

    Models sometimes format a long clause as a JML first line followed by visually aligned
    Java comments. OpenJML then sees only the unfinished first line. Promotion is deliberately
    narrow: it starts only for a JML clause with unmatched parentheses or a trailing operator,
    and stops as soon as that expression is complete.
    """
    lines = stub.splitlines(keepends=True)
    active = False
    depth = 0
    output = []
    for line in lines:
        jml = re.match(r"^(\s*)//@\s?(.*?)(\r?\n)?$", line)
        ordinary = re.match(r"^(\s*)//(?!@)\s?(.*?)(\r?\n)?$", line)
        if jml:
            text = jml.group(2)
            depth = _paren_delta(text)
            active = depth > 0 or bool(re.search(r"(?:&&|\|\||==>|<==>|[+\-*/]|==|!=|<=|>=)\s*$", text))
            output.append(line)
            if ";" in text and depth <= 0:
                active = False
            continue
        if active and ordinary:
            text = ordinary.group(2)
            newline = ordinary.group(3) or ""
            output.append(f"{ordinary.group(1)}//@ {text}{newline}")
            depth += _paren_delta(text)
            if (";" in text and depth <= 0) or (depth <= 0 and not re.search(
                    r"(?:&&|\|\||==>|<==>|[+\-*/]|==|!=|<=|>=)\s*$", text)):
                active = False
            continue
        active, depth = False, 0
        output.append(line)
    return "".join(output)


def normalize_old_in_requires(stub: str) -> str:
    r"""Remove redundant/illegal ``\old`` wrappers from line preconditions.

    A method precondition is evaluated in the pre-state already, so this changes syntax but
    not meaning. Postconditions and every other JML context remain untouched.
    """
    def rewrite(match: re.Match) -> str:
        clause = re.sub(r"\\old\s*\(\s*([^()]+?)\s*\)", r"\1", match.group(2))
        return match.group(1) + clause

    return re.sub(r"(?m)^(\s*//@\s*requires\s+)([^\n]*)$", rewrite, stub)


def _paren_delta(text: str) -> int:
    """Count grouping parentheses outside simple quoted literals."""
    cleaned = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', "", text)
    return cleaned.count("(") - cleaned.count(")")


def extract_jml(stub: str):
    """Best-effort extraction of JML annotation lines for display."""
    return [ln.strip() for ln in stub.splitlines() if _JML_LINE.search(ln)]


def normalize_clause(clause: str) -> str:
    c = clause.strip().rstrip(";").strip()
    return re.sub(r'\s+', ' ', c).lower()


def _is_clause(c: str) -> bool:
    return bool(_KW.search(c))


def extract_clauses(stub: str):
    """Return normalized JML contract clauses: //@ lines + /*@ ... */ block bodies, keeping
    only those with a JML contract keyword (drops method signatures + spec_public/pure noise).

    Handles single-line `/*@ spec_public @*/` correctly — a prior line-based scanner left
    block mode open and mis-extracted every following line.
    """
    out = []
    for ln in stub.splitlines():
        m = _SL.match(ln)
        if m and m.group(1).strip():
            out.append(m.group(1).strip())
    for blk in _BLOCK.findall(stub):           # each /*@ ... */ block (single- or multi-line)
        for ln in blk.splitlines():
            c = ln.strip().lstrip('*').lstrip('@').strip()
            if c:
                out.append(c)
    return [normalize_clause(c) for c in out if _is_clause(c)]


def clause_diff(a: str, b: str):
    """Clause-level diff of two stubs by normalized clause text."""
    sa, sb = set(extract_clauses(a)), set(extract_clauses(b))
    return {"added": sorted(sb - sa), "removed": sorted(sa - sb), "common": sorted(sa & sb)}


def contains_clause(stub: str, clause: str) -> bool:
    """True if `clause` is present in `stub` (normalized comparison)."""
    return normalize_clause(clause) in set(extract_clauses(stub))
