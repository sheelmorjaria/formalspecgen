# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Lexical helpers for the JML-annotated Java specification artifact.

The stub is a Java skeleton (class + fields + method signatures, empty bodies) with
`//@`/`/*@*/` JML annotations. The native implementation pipeline consumes this artifact,
and validation uses real Java structure rather than a meaningless dummy class.

This module also owns clause extraction + clause diffing (shared by the eval harness and
the no-clobber refine flow).
"""
from __future__ import annotations

from dataclasses import dataclass
import re

_CLASS = re.compile(r'\bpublic\s+(?:final\s+|abstract\s+)?class\s+(\w+)')
# annotation lines for DISPLAY (//@ lines + /*@ ... */ block markers)
_JML_LINE = re.compile(r'^\s*//@|^\s*/\*@|^\s*\*@|\*@\s*/|^\s*//')
_TOKEN = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
    r'\\[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*|'
    r'0[xX][0-9A-Fa-f_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?[A-Za-z]*|'
    r'<==>|==>|<==|<=|>=|==|!=|&&|\|\||\+\+|--|<<|>>>|>>|::|->|'
    r'[^\s]')
_STATEMENT_PREFIX = re.compile(
    r"^(?:also\s+)?(?:(?:public|protected|private)\s+)?"
    r"(?:(?:also|behavior|normal_behavior|exceptional_behavior)\s+)*"
    r"(requires|ensures|invariant|assignable|signals|loop_invariant|decreases|"
    r"represents|accessible|measured_by|assert|assume|constraint|diverges|when|"
    r"loop_assignable|loop_modifies|maintaining|decreasing|modifiable|modifies)\b",
    re.I,
)
_BEHAVIOR_HEADER = re.compile(
    r"^(?:also|(?:also\s+)?(?:(?:public|protected|private)\s+)?"
    r"(?:behavior|normal_behavior|exceptional_behavior))$",
    re.I,
)
_IGNORED_ANNOTATION = re.compile(
    r"^(?:(?:public|protected|private)\s+)?"
    r"(?:spec_public|spec_protected|pure|helper|model|ghost)$",
    re.I,
)
_SEMANTIC_MODIFIER = re.compile(
    r"^(?:(?:public|protected|private)\s+)?"
    r"(?P<modifier>nullable|non_null|nullable_by_default|non_null_by_default)$",
    re.I,
)
_JAVA_UNICODE_ESCAPE = re.compile(r"\\u+[0-9A-Fa-f]{4}")


@dataclass(frozen=True)
class JMLStatement:
    offset: int
    text: str
    keyword: str


class JMLParseError(ValueError):
    """Raised when an active JML annotation is outside the supported grammar."""


def class_name(stub: str):
    """Public class name, used to name the .java file (javac/openjml requires the match)."""
    m = _CLASS.search(java_code_mask(stub))
    return m.group(1) if m else None


def java_code_mask(source: str) -> str:
    """Mask literals and every comment while preserving source offsets/newlines."""
    output = list(source)
    index = 0
    while index < len(source):
        if source.startswith('"""', index):
            end = source.find('"""', index + 3)
            end = len(source) if end < 0 else end + 3
            _mask_range(output, source, index, end)
            index = end
        elif source[index] in {'"', "'"}:
            quote = source[index]
            end = _quoted_end(source, index, quote)
            _mask_range(output, source, index, end)
            index = end
        elif source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = len(source) if end < 0 else end
            _mask_range(output, source, index, end)
            index = end
        elif source.startswith("/*", index):
            closing = source.find("*/", index + 2)
            end = len(source) if closing < 0 else closing + 2
            _mask_range(output, source, index, end)
            index = end
        else:
            index += 1
    return "".join(output)


def _mask_range(output: list[str], source: str, start: int, end: int) -> None:
    for position in range(start, end):
        if source[position] not in "\r\n":
            output[position] = " "


def _quoted_end(source: str, start: int, quote: str) -> int:
    index = start + 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
        elif source[index] == quote:
            return index + 1
        else:
            index += 1
    return len(source)


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
    """Canonicalize layout while preserving every semantic token.

    JML identifiers and Java string/character literals are case-sensitive.  In
    particular, lower-casing a clause can turn a contract about ``"Admin"``
    into one about ``"admin"``.  Token-based whitespace normalization accepts
    harmless formatting changes without rewriting identifier or literal data.
    """
    tokens = _TOKEN.findall(clause.strip())
    while tokens and tokens[-1] == ";":
        tokens.pop()
    return " ".join(tokens)


def extract_clauses(stub: str):
    """Return supported active JML statements, ignoring unsupported annotations.

    Trust-boundary callers use :func:`extract_clause_records`, which is strict.
    This compatibility helper remains best-effort for display and lint flows.
    """
    return [record.text for record in parse_jml_statements(stub, strict=False)]


def extract_clause_records(stub: str) -> list[tuple[int, str]]:
    """Return strict ``(source_offset, statement)`` records for comparison.

    Offsets let callers bind method contracts to the declaration they govern
    and distinguish class invariants from annotations inside method bodies.
    """
    return [(record.offset, record.text)
            for record in parse_jml_statements(stub, strict=True)]


def parse_jml_statements(source: str, *, strict: bool = True) -> list[JMLStatement]:
    """Lex active JML comments and classify each top-level statement.

    Ordinary Java comments and literals are skipped before looking for JML
    markers. Semicolons inside parentheses (notably quantifiers) and literals
    do not split statements.
    """
    unicode_escape = _JAVA_UNICODE_ESCAPE.search(source)
    if strict and unicode_escape:
        # Java translates eligible Unicode escapes before recognizing tokens
        # and comments.  This scanner deliberately operates on source text, so
        # accepting escape-bearing input could make it disagree with javac or
        # OpenJML about where an annotation begins.  Reject the whole lexical
        # feature until that translation can be implemented with source maps.
        raise JMLParseError(
            "Java Unicode escapes are unsupported at the contract boundary "
            f"(offset {unicode_escape.start()})")

    records: list[JMLStatement] = []
    for offset, body in _active_jml_annotations(source):
        for relative, raw_statement in _split_statements(body):
            normalized = normalize_clause(raw_statement)
            if not normalized:
                continue
            prefix = _STATEMENT_PREFIX.match(normalized)
            if prefix:
                records.append(JMLStatement(offset + relative, normalized,
                                            prefix.group(1).lower()))
            elif _BEHAVIOR_HEADER.fullmatch(normalized):
                records.append(JMLStatement(offset + relative, normalized, "behavior"))
            elif semantic := _SEMANTIC_MODIFIER.fullmatch(normalized):
                records.append(JMLStatement(offset + relative, normalized,
                                            semantic.group("modifier").lower()))
            elif _IGNORED_ANNOTATION.fullmatch(normalized):
                continue
            elif strict:
                raise JMLParseError(
                    f"unsupported active JML statement at offset {offset + relative}: "
                    f"{normalized[:120]}")
    return sorted(records, key=lambda record: record.offset)


def _active_jml_annotations(source: str) -> list[tuple[int, str]]:
    annotations: list[tuple[int, str]] = []
    index = 0
    while index < len(source):
        if source.startswith('"""', index):
            closing = source.find('"""', index + 3)
            index = len(source) if closing < 0 else closing + 3
        elif source[index] in {'"', "'"}:
            index = _quoted_end(source, index, source[index])
        elif source.startswith("//@", index):
            end = source.find("\n", index + 3)
            end = len(source) if end < 0 else end
            annotations.append((index, source[index + 3:end]))
            index = end
        elif source.startswith("//", index):
            end = source.find("\n", index + 2)
            index = len(source) if end < 0 else end
        elif source.startswith("/*@", index):
            closing = source.find("*/", index + 3)
            if closing < 0:
                raise JMLParseError(f"unterminated JML block annotation at offset {index}")
            body = source[index + 3:closing]
            if body.rstrip().endswith("@"):
                body = body.rstrip()[:-1]
            annotations.append((index, _strip_block_decoration(body)))
            index = closing + 2
        elif source.startswith("/*", index):
            closing = source.find("*/", index + 2)
            if closing < 0:
                raise JMLParseError(f"unterminated Java block comment at offset {index}")
            index = closing + 2
        else:
            index += 1
    return annotations


def _strip_block_decoration(body: str) -> str:
    return re.sub(r"(?m)^(\s*)\*?\s*@?\s?", r"\1", body)


def _split_statements(body: str) -> list[tuple[int, str]]:
    statements: list[tuple[int, str]] = []
    start = 0
    depth = 0
    index = 0
    quote = ""
    while index < len(body):
        char = body[index]
        if quote:
            if char == "\\":
                index += 1
            elif char == quote:
                quote = ""
        elif char in {'"', "'"}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        elif char == ";" and depth == 0:
            statements.append((start, body[start:index + 1]))
            start = index + 1
        index += 1
    if body[start:].strip():
        statements.append((start, body[start:]))
    return statements


def clause_diff(a: str, b: str):
    """Clause-level diff of two stubs by normalized clause text."""
    sa, sb = set(extract_clauses(a)), set(extract_clauses(b))
    return {"added": sorted(sb - sa), "removed": sorted(sa - sb), "common": sorted(sa & sb)}


def contains_clause(stub: str, clause: str) -> bool:
    """True if `clause` is present in `stub` (normalized comparison)."""
    return normalize_clause(clause) in set(extract_clauses(stub))
