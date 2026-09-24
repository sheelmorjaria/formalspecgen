# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Authoritative structural Java/JML contract representation."""
from __future__ import annotations

import re
from typing import Any

from . import jml_io


_METHOD = re.compile(
    r"(?m)^[ \t]*(?P<declaration>(?:public|protected|private)\s+"
    r"(?:(?:static|final|synchronized|abstract|native|strictfp|default)\s+)*"
    r"(?:<[^;{}()]+>\s+)?[\w.$<>\[\],?]+\s+[A-Za-z_$][\w$]*\s*"
    r"\([^;{}]*\)(?:\s+throws\s+[^;{]+)?)[ \t]*(?P<terminator>[;{])")
_FIELD = re.compile(
    r"(?m)^[ \t]*(?:public|protected|private)\s+"
    r"(?:(?:static|final|volatile|transient)\s+)*"
    r"[\w.$<>\[\], ?]+\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?:=[^;]*)?;")
_CLASS_CLAUSES = {"invariant", "constraint", "represents", "accessible"}
_PROOF_ONLY = {"loop_invariant", "loop_assignable", "loop_modifies",
               "maintaining", "decreases", "decreasing", "assert"}


def contract_surface(code: str, *, public_only: bool = False) -> dict[str, Any]:
    """Build a method-bound contract surface from lexically active JML.

    ``public_only`` excludes private helper APIs and their ordinary contracts,
    while retaining assumptions from private bodies because those facts can
    still influence a proof of the public wrapper.
    """
    masked = jml_io.java_code_mask(code)
    cname = jml_io.class_name(code)
    method_matches = list(_METHOD.finditer(masked))
    constructor_matches = [] if not cname else list(re.finditer(
        rf"(?m)^[ \t]*(?P<declaration>(?:public|protected|private)\s+"
        rf"{re.escape(cname)}\s*\([^;{{}}]*\)(?:\s+throws\s+[^;{{]+)?)"
        rf"[ \t]*(?P<terminator>[;{{])",
        masked,
    ))
    members: list[dict[str, Any]] = []
    for kind, matches in (("method", method_matches),
                          ("constructor", constructor_matches)):
        for match in matches:
            terminator = match.group("terminator")
            opening = match.start("terminator") if terminator == "{" else -1
            declaration = code[match.start("declaration"):match.end("declaration")]
            signature = _normalized_declaration(declaration)
            visibility = _visibility(signature)
            members.append({
                "kind": kind,
                "start": match.start("declaration"),
                "open": opening,
                "close": _matching_brace(masked, opening) if opening >= 0 else -1,
                "signature": signature,
                "included": not public_only or visibility in {"public", "protected"},
            })
    members.sort(key=lambda item: item["start"])

    fields = []
    for match in _FIELD.finditer(masked):
        declaration = code[match.start():match.end()]
        normalized = _normalized_declaration(declaration)
        fields.append((match.start(), normalized,
                       _field_is_public_contract(declaration), match.group("name")))

    surface: dict[str, Any] = {
        "class": cname,
        "methods": sorted(item["signature"] for item in members
                          if item["included"] and item["kind"] == "method"),
        "constructors": sorted(item["signature"] for item in members
                               if item["included"] and item["kind"] == "constructor"),
        "fields": [],
        "clauses": {"class": [], "members": {}},
        "private_assumptions": {},
        "parse_errors": [],
    }
    included = [item for item in members if item["included"]]
    surface["clauses"]["members"] = {
        item["signature"]: [] for item in included
    }
    try:
        records = jml_io.parse_jml_statements(code, strict=True)
    except jml_io.JMLParseError as exc:
        surface["fields"] = sorted(value for _, value, observable, _ in fields
                                   if not public_only or observable)
        surface["parse_errors"] = [str(exc)]
        return surface

    for record in records:
        containing = next((item for item in members
                           if item["open"] >= 0 and
                           item["open"] < record.offset < item["close"]), None)
        if containing is not None:
            if record.keyword == "assume":
                target = (surface["clauses"]["members"] if containing["included"]
                          else surface["private_assumptions"])
                target.setdefault(containing["signature"], []).append(record.text)
            # Assertions, loop invariants, and termination measures are proof
            # obligations rather than reviewed assumptions.
            continue
        if record.keyword in _PROOF_ONLY:
            continue
        if record.keyword in _CLASS_CLAUSES:
            surface["clauses"]["class"].append(record.text)
            continue
        following = next((item for item in members if item["start"] > record.offset), None)
        intervening_field = next((offset for offset, _, _, _ in fields
                                  if offset > record.offset), None)
        if following is not None and (intervening_field is None or
                                      following["start"] < intervening_field):
            if following["included"]:
                surface["clauses"]["members"][following["signature"]].append(record.text)
            elif record.keyword == "assume":
                surface["private_assumptions"].setdefault(
                    following["signature"], []).append(record.text)
        else:
            surface["clauses"]["class"].append(record.text)

    surface["clauses"]["members"] = {
        key: surface["clauses"]["members"][key]
        for key in sorted(surface["clauses"]["members"])
    }
    surface["private_assumptions"] = {
        key: surface["private_assumptions"][key]
        for key in sorted(surface["private_assumptions"])
    }
    referenced = {
        token
        for text in [*surface["clauses"]["class"],
                     *(clause for values in surface["clauses"]["members"].values()
                       for clause in values),
                     *(clause for values in surface["private_assumptions"].values()
                       for clause in values)]
        for token in jml_io._TOKEN.findall(text)
    }
    surface["fields"] = sorted(
        value for _, value, observable, name in fields
        if not public_only or observable or name in referenced)
    return surface


def surface_differences(expected: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    return {key: {"expected": expected[key], "actual": actual[key]}
            for key in expected if expected[key] != actual.get(key)}


def has_reviewed_contract(surface: dict[str, Any]) -> bool:
    clauses = surface.get("clauses", {})
    return bool(clauses.get("class") or
                any(clauses.get("members", {}).values()) or
                surface.get("private_assumptions"))


def _normalized_declaration(value: str) -> str:
    value = value.strip()
    if value.endswith("{"):
        value = value[:-1]
    return " ".join(jml_io._TOKEN.findall(value.strip()))


def _visibility(declaration: str) -> str:
    match = re.match(r"^(public|protected|private)\b", declaration)
    return match.group(1) if match else ""


def _field_is_public_contract(declaration: str) -> bool:
    normalized = _normalized_declaration(declaration)
    return _visibility(normalized) in {"public", "protected"} or bool(
        re.search(r"/\*@\s*spec_(?:public|protected)\s*@\*/", declaration, re.I))


def _matching_brace(masked: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(masked)
