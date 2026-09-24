# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Authoritative structural Java/JML contract representation."""
from __future__ import annotations

from collections import Counter
import re
from typing import Any

import javalang

from . import jml_io


_METHOD = re.compile(
    r"(?m)(?:^[ \t]*|(?<=[{};])[ \t]*)(?P<declaration>(?:public|protected|private)\s+"
    r"(?:(?:static|final|synchronized|abstract|native|strictfp|default)\s+)*"
    r"(?:<[^;{}()]+>\s+)?[\w.$<>\[\],?]+\s+(?P<name>[A-Za-z_$][\w$]*)\s*"
    r"\([^;{}]*\)(?:\s+throws\s+[^;{]+)?)\s*(?P<terminator>[;{])")
_FIELD = re.compile(
    r"(?m)(?:^[ \t]*|(?<=[{};])[ \t]*)(?:public|protected|private)\s+"
    r"(?:(?:static|final|volatile|transient)\s+)*"
    r"[\w.$<>\[\], ?]+\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?:=[^;]*)?;")
_CLASS_CLAUSES = {"invariant", "constraint", "represents", "accessible"}
_PROOF_ONLY = {"loop_invariant", "loop_assignable", "loop_modifies",
               "maintaining", "decreases", "decreasing", "assert"}
_NULLNESS_MODIFIERS = {
    "nullable", "non_null", "nullable_by_default", "non_null_by_default",
}


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
        rf"(?m)(?:^[ \t]*|(?<=[{{}};])[ \t]*)"
        rf"(?P<declaration>(?:public|protected|private)\s+"
        rf"{re.escape(cname)}\s*\([^;{{}}]*\)(?:\s+throws\s+[^;{{]+)?)"
        rf"\s*(?P<terminator>[;{{])",
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
                "end": match.end("declaration"),
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
        fields.append((match.start(), match.end(), normalized,
                       _field_is_public_contract(declaration), match.group("name")))

    declaration_issues = _declaration_completeness_issues(
        code, cname, method_matches, constructor_matches, fields)

    surface: dict[str, Any] = {
        "class": cname,
        "methods": sorted(item["signature"] for item in members
                          if item["included"] and item["kind"] == "method"),
        "constructors": sorted(item["signature"] for item in members
                               if item["included"] and item["kind"] == "constructor"),
        "fields": [],
        "clauses": {"class": [], "members": {}},
        "semantic_modifiers": {"class": [], "members": {}, "fields": {}},
        "private_assumptions": {},
        "parse_errors": declaration_issues,
    }
    included = [item for item in members if item["included"]]
    surface["clauses"]["members"] = {
        item["signature"]: [] for item in included
    }
    surface["semantic_modifiers"]["members"] = {
        item["signature"]: [] for item in included
    }
    try:
        records = jml_io.parse_jml_statements(code, strict=True)
    except jml_io.JMLParseError as exc:
        surface["fields"] = sorted(value for _, _, value, observable, _ in fields
                                   if not public_only or observable)
        surface["parse_errors"].append(str(exc))
        return surface

    for record in records:
        declaration_owner = next((item for item in members
                                  if item["start"] <= record.offset < item["end"]), None)
        declaration_field = next((field for field in fields
                                  if field[0] <= record.offset < field[1]), None)
        containing = next((item for item in members
                           if item["open"] >= 0 and
                           item["open"] < record.offset < item["close"]), None)
        if record.keyword in _NULLNESS_MODIFIERS:
            _place_semantic_modifier(
                surface, record, members, fields, declaration_owner,
                declaration_field, containing, masked, cname, public_only)
            continue
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
        intervening_field = next((offset for offset, _, _, _, _ in fields
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
    for scope in ("members", "fields"):
        surface["semantic_modifiers"][scope] = {
            key: values
            for key, values in sorted(surface["semantic_modifiers"][scope].items())
            if values
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
        value for _, _, value, observable, name in fields
        if not public_only or observable or name in referenced)
    return surface


def surface_differences(expected: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    return {key: {"expected": expected[key], "actual": actual[key]}
            for key in expected if expected[key] != actual.get(key)}


def has_reviewed_contract(surface: dict[str, Any]) -> bool:
    clauses = surface.get("clauses", {})
    modifiers = surface.get("semantic_modifiers", {})
    return bool(clauses.get("class") or
                any(clauses.get("members", {}).values()) or
                surface.get("private_assumptions") or
                modifiers.get("class") or
                any(modifiers.get("members", {}).values()) or
                any(modifiers.get("fields", {}).values()))


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


def _declaration_completeness_issues(
        code: str,
        class_name: str | None,
        method_matches: list[re.Match[str]],
        constructor_matches: list[re.Match[str]],
        fields: list[tuple[int, int, str, bool, str]]) -> list[str]:
    """Cross-check every represented member against a structural Java parse.

    Regexes remain useful for preserving source offsets and JML ownership, but
    a failed regex match must never mean that a declaration silently vanished.
    The AST is therefore an independent completeness oracle for the deliberately
    supported Java subset.
    """
    if not class_name or jml_io._JAVA_UNICODE_ESCAPE.search(code):
        return []
    try:
        tree = javalang.parse.parse(code)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError,
            TypeError) as exc:
        detail = str(exc).strip() or type(exc).__name__
        return [f"unsupported Java syntax at contract boundary: {detail}"]

    declaration = next(
        (item for item in tree.types
         if isinstance(item, javalang.tree.ClassDeclaration) and
         item.name == class_name),
        None,
    )
    if declaration is None:
        return [f"public class {class_name} was not represented by the Java parser"]

    nested_types = [item.name for item in declaration.body
                    if isinstance(item, javalang.tree.TypeDeclaration)]
    issues = (["nested Java type declarations are unsupported at the contract "
               f"boundary: {', '.join(sorted(nested_types))}"]
              if nested_types else [])

    ast_members = {
        "methods": Counter((item.name, item.position.line)
                           for item in declaration.methods),
        "constructors": Counter((item.name, item.position.line)
                                for item in declaration.constructors),
        "fields": Counter((declarator.name, item.position.line)
                          for item in declaration.fields
                          for declarator in item.declarators),
    }
    represented = {
        "methods": Counter((match.group("name"), _line_number(code, match.start("declaration")))
                           for match in method_matches),
        "constructors": Counter((class_name,
                                 _line_number(code, match.start("declaration")))
                                for match in constructor_matches),
        "fields": Counter((name, _line_number(code, start))
                          for start, _, _, _, name in fields),
    }
    for kind in ("methods", "constructors", "fields"):
        missing = ast_members[kind] - represented[kind]
        extra = represented[kind] - ast_members[kind]
        if missing or extra:
            details = []
            if missing:
                details.append(f"unrepresented={_format_declarations(missing)}")
            if extra:
                details.append(f"misowned={_format_declarations(extra)}")
            issues.append(
                f"incomplete Java {kind} at contract boundary: {'; '.join(details)}")
    return issues


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _format_declarations(declarations: Counter[tuple[str, int]]) -> str:
    values = []
    for (name, line), count in sorted(declarations.items()):
        values.extend([f"{name}@{line}"] * count)
    return ",".join(values)


def _place_semantic_modifier(
        surface: dict[str, Any],
        record: jml_io.JMLStatement,
        members: list[dict[str, Any]],
        fields: list[tuple[int, int, str, bool, str]],
        declaration_owner: dict[str, Any] | None,
        declaration_field: tuple[int, int, str, bool, str] | None,
        containing: dict[str, Any] | None,
        masked: str,
        class_name: str | None,
        public_only: bool) -> None:
    """Attach a semantic JML modifier to its class, field, or method scope."""
    modifiers = surface["semantic_modifiers"]
    owner = declaration_owner or containing
    if owner is not None:
        if owner["included"]:
            modifiers["members"].setdefault(owner["signature"], []).append(record.text)
        return
    if declaration_field is not None:
        _, _, signature, observable, _ = declaration_field
        if not public_only or observable:
            modifiers["fields"].setdefault(signature, []).append(record.text)
        return

    class_open = -1
    if class_name:
        class_match = re.search(
            rf"\bclass\s+{re.escape(class_name)}\b[^{{]*{{", masked)
        if class_match:
            class_open = class_match.end() - 1
    if class_open < 0 or record.offset < class_open:
        modifiers["class"].append(record.text)
        return

    following_member = next(
        (item for item in members if item["start"] > record.offset), None)
    following_field = next(
        (field for field in fields if field[0] > record.offset), None)
    if following_member is not None and (
            following_field is None or following_member["start"] < following_field[0]):
        if following_member["included"]:
            modifiers["members"].setdefault(
                following_member["signature"], []).append(record.text)
    elif following_field is not None:
        _, _, signature, observable, _ = following_field
        if not public_only or observable:
            modifiers["fields"].setdefault(signature, []).append(record.text)
    else:
        modifiers["class"].append(record.text)


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
