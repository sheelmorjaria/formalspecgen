# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Authoritative structural Java/JML contract representation."""
from __future__ import annotations

from collections import Counter
import json
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
_SEMANTIC_MODIFIERS = {
    "nullable", "non_null", "nullable_by_default", "non_null_by_default",
    "pure", "helper", "spec_public", "spec_protected", "model", "ghost",
}
_CONTRACT_JAVA_ANNOTATIONS = {
    "pure", "nullable", "nonnull", "nullablebydefault", "nonnullbydefault",
    "helper", "specpublic", "specprotected", "model", "ghost",
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
                "name": (match.group("name") if kind == "method" else cname),
                "line": _line_number(code, match.start("declaration")),
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

    declaration_issues, compilation_unit, class_declaration = _declaration_analysis(
        code, cname, method_matches, constructor_matches, fields)

    surface: dict[str, Any] = {
        "class": cname,
        "context": _compilation_context(compilation_unit, class_declaration, cname),
        "methods": sorted(item["signature"] for item in members
                          if item["included"] and item["kind"] == "method"),
        "constructors": sorted(item["signature"] for item in members
                               if item["included"] and item["kind"] == "constructor"),
        "fields": [],
        "clauses": {"class": [], "members": {}},
        "semantic_modifiers": {"class": [], "members": {}, "fields": {}},
        "java_annotations": {"class": [], "members": {}, "fields": {}},
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
    surface["java_annotations"]["members"] = {
        item["signature"]: [] for item in included
    }
    _add_java_annotations(
        surface, class_declaration, members, fields, code, public_only)
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
        if record.keyword in _SEMANTIC_MODIFIERS:
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
    for collection in ("semantic_modifiers", "java_annotations"):
        for scope in ("members", "fields"):
            surface[collection][scope] = {
                key: values
                for key, values in sorted(surface[collection][scope].items())
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
        if not public_only or observable or name in referenced or
        value in surface["semantic_modifiers"]["fields"])
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
                any(modifiers.get("fields", {}).values()) or
                _has_contract_java_annotation(surface.get("java_annotations", {})))


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


def _declaration_analysis(
        code: str,
        class_name: str | None,
        method_matches: list[re.Match[str]],
        constructor_matches: list[re.Match[str]],
        fields: list[tuple[int, int, str, bool, str]],
        ) -> tuple[list[str], Any | None, Any | None]:
    """Cross-check every represented member against a structural Java parse.

    Regexes remain useful for preserving source offsets and JML ownership, but
    a failed regex match must never mean that a declaration silently vanished.
    The AST is therefore an independent completeness oracle for the deliberately
    supported Java subset.
    """
    if not class_name or jml_io._JAVA_UNICODE_ESCAPE.search(code):
        return [], None, None
    try:
        tree = javalang.parse.parse(code)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError,
            TypeError) as exc:
        detail = str(exc).strip() or type(exc).__name__
        return [f"unsupported Java syntax at contract boundary: {detail}"], None, None

    declaration = next(
        (item for item in tree.types
         if isinstance(item, javalang.tree.ClassDeclaration) and
         item.name == class_name),
        None,
    )
    if declaration is None:
        return ([f"public class {class_name} was not represented by the Java parser"],
                tree, None)

    additional_types = [item.name for item in tree.types if item is not declaration]
    nested_types = [item.name for item in declaration.body
                    if isinstance(item, javalang.tree.TypeDeclaration)]
    issues = []
    if additional_types:
        issues.append(
            "additional top-level Java types are unsupported at the contract "
            f"boundary: {', '.join(sorted(additional_types))}")
    if nested_types:
        issues.append(
            "nested Java type declarations are unsupported at the contract "
            f"boundary: {', '.join(sorted(nested_types))}")

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
    return issues, tree, declaration


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _format_declarations(declarations: Counter[tuple[str, int]]) -> str:
    values = []
    for (name, line), count in sorted(declarations.items()):
        values.extend([f"{name}@{line}"] * count)
    return ",".join(values)


def _compilation_context(compilation_unit: Any | None,
                         declaration: Any | None,
                         class_name: str | None) -> dict[str, Any]:
    """Return the name-resolution and class-header context of the contract."""
    package_name = ""
    package_annotations: list[str] = []
    imports: list[str] = []
    if compilation_unit is not None:
        package = compilation_unit.package
        if package is not None:
            package_name = package.name
            package_annotations = sorted(
                _annotation_signature(item) for item in (package.annotations or []))
        imports = sorted(
            ("static " if item.static else "") + item.path +
            (".*" if item.wildcard else "")
            for item in compilation_unit.imports)

    identity = ".".join(part for part in (package_name, class_name or "") if part)
    type_context = {
        "identity": identity,
        "modifiers": [],
        "type_parameters": [],
        "extends": None,
        "implements": [],
        "annotations": [],
    }
    if declaration is not None:
        type_context.update({
            "modifiers": sorted(declaration.modifiers or []),
            "type_parameters": _ast_projection(declaration.type_parameters or []),
            "extends": _ast_projection(declaration.extends),
            "implements": _ast_projection(declaration.implements or []),
            "annotations": sorted(
                _annotation_signature(item) for item in declaration.annotations),
        })
    return {
        "package": package_name,
        "package_annotations": package_annotations,
        "imports": imports,
        "type": type_context,
    }


def _ast_projection(value: Any) -> Any:
    """Convert the relevant javalang AST value into stable JSON data."""
    if isinstance(value, javalang.ast.Node):
        return {
            "node": type(value).__name__,
            **{attribute: _ast_projection(getattr(value, attribute))
               for attribute in value.attrs if attribute != "documentation"},
        }
    if isinstance(value, (list, tuple)):
        return [_ast_projection(item) for item in value]
    return value


def _annotation_signature(annotation: Any) -> str:
    return json.dumps(
        {"name": annotation.name, "element": _ast_projection(annotation.element)},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _add_java_annotations(
        surface: dict[str, Any],
        declaration: Any | None,
        members: list[dict[str, Any]],
        fields: list[tuple[int, int, str, bool, str]],
        source: str,
        public_only: bool) -> None:
    """Bind Java annotation syntax to the declaration it modifies."""
    if declaration is None:
        return
    target = surface["java_annotations"]
    target["class"] = sorted(
        _annotation_signature(item) for item in declaration.annotations)

    ast_members = [
        *(('method', item) for item in declaration.methods),
        *(('constructor', item) for item in declaration.constructors),
    ]
    for kind, ast_member in ast_members:
        owner = next(
            (item for item in members
             if item["kind"] == kind and item["name"] == ast_member.name and
             item["line"] == ast_member.position.line),
            None,
        )
        public_spec = any(_annotation_is_public_spec(item)
                          for item in ast_member.annotations)
        if owner is not None and (owner["included"] or public_spec) and \
                ast_member.annotations:
            target["members"].setdefault(owner["signature"], []).extend(sorted(
                _annotation_signature(item) for item in ast_member.annotations))

    for ast_field in declaration.fields:
        signatures = sorted(_annotation_signature(item)
                            for item in ast_field.annotations)
        if not signatures:
            continue
        for declarator in ast_field.declarators:
            owner = next(
                (item for item in fields
                 if item[4] == declarator.name and
                 _line_number(source, item[0]) == ast_field.position.line),
                None,
            )
            public_spec = any(_annotation_is_public_spec(item)
                              for item in ast_field.annotations)
            if owner is not None and (not public_only or owner[3] or public_spec):
                target["fields"].setdefault(owner[2], []).extend(signatures)


def _has_contract_java_annotation(annotations: dict[str, Any]) -> bool:
    values = [
        *annotations.get("class", []),
        *(item for group in annotations.get("members", {}).values() for item in group),
        *(item for group in annotations.get("fields", {}).values() for item in group),
    ]
    for value in values:
        name = json.loads(value).get("name", "").rsplit(".", 1)[-1]
        if name.replace("_", "").lower() in _CONTRACT_JAVA_ANNOTATIONS:
            return True
    return False


def _annotation_is_public_spec(annotation: Any) -> bool:
    name = annotation.name.rsplit(".", 1)[-1].replace("_", "").lower()
    return name in {"specpublic", "specprotected"}


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
        if owner["included"] or record.keyword in {"spec_public", "spec_protected"}:
            modifiers["members"].setdefault(owner["signature"], []).append(record.text)
        return
    if declaration_field is not None:
        _, _, signature, observable, _ = declaration_field
        if (not public_only or observable or
                record.keyword in {"spec_public", "spec_protected"}):
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
        if (following_member["included"] or
                record.keyword in {"spec_public", "spec_protected"}):
            modifiers["members"].setdefault(
                following_member["signature"], []).append(record.text)
    elif following_field is not None:
        _, _, signature, observable, _ = following_field
        if (not public_only or observable or
                record.keyword in {"spec_public", "spec_protected"}):
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
