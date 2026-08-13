# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Hash-bound deterministic Java refactoring profiles."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import javalang

from .java_inspection import _mask_non_code, _matching_brace


def extract_method_from_inspection(source_path: str | Path, inspection_path: str | Path,
                                   method_name: str) -> dict:
    source_file, evidence_file = Path(source_path), Path(inspection_path)
    try:
        source = source_file.read_text(encoding="utf-8")
        evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        return _fail("input_unavailable", str(exc))
    digest = hashlib.sha256(source.encode()).hexdigest()
    if (evidence.get("status") != "INSPECTED" or
            evidence.get("claim") != "STATIC_INSPECTION" or
            evidence.get("source_sha256") != digest):
        return _fail("inspection_binding_mismatch",
                     "Inspection must be successful and hash-bound to the source")
    long_lines = {item.get("line") for item in evidence.get("findings", [])
                  if item.get("code") == "long-method"}
    try:
        tree = javalang.parse.parse(source)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError,
            TypeError) as exc:
        return _fail("unsupported_java_syntax", str(exc))
    matches = [node for _, node in tree.filter(javalang.tree.MethodDeclaration)
               if node.name == method_name]
    if len(matches) != 1:
        return _fail("method_not_unique", "Method name must identify exactly one declaration")
    method = matches[0]
    if method.position is None or method.position.line not in long_lines:
        return _fail("method_not_inspected_long",
                     "The hash-bound inspection did not classify this method as long")
    if method.body is None or not ({"public", "protected"} & set(method.modifiers)):
        return _fail("unsupported_method_shape", "Method must be concrete and public/protected")
    helper_name = f"{method_name}Extracted"
    if any(node.name == helper_name for _, node in tree.filter(
            javalang.tree.MethodDeclaration)):
        return _fail("helper_name_collision", f"Method {helper_name} already exists")
    try:
        transformed = _extract(source, method, helper_name)
    except ValueError as exc:
        return _fail("unsupported_method_span", str(exc))
    return {"status": "TRANSFORMED", "claim": "DETERMINISTIC_REFACTOR_CANDIDATE",
            "pattern": "Extract Method", "method": method_name,
            "source_sha256": digest,
            "refactored_sha256": hashlib.sha256(transformed.encode()).hexdigest(),
            "source": transformed, "formal_preservation_proved": False,
            "requires_refactor_gate": True}


def _extract(source: str, method, helper_name: str) -> str:
    lines = source.splitlines(keepends=True)
    start = sum(len(line) for line in lines[:method.position.line - 1])
    masked = _mask_non_code(source)
    opening = masked.find("{", start)
    end = _matching_brace(masked, opening)
    declaration = source[start:opening]
    body = source[opening:end + 1]
    name_match = re.search(rf"\b{re.escape(method.name)}\s*(?=\()", declaration)
    if opening < 0 or end <= opening or name_match is None:
        raise ValueError("AST method span could not be reconstructed")
    indent = re.match(r"[ \t]*", declaration).group(0)
    arguments = ", ".join(parameter.name for parameter in method.parameters)
    call = f"{helper_name}({arguments});"
    if method.return_type is not None:
        call = "return " + call
    wrapper = declaration + "{\n" + indent + "    " + call + "\n" + indent + "}"
    helper_declaration = (declaration[:name_match.start()] + helper_name +
                          declaration[name_match.end():])
    helper_declaration = re.sub(r"\b(?:public|protected)\b", "private",
                                helper_declaration, count=1)
    contracts = _leading_jml_contract(source, start)
    helper = contracts + helper_declaration + body
    return source[:start] + wrapper + "\n\n" + helper + source[end + 1:]


def _leading_jml_contract(source: str, declaration_start: int) -> str:
    prefix = source[:declaration_start]
    lines = prefix.splitlines(keepends=True)
    selected = []
    for line in reversed(lines):
        if line.strip().startswith("//@"):
            selected.append(line); continue
        if not line.strip() and selected:
            continue
        break
    return "".join(reversed(selected))


def _fail(code: str, message: str) -> dict:
    return {"status": "FAIL", "claim": "NO_PROOF", "code": code, "message": message,
            "formal_preservation_proved": False, "requires_refactor_gate": True}
