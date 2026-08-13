# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, read-only Java modernization inspection."""
from __future__ import annotations

import hashlib
from pathlib import Path

import javalang


GOD_FIELD_THRESHOLD = 10
GOD_METHOD_THRESHOLD = 15
LONG_METHOD_LINES = 60
CONSTRUCTOR_DEPENDENCY_THRESHOLD = 5

def inspect_java_file(path: str | Path) -> dict:
    source_path = Path(path)
    if source_path.suffix.lower() not in {".java", ".jml"}:
        return _fail("unsupported_language", "Java/JML source is required")
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        return _fail("source_unavailable", str(exc))
    try:
        tree = javalang.parse.parse(source)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError,
            TypeError) as exc:
        return _fail("unsupported_java_syntax", str(exc))
    classes = [declaration for declaration in tree.types
               if isinstance(declaration, javalang.tree.ClassDeclaration)]
    if len(tree.types) != 1 or len(classes) != 1:
        return _fail("unsupported_class_shape", "Exactly one concrete class is required")
    declaration = classes[0]
    class_name = declaration.name
    methods = list(declaration.constructors) + list(declaration.methods)
    fields = list(declaration.fields)
    findings = []

    switches = [node for _, node in declaration.filter(javalang.tree.IfStatement)
                if _runtime_type_condition(node.condition)]
    if len(switches) >= 2:
        findings.append(_finding(_line(switches[0]), "type-switch", "warning",
            f"Found {len(switches)} runtime type-dispatch branches.", "Strategy",
            "Move variant behavior behind a polymorphic strategy interface."))

    if len(fields) >= GOD_FIELD_THRESHOLD and len(methods) >= GOD_METHOD_THRESHOLD:
        findings.append(_finding(_line(declaration), "god-class", "warning",
            f"Class has {len(fields)} fields and {len(methods)} methods.", "Facade",
            "Split cohesive responsibilities, retaining a small façade at the existing boundary."))

    for method in methods:
        lines = _callable_lines(source, method)
        if lines > LONG_METHOD_LINES:
            findings.append(_finding(_line(method), "long-method", "warning",
                f"Method {method.name} spans {lines} lines.", "Extract Method",
                "Extract cohesive steps while preserving the existing JML method contract."))
        parameters = len(method.parameters)
        if (isinstance(method, javalang.tree.ConstructorDeclaration) and
                parameters >= CONSTRUCTOR_DEPENDENCY_THRESHOLD):
            findings.append(_finding(_line(method), "constructor-overinjection", "warning",
                f"Constructor accepts {parameters} dependencies/parameters.", "Facade",
                "Group cohesive collaborators behind narrower role interfaces; review lifetime ownership."))

    return {"status": "INSPECTED", "claim": "STATIC_INSPECTION",
            "scope": "deterministic_token_aware_java_structure_heuristics",
            "parser_mode": "javalang_ast_0.13.0", "source": str(source_path.resolve()),
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "class": class_name, "metrics": {"fields": len(fields), "methods": len(methods)},
            "findings": findings, "automated_refactor_applied": False,
            "formal_defect_proved": False, "behavior_equivalence_proved": False}


def _mask_non_code(source: str) -> str:
    output = list(source); index = 0; state = "code"
    while index < len(source):
        pair = source[index:index + 2]
        char = source[index]
        if state == "code" and pair in {"//", "/*"}:
            state = "line" if pair == "//" else "block"
            output[index] = output[index + 1] = " "; index += 2; continue
        if state == "code" and char in {'"', "'"}:
            state = "string" if char == '"' else "char"; output[index] = " "
        elif state == "line":
            if char == "\n": state = "code"
            else: output[index] = " "
        elif state == "block":
            if pair == "*/":
                output[index] = output[index + 1] = " "; index += 2; state = "code"; continue
            if char != "\n": output[index] = " "
        elif state in {"string", "char"}:
            quote = '"' if state == "string" else "'"
            if char == "\\" and index + 1 < len(source):
                output[index] = output[index + 1] = " "; index += 2; continue
            output[index] = " " if char != "\n" else "\n"
            if char == quote: state = "code"
            elif char == "\n": raise ValueError("unterminated string or character literal")
        index += 1
    if state in {"block", "string", "char"}:
        raise ValueError("unterminated comment or literal")
    return "".join(output)


def _matching_brace(source: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(source)):
        depth += 1 if source[index] == "{" else -1 if source[index] == "}" else 0
        if depth == 0: return index
    return opening


def _runtime_type_condition(condition) -> bool:
    nodes = [condition]
    if isinstance(condition, javalang.ast.Node):
        nodes.extend(node for _, node in condition)
    has_type_member = any(isinstance(node, javalang.tree.MemberReference) and
                          node.member == "type" for node in nodes)
    return any(
        isinstance(node, javalang.tree.BinaryOperation) and
        (node.operator == "instanceof" or (node.operator in {"==", "!="} and has_type_member))
        or isinstance(node, javalang.tree.MethodInvocation) and node.member == "getClass"
        for node in nodes)


def _callable_lines(source: str, method) -> int:
    if method.body is None or method.position is None:
        return 0
    masked = _mask_non_code(source)
    lines = source.splitlines(keepends=True)
    start = sum(len(line) for line in lines[:method.position.line - 1])
    opening = masked.find("{", start)
    if opening < 0:
        return 0
    end = _matching_brace(masked, opening)
    return source.count("\n", start, end) + 1


def _line(node) -> int:
    return node.position.line if node.position is not None else 1


def _finding(line: int, code: str, severity: str, message: str,
             pattern: str, recommendation: str) -> dict:
    return {"line": line, "code": code,
            "severity": severity, "message": message, "suggested_pattern": pattern,
            "recommendation": recommendation}


def _fail(code: str, message: str) -> dict:
    return {"status": "FAIL", "claim": "NO_PROOF", "code": code, "message": message,
            "automated_refactor_applied": False, "formal_defect_proved": False,
            "behavior_equivalence_proved": False}
