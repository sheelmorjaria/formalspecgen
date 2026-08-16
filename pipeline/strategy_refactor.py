"""Narrow deterministic Strategy extraction: literal parameter-dispatch to polymorphism.

Admitted shape (everything else fails closed): one public/protected void method
with a single ``int`` parameter, whose body is solely an if/else-if chain of
``param == <literal>`` conditions, each branch assigning the same int field one
integer literal, and a leading JML contract containing ``ensures <field> >= <k>``.
The transform emits a strategy interface (with a static total selector and the
translated ``\\result`` contract), one constant implementation per branch, and a
primary that selects then delegates — the multifile refactor gate must still
prove contract preservation.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import javalang

from .deterministic_refactor import (
    _fail,
    _leading_jml_contract,
    _mask_non_code,
    _matching_brace,
    source_file_name,
)

_BRANCH = re.compile(
    r"if\s*\(\s*(?:this\.)?(?P<param>\w+)\s*==\s*(?P<value>-?\d+)\s*\)\s*\{"
    r"(?P<body>[^{}]*)\}")
_ASSIGNMENT = re.compile(
    r"^\s*(?:this\.)?(?P<field>\w+)\s*=\s*(?P<price>-?\d+)\s*;\s*"
    r"(?://\s*(?P<label>[A-Za-z_]\w*)\s*)?$")
_ENSURES = re.compile(r"ensures\s+(?:this\.)?(?P<field>\w+)\s*>=\s*(?P<bound>-?\d+)\s*;")
_REQUIRES_LINE = re.compile(r"^\s*//@\s*(requires[^;]*;)")


def _method_span(source: str, method):
    """Return (declaration_start, opening_brace, closing_brace) character offsets."""
    lines = source.splitlines(keepends=True)
    start = sum(len(line) for line in lines[:method.position.line - 1])
    masked = _mask_non_code(source)
    opening = masked.find("{", start)
    return start, opening, _matching_brace(masked, opening)


def _strategy_files(source: str, method) -> dict[str, str]:
    if method.return_type is not None or method.body is None:
        raise ValueError("Strategy method must be void with a concrete body")
    if len(method.parameters) != 1 or method.parameters[0].type.name != "int":
        raise ValueError("Strategy method must take exactly one int parameter")
    parameter = method.parameters[0].name
    declaration_start, opening, closing = _method_span(source, method)
    body = source[opening + 1:closing]
    contract = _leading_jml_contract(source, declaration_start)

    branches = list(_BRANCH.finditer(body))
    covered = "".join(match.group(0) for match in branches)
    normalize = lambda text: re.sub(r"\s+", "", re.sub(r"\belse\b", "", text))
    if not branches or normalize(covered) != normalize(body):
        raise ValueError("method body must consist solely of literal-equality branches")
    parsed, fields, values, labels = [], set(), set(), []
    for match in branches:
        assignment = _ASSIGNMENT.match(match.group("body").strip())
        if assignment is None or match.group("param") != parameter:
            raise ValueError("each branch must assign one int literal to the same field")
        parsed.append({"value": int(match.group("value")),
                       "field": assignment.group("field"),
                       "price": int(assignment.group("price")),
                       "label": assignment.group("label")})
        fields.add(assignment.group("field"))
        values.add(int(match.group("value")))
    if len(fields) != 1 or len(values) != len(parsed):
        raise ValueError("branches must target one field with distinct literals")
    if len(parsed) < 2:
        raise ValueError("Strategy requires two or more branches")
    field = parsed[0]["field"]

    ensures = _ENSURES.search(contract)
    if ensures is None or ensures.group("field") != field:
        raise ValueError("method contract must include ensures <field> >= <constant>")
    bound = int(ensures.group("bound"))
    for item in parsed:
        if item["price"] < bound:
            raise ValueError("branch literal violates the ensured lower bound")
    requires = [match.group(1) for match in
                (_REQUIRES_LINE.search(line) for line in contract.splitlines()) if match]
    if not requires:
        raise ValueError("method contract must carry at least one requires clause")

    interface = f"{field.capitalize()}Strategy"
    names = []
    for item in parsed:
        stem = item["label"].capitalize() if item["label"] else (
            f"Branch{str(item['value']).replace('-', 'Minus')}")
        names.append(f"{stem}{field.capitalize()}")
    if len(set(names)) != len(names):
        raise ValueError("branch labels collide")

    selector_lines = [f"        if ({parameter} == {item['value']}) {{ return new {name}(); }}"
                      for item, name in zip(parsed, names)]
    selector_name = f"for{parameter[0].upper()}{parameter[1:]}"
    interface_source = (
        f"public interface {interface} {{\n\n"
        f"    //@ ensures \\result >= {bound};\n"
        f"    int calculate();\n\n"
        + "".join(f"    //@ {clause}\n" for clause in requires)
        + f"    static {interface} {selector_name}(int {parameter}) {{\n"
        + "\n".join(selector_lines) + "\n"
        + f"        throw new IllegalArgumentException(\"unsupported {parameter}: \" + {parameter});\n"
        + "    }\n}\n")
    files = {f"{interface}.java": interface_source}
    for item, name in zip(parsed, names):
        files[f"{name}.java"] = (
            f"public class {name} implements {interface} {{\n\n"
            f"    //@ ensures \\result == {item['price']};\n"
            f"    public int calculate() {{ return {item['price']}; }}\n}}\n")

    primary_body = (f"\n        {interface} strategy = {interface}.{selector_name}({parameter});\n"
                    f"        {field} = strategy.calculate();\n    ")
    primary = source[:opening + 1] + primary_body + source[closing:]
    files[source_file_name(source)] = primary
    return files


def extract_strategy_from_inspection(source_path: str | Path, inspection_path: str | Path,
                                     method_name: str) -> dict:
    """Extract a literal parameter-dispatch chain into Strategy polymorphism."""
    source_file, evidence_file = Path(source_path), Path(inspection_path)
    try:
        source = source_file.read_text(encoding="utf-8")
        evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        return _fail("input_unavailable", str(exc))
    digest = hashlib.sha256(source.encode()).hexdigest()
    finding = next((item for item in evidence.get("findings", [])
                    if item.get("code") == "type-switch" and
                    method_name in item.get("methods", [])), None)
    if (evidence.get("status") != "INSPECTED" or evidence.get("claim") != "STATIC_INSPECTION" or
            evidence.get("source_sha256") != digest or finding is None):
        return _fail("inspection_binding_mismatch", "A hash-bound type-switch finding is required")
    try:
        tree = javalang.parse.parse(source)
        method = next(node for _, node in tree.filter(javalang.tree.MethodDeclaration)
                      if node.name == method_name)
        if not ({"public", "protected"} & set(method.modifiers)):
            raise ValueError("Strategy method must be public or protected")
        files = _strategy_files(source, method)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError, TypeError) as exc:
        return _fail("unsupported_java_syntax", str(exc))
    except (StopIteration, ValueError) as exc:
        return _fail("unsupported_strategy_shape", str(exc))
    return {"status": "TRANSFORMED", "claim": "DETERMINISTIC_MULTIFILE_REFACTOR_CANDIDATE",
            "pattern": "Strategy", "method": method_name, "source_sha256": digest,
            "files": files, "formal_preservation_proved": False,
            "requires_multifile_refactor_gate": True,
            "heap_topology_equivalence_proved": False}
