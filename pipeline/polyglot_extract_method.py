# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""AST-guided string-splicing extract-method for Rust, C, and C++.

Tree-sitter is a parser, not a pretty-printer: it supplies exact byte
coordinates, and the transformation splices the RAW source so formatting,
comments, and native contracts (Prusti attributes, ACSL blocks, C++
assertions) move verbatim instead of being re-rendered.

Supported boundary (v1): WHOLE-BODY delegation. The helper receives the
original signature (renamed), the original body moves into it untouched,
and the original function becomes a one-line call. Locals move with the
body, so no free-variable analysis is required. C++ supports in-class
method definitions only; out-of-line qualified definitions would need
class-declaration surgery and fail closed.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .polyglot_surface import Language, Parser, _TS_LANGUAGES, language_for

_FUNCTION_NODE = {"rust": "function_item", "c": "function_definition",
                  "cpp": "function_definition"}
_SUFFIX = {"rust": ".rs", "c": ".c", "cpp": ".cpp"}
_POLYGLOT_SUFFIXES = {".rs", ".c", ".cpp", ".cc", ".cxx"}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fail(code: str, message: str) -> dict:
    return {"status": "FAIL", "code": code, "message": message}


def _walk(root):
    stack, nodes = [root], []
    while stack:
        node = stack.pop()
        nodes.append(node)
        for child in node.children:
            stack.append(child)
    return nodes


def _text(source: str, node) -> str:
    return source.encode("utf-8")[node.start_byte:node.end_byte].decode("utf-8")


def _node_name(node, source: str, language: str) -> str | None:
    """The called name of a function node (its declarator, never a parameter)."""
    if language == "rust":
        name = node.child_by_field_name("name")
        return _text(source, name) if name is not None else None
    declarator = _function_declarator(node)
    if declarator is None:
        return None
    inner = declarator.child_by_field_name("declarator")
    while inner is not None and inner.type in {"pointer_declarator", "parenthesized_declarator"}:
        inner = inner.child_by_field_name("declarator")
    if inner is None:
        return None
    if inner.type in {"identifier", "field_identifier"}:
        return _text(source, inner)
    names = [child for child in _walk(inner)
             if child.type in {"identifier", "field_identifier"}]
    return _text(source, max(names, key=lambda child: child.start_byte)) if names else None


def _function_declarator(node):
    """Descend pointer/reference wrappers to the function_declarator."""
    declarator = node.child_by_field_name("declarator")
    while declarator is not None and declarator.type != "function_declarator":
        declarator = declarator.child_by_field_name("declarator")
    return declarator


def _contract_start(node, source: str, language: str) -> int:
    """Byte start of the immediately preceding native-contract run.

    Rust attributes are attribute_item SIBLINGS of the function_item, and
    ACSL blocks are comment nodes beside the C definition — neither is part
    of the function node, so the splice span must be widened explicitly.
    """
    data = source.encode("utf-8")
    start, previous = node.start_byte, node.prev_sibling
    while previous is not None:
        if data[previous.end_byte:start].strip():
            break
        text = data[previous.start_byte:previous.end_byte].decode("utf-8", "replace")
        if language == "rust" and previous.type == "attribute_item":
            start = previous.start_byte
        elif language == "c" and previous.type == "comment" and text.startswith("/*@"):
            start = previous.start_byte
        else:
            break
        previous = previous.prev_sibling
    return start


def locate_function(source: str, language: str, name: str) -> dict:
    """Return the byte coordinates of one function and its preceding contract."""
    if language not in _FUNCTION_NODE:
        return _fail("unsupported_language", f"extract-method supports {sorted(_FUNCTION_NODE)}")
    if Parser is None:
        return _fail("tree_sitter_unavailable",
                     "byte splicing requires the pinned tree-sitter grammars")
    parser = Parser()
    parser.language = Language(_TS_LANGUAGES[_SUFFIX[language]])
    tree = parser.parse(source.encode("utf-8"))
    if tree.root_node.has_error:
        return _fail("source_parse_error", "the source failed to parse")
    matches = [node for node in _walk(tree.root_node)
               if node.type == _FUNCTION_NODE[language]
               and node.child_by_field_name("body") is not None
               and _node_name(node, source, language) == name]
    if not matches:
        return _fail("method_not_found", f"no function body named {name!r} was found")
    if len(matches) > 1:
        return _fail("ambiguous_method",
                     f"{name!r} names more than one function body in this source")
    node = matches[0]
    body = node.child_by_field_name("body")
    declarator = _function_declarator(node)
    parameters = (declarator.child_by_field_name("parameters")
                  if declarator is not None
                  else node.child_by_field_name("parameters"))
    return {"status": "LOCATED", "function_start": node.start_byte,
            "function_end": node.end_byte, "body_start": body.start_byte,
            "body_end": body.end_byte,
            "parameters_start": parameters.start_byte if parameters is not None
            else body.start_byte,
            "parameters_end": parameters.end_byte if parameters is not None
            else body.start_byte,
            "contract_start": _contract_start(node, source, language)}


def _split_parameters(text: str) -> list[str]:
    """Split a parameter list on top-level commas only."""
    parts, depth, current = [], 0, []
    for character in text:
        if character in "([<":
            depth += 1
        elif character in ")]>":
            depth -= 1
        if character == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    parts.append("".join(current).strip())
    return [part for part in parts if part]


def _call_arguments(source: str, located: dict, language: str) -> tuple[list[str], bool]:
    """Argument names for the helper call; self receivers pass as self."""
    parameters = _split_parameters(
        source[located["parameters_start"] + 1:located["parameters_end"] - 1])
    if language == "rust":
        receivers = [item for item in parameters
                     if re.fullmatch(r"&?\s*(?:mut\s+)?self", item)]
        rest = [item for item in parameters if item not in receivers]
        return [item.split(":")[0].strip() for item in rest], bool(receivers)
    arguments = []
    for item in parameters:
        if item == "void":
            continue
        identifiers = re.findall(r"[A-Za-z_]\w*", item)
        if identifiers:
            arguments.append(identifiers[-1])
    return arguments, False


def _returns_value(source: str, located: dict, language: str) -> bool:
    head = source[located["function_start"]:located["parameters_start"]]
    tail = source[located["parameters_end"]:located["body_start"]]
    if language == "rust":
        return "->" in tail and not re.search(r"->\s*\(\s*\)", tail)
    first = re.match(r"\s*(?:static\s+|virtual\s+|inline\s+)*([A-Za-z_]\w*)", head)
    if (first.group(1) if first else "") != "void":
        return True
    return re.search(r"\bvoid\s*\*", head) is not None  # void* returns a value


def extract_method_polyglot(source: str, language: str, name: str) -> dict:
    """Whole-body delegation extract-method via raw byte splicing."""
    located = locate_function(source, language, name)
    if located["status"] != "LOCATED":
        return located
    if language == "cpp":
        # Out-of-line qualified definitions (Counter::add) would need class
        # declaration surgery for the helper; fail closed on that shape.
        head = source[located["function_start"]:located["parameters_start"]]
        if re.search(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)+\s*$", head.strip()):
            return _fail("unsupported_cpp_out_of_line",
                         "the C++ lane supports in-class method definitions only")
    gap = source[located["contract_start"]:located["function_start"]]  # verbatim
    signature = source[located["function_start"]:located["body_start"]].rstrip()
    body = source[located["body_start"]:located["body_end"]]
    helper_name = f"{name}_helper"
    if language == "rust":
        renamed = re.sub(r"\bfn\s+" + re.escape(name) + r"\b",
                         f"fn {helper_name}", signature, count=1)
        # The helper is file-internal: strip visibility so it never widens the
        # public API surface the proof gate binds.
        renamed = re.sub(r"\bpub(?:\([^)]*\))?\s+(?=fn\b)", "", renamed, count=1)
    else:
        renamed = re.sub(r"(?<![A-Za-z0-9_:])" + re.escape(name) + r"\s*\(",
                         f"{helper_name}(", signature, count=1)
        if language == "c" and not re.match(r"\s*static\b", renamed):
            renamed = "static " + renamed
        renamed = renamed.replace(" override", "")
    arguments, has_receiver = _call_arguments(source, located, language)
    call = (f"self.{helper_name}({', '.join(arguments)})" if has_receiver
            else f"{helper_name}({', '.join(arguments)})")
    if _returns_value(source, located, language):
        call_body = (f"{{ {call} }}" if language == "rust"  # tail expression
                     else f"{{ return {call}; }}")
    else:
        call_body = f"{{ {call}; }}"
    helper = gap + renamed + " " + body
    # The span's own line indent lives in the text BEFORE the splice point; the
    # helper inherits it from the prefix, but the wrapper needs it re-applied.
    line_start = source.rfind("\n", 0, located["contract_start"]) + 1
    lead = source[line_start:located["contract_start"]]
    indent = lead if lead.strip() == "" else ""
    wrapper = indent + gap + signature + " " + call_body
    refactored = (source[:located["contract_start"]] + helper + "\n\n" +
                  wrapper + source[located["function_end"]:])
    return {"status": "TRANSFORMED", "source": refactored, "language": language,
            "method": name, "helper_name": helper_name,
            "offsets": {key: located[key] for key in
                        ("contract_start", "function_start", "body_start", "body_end")},
            "baseline_sha256": _sha256(source), "refactored_sha256": _sha256(refactored)}


def apply_extract_method_polyglot(source: str | Path, method: str,
                                  out: str | Path) -> dict:
    """Apply one splice and immediately run the native polyglot proof gate."""
    from .refactor_gate import verify_contract_preserving_refactor

    source_path = Path(source)
    try:
        code = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        return _fail("source_unavailable", str(exc))
    language = language_for(source_path.suffix.lower())
    if source_path.suffix.lower() not in _POLYGLOT_SUFFIXES or language is None:
        return _fail("unsupported_language",
                     "polyglot extract-method supports .rs, .c, .cpp, .cc, .cxx sources")
    transformed = extract_method_polyglot(code, language, method)
    if transformed["status"] != "TRANSFORMED":
        return transformed
    destination = Path(out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(transformed.pop("source"), encoding="utf-8")
    proof = verify_contract_preserving_refactor(source_path, destination)
    return {"status": "VERIFIED" if proof["status"] == "VERIFIED" else "FAIL",
            "claim": proof.get("claim", "NO_PROOF"),
            "transformation": transformed, "verification": proof,
            "automated_refactor_applied": True,
            "behavior_equivalence_proved": False,
            "refactor_verified": False}
