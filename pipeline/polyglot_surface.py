# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Tree-sitter public-API and contract surfaces for polyglot refactor gating.

`public_api_surface` yields normalized, sorted signature lists (the polyglot
analogue of `refactor_gate.public_method_surface`); `contract_clauses` yields
the normalized native-contract set (Prusti attributes, ACSL blocks, C++
assertion checks) — the analogue of `refactor_gate._public_contract_clauses`.
Both fall back to deterministic regex extraction when the Tree-sitter grammars
are unavailable, mirroring `codebase_analysis`'s optional-import guard.
"""
from __future__ import annotations

import re
from pathlib import Path

try:  # Optional at import time for minimal installations.
    from tree_sitter import Language, Parser
    import tree_sitter_rust, tree_sitter_c, tree_sitter_cpp
except ImportError:  # pragma: no cover - exercised only in minimal environments
    Language = Parser = None

_TS_LANGUAGES = {
    ".rs": tree_sitter_rust.language() if Parser else None,
    ".c": tree_sitter_c.language() if Parser else None,
    ".cpp": tree_sitter_cpp.language() if Parser else None,
    ".cc": tree_sitter_cpp.language() if Parser else None,
    ".cxx": tree_sitter_cpp.language() if Parser else None,
}

_RUST_SIGNATURE = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:const\s+)?fn\s+"
    r"[A-Za-z_]\w*\s*(?:<[^>{;]*>)?\s*\([^;{}]*\)\s*(?:->\s*[^;{]+)?")
_RUST_TRAIT = re.compile(r"(?m)^\s*(?:pub\s+)?trait\s+[A-Za-z_]\w*")
_C_SIGNATURE = re.compile(
    r"(?m)^\s*(?!if\b|for\b|while\b|switch\b)(?:[A-Za-z_]\w*\s+|\*\s*)+"
    r"[A-Za-z_]\w*\s*\([^;{}]*\)\s*(?=\{|;)")
_CPP_METHOD = re.compile(
    r"(?m)^\s*(?:virtual\s+|static\s+|inline\s+)*[A-Za-z_][\w:<>,\s*&]*\s+"
    r"[A-Za-z_]\w*\s*\([^;{}]*\)\s*(?:const\s*)?(?:override\s*)?(?:;|\{)")
_CPP_CLASS = re.compile(r"(?m)^\s*(?:class|struct)\s+[A-Za-z_]\w*")

_RUST_CONTRACT_ATTR = re.compile(r"#\[(?:requires|ensures|after_expiry|pure|trusted)"
                                 r"[\s\S]*?\]")
_ACSL_BLOCK = re.compile(r"/\*@(?:.|\n)*?\*/", re.MULTILINE)
_CPP_ASSERT = re.compile(r"(?m)\bassert\s*\([^;]+\)\s*;")


def _walk(root):
    stack, nodes = [root], []
    while stack:
        node = stack.pop()
        nodes.append(node)
        for child in node.children:
            stack.append(child)
    return nodes


def _ts_nodes(source: str, suffix: str):
    if Parser is None:  # grammars unavailable in this process
        return None
    language = _TS_LANGUAGES.get(suffix)
    if language is None:
        return None
    parser = Parser(); parser.language = Language(language)
    tree = parser.parse(source.encode("utf-8"))
    if tree.root_node.has_error:
        return None
    return _walk(tree.root_node)


def _node_text(source: str, node) -> str:
    return source.encode("utf-8")[node.start_byte:node.end_byte].decode("utf-8")


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _signature_only(text: str) -> str:
    """Truncate a declaration node at its body: the API surface is the signature."""
    brace = text.find("{")
    return text[:brace] if brace >= 0 else text


def public_api_surface(source: str, language: str) -> list[str]:
    """Normalized public signature surface for rust, c, or cpp."""
    suffix = {"rust": ".rs", "c": ".c", "cpp": ".cpp"}[language]
    nodes = _ts_nodes(source, suffix)
    if nodes is not None:
        signatures = []
        for node in nodes:
            if language == "rust":
                if node.type in {"function_item", "function_signature_item"}:
                    text = _node_text(source, node)
                    if text.lstrip().startswith("pub "):
                        signatures.append(_normalize(_signature_only(text)))
                elif node.type == "trait_item":
                    signatures.append(_normalize(_node_text(source, node)))
            elif language == "c":
                if node.type == "function_definition":
                    signatures.append(_normalize(
                        _signature_only(_node_text(source, node))))
            else:  # cpp
                if node.type in {"function_definition", "declaration",
                                 "function_declaration"}:
                    signatures.append(_normalize(
                        _signature_only(_node_text(source, node))))
                elif node.type == "class_specifier":
                    signatures.append(_normalize(
                        _signature_only(_node_text(source, node))))
        return sorted(signatures)
    # Regex fallback for minimal environments.
    if language == "rust":
        return sorted(_normalize(m.group(0)) for m in _RUST_SIGNATURE.finditer(source)) or \
               sorted(_normalize(m.group(0)) for m in _RUST_TRAIT.finditer(source))
    if language == "c":
        return sorted(_normalize(m.group(0)) for m in _C_SIGNATURE.finditer(source))
    return (sorted(_normalize(_signature_only(m.group(0))) for m in _CPP_METHOD.finditer(source)) +
            sorted(_normalize(_signature_only(m.group(0))) for m in _CPP_CLASS.finditer(source)))


def contract_clauses(source: str, language: str) -> set[str]:
    """Normalized native-contract clause set (proof hints excluded by shape)."""
    if language == "rust":
        return {_normalize(m.group(0)) for m in _RUST_CONTRACT_ATTR.finditer(source)}
    if language == "c":
        return {_normalize(m.group(0)) for m in _ACSL_BLOCK.finditer(source)
                if not re.search(r"\bloop\b", m.group(0))}
    return {_normalize(m.group(0)) for m in _CPP_ASSERT.finditer(source)}


def language_for(suffix: str) -> str | None:
    return {".rs": "rust", ".c": "c", ".cpp": "cpp", ".cc": "cpp",
            ".cxx": "cpp"}.get(suffix.lower())
