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
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:const\s+)?(?:async\s+)?fn\s+"
    r"[A-Za-z_]\w*\s*(?:<[^>{;]*>)?\s*\([^;{}]*\)\s*(?:->\s*[^;{]+)?")
_RUST_TRAIT = re.compile(r"(?m)^\s*(?:pub\s+)?trait\s+[A-Za-z_]\w*")
_C_SIGNATURE = re.compile(
    r"(?m)^\s*(?!if\b|for\b|while\b|switch\b)(?:[A-Za-z_]\w*\s+|\*\s*)+"
    r"[A-Za-z_]\w*\s*\([^;{}]*\)\s*(?=\{|;)")
_CPP_METHOD = re.compile(
    r"(?m)^\s*(?:virtual\s+|static\s+|inline\s+)*[A-Za-z_][\w:<>,\s*&]*\s+"
    r"[A-Za-z_]\w*\s*\([^;{}]*\)\s*(?:const\s*)?(?:override\s*)?(?:;|\{)")
_CPP_CLASS = re.compile(r"(?m)^\s*(?:class|struct)\s+[A-Za-z_]\w*")

_RUST_ATTRIBUTE = re.compile(
    r"#\[\s*(?P<name>[A-Za-z_]\w*)(?:\([\s\S]*?\))?\s*\]")
_RUST_CONTRACT_NAMES = {"requires", "ensures", "after_expiry", "pure", "terminates"}
_RUST_PROOF_TRUST_NAMES = {"trusted", "extern_spec", "verify_only_spec"}
_ACSL_BLOCK = re.compile(r"/\*@(?:.|\n)*?\*/", re.MULTILINE)
_CPP_ASSERT = re.compile(r"(?m)\bassert\s*\([^;]+\)\s*;")
_ACSL_PROOF_TRUST = re.compile(r"\b(?:admit|admits|axiom|axiomatic)\b", re.I)


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
    surface = native_contract_surface(source, language)
    clauses = set(surface["global_contracts"])
    for item in surface["functions"]:
        clauses.update(item["contracts"])
    return clauses


def native_contract_surface(source: str, language: str) -> dict:
    """Declaration-bound native contracts plus proof-trust controls.

    Existing functions retain their own clauses during a refactor. New private
    helpers may carry copied contracts, but trust attributes and verifier
    escape hatches are compared independently of API visibility.
    """
    if language == "rust":
        return _rust_contract_surface(source)
    if language == "c":
        return _c_contract_surface(source)
    if language == "cpp":
        return {
            "functions": [],
            "api": public_api_surface(source, language),
            "global_contracts": sorted(
                _normalize(match.group(0)) for match in _CPP_ASSERT.finditer(source)),
            "proof_trust": [],
            "parse_errors": [],
        }
    raise ValueError(f"unsupported native contract language: {language}")


def _rust_contract_surface(source: str) -> dict:
    attributes = list(_RUST_ATTRIBUTE.finditer(source))
    signatures = list(_RUST_SIGNATURE.finditer(source))
    assigned_contracts: set[int] = set()
    assigned_trust: set[int] = set()
    functions = []
    proof_trust = []
    for signature_match in signatures:
        signature = _normalize(signature_match.group(0))
        attached = _contiguous_preceding(source, attributes, signature_match.start())
        contracts = []
        for attribute in attached:
            name = attribute.group("name").lower()
            normalized = _normalize(attribute.group(0))
            if name in _RUST_CONTRACT_NAMES:
                contracts.append(normalized)
                assigned_contracts.add(attribute.start())
            if name in _RUST_PROOF_TRUST_NAMES:
                proof_trust.append(f"{signature}: {normalized}")
                assigned_trust.add(attribute.start())
        functions.append({"signature": signature, "contracts": contracts})

    parse_errors = []
    for attribute in attributes:
        name = attribute.group("name").lower()
        if name in _RUST_CONTRACT_NAMES and attribute.start() not in assigned_contracts:
            parse_errors.append(
                f"unbound Rust contract attribute at offset {attribute.start()}")
        if name in _RUST_PROOF_TRUST_NAMES and attribute.start() not in assigned_trust:
            proof_trust.append(
                f"unbound@{attribute.start()}: {_normalize(attribute.group(0))}")
    api = sorted(
        [item["signature"] for item in functions
         if re.match(r"^pub(?:\([^)]*\))?\s+", item["signature"])] +
        [_normalize(match.group(0)) for match in _RUST_TRAIT.finditer(source)])
    return {
        "functions": sorted(functions, key=lambda item: item["signature"]),
        "api": api,
        "global_contracts": [],
        "proof_trust": sorted(proof_trust),
        "parse_errors": parse_errors,
    }


def _c_contract_surface(source: str) -> dict:
    blocks = list(_ACSL_BLOCK.finditer(source))
    signatures = list(_C_SIGNATURE.finditer(source))
    assigned: set[int] = set()
    functions = []
    proof_trust = []
    for signature_match in signatures:
        signature = _normalize(signature_match.group(0))
        attached = _contiguous_preceding(source, blocks, signature_match.start())
        contracts = []
        for block in attached:
            normalized = _normalize(block.group(0))
            if re.search(r"\bloop\b", block.group(0)):
                continue
            assigned.add(block.start())
            if _ACSL_PROOF_TRUST.search(block.group(0)):
                proof_trust.append(f"{signature}: {normalized}")
            else:
                contracts.append(normalized)
        functions.append({"signature": signature, "contracts": contracts})

    parse_errors = []
    for block in blocks:
        if re.search(r"\bloop\b", block.group(0)):
            continue
        normalized = _normalize(block.group(0))
        if block.start() not in assigned:
            if _ACSL_PROOF_TRUST.search(block.group(0)):
                proof_trust.append(f"unbound@{block.start()}: {normalized}")
            else:
                parse_errors.append(
                    f"unbound ACSL contract block at offset {block.start()}")
    api = sorted(
        item["signature"] for item in functions
        if not re.match(r"^static\b", item["signature"]))
    return {
        "functions": sorted(functions, key=lambda item: item["signature"]),
        "api": api,
        "global_contracts": [],
        "proof_trust": sorted(proof_trust),
        "parse_errors": parse_errors,
    }


def _contiguous_preceding(source: str, candidates: list[re.Match],
                          declaration_start: int) -> list[re.Match]:
    """Return annotations immediately preceding a declaration, in source order."""
    cursor = declaration_start
    selected = []
    for candidate in reversed(candidates):
        if candidate.end() > cursor:
            continue
        if source[candidate.end():cursor].strip():
            break
        selected.append(candidate)
        cursor = candidate.start()
    return list(reversed(selected))


def language_for(suffix: str) -> str | None:
    return {".rs": "rust", ".c": "c", ".cpp": "cpp", ".cc": "cpp",
            ".cxx": "cpp"}.get(suffix.lower())
