# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Tree-sitter public-API and contract surfaces for polyglot refactor gating.

`public_api_surface` yields normalized, sorted signature lists (the polyglot
analogue of `refactor_gate.public_method_surface`); `contract_clauses` yields
the normalized native-contract set (Prusti attributes, ACSL blocks, C++
assertion checks) — the analogue of `refactor_gate._public_contract_clauses`.
Public API inspection retains a regex fallback for minimal installations.
Rust contract-preservation claims require Tree-sitter so attributes and
declaration ownership cannot silently disappear.
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

_RUST_CONTRACT_NAMES = {"requires", "ensures", "after_expiry", "pure", "terminates"}
_RUST_PROOF_TRUST_NAMES = {"trusted", "extern_spec", "verify_only_spec"}
_RUST_CONDITIONAL_ATTRIBUTE_NAMES = {"cfg", "cfg_attr"}
_RUST_CONTAINER_NODES = {"mod_item", "impl_item", "trait_item"}
_RUST_CALLABLE_NODES = {"function_item", "function_signature_item"}
_RUST_BINDING_CONTEXT_NODES = {"use_declaration", "extern_crate_declaration"}
_RUST_SEMANTIC_DECLARATION_NODES = {
    "const_item", "static_item", "type_item", "struct_item", "enum_item", "union_item",
}
_RUST_BINDING_DECLARATION_NODES = {"const_item", "static_item", "type_item"}
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
    if Parser is None:
        return _empty_rust_surface(
            "tree-sitter Rust parsing is required for contract preservation")
    parser = Parser()
    parser.language = Language(_TS_LANGUAGES[".rs"])
    root = parser.parse(source.encode("utf-8")).root_node
    if root.has_error:
        return _empty_rust_surface(
            "Rust source could not be parsed completely at the contract boundary")

    state = {
        "functions": [], "api": [], "proof_trust": [], "parse_errors": [],
        "binding_context": [], "semantic_declarations": [],
        "binding_declarations": [],
        "processed_callables": set(),
    }
    _collect_rust_items(source, root, (), state)
    for node in _walk(root):
        if node.type in _RUST_CALLABLE_NODES and node.start_byte not in \
                state["processed_callables"]:
            state["parse_errors"].append(
                f"unsupported Rust callable ownership at offset {node.start_byte}")
    return {
        "functions": sorted(
            state["functions"], key=lambda item: (item["identity"], item["signature"])),
        "api": sorted(state["api"]),
        "global_contracts": [],
        "proof_trust": sorted(state["proof_trust"]),
        "binding_context": sorted(state["binding_context"]),
        "semantic_declarations": sorted(state["semantic_declarations"]),
        "binding_declarations": sorted(state["binding_declarations"]),
        "parse_errors": state["parse_errors"],
    }


def _empty_rust_surface(error: str) -> dict:
    return {"functions": [], "api": [], "global_contracts": [],
            "proof_trust": [], "binding_context": [],
            "semantic_declarations": [], "binding_declarations": [],
            "parse_errors": [error]}


def _collect_rust_items(source: str, container, owners: tuple[str, ...],
                        state: dict) -> None:
    """Collect callables from one parsed Rust item container."""
    pending_attributes = []
    for child in container.named_children:
        if child.type in {"attribute_item", "inner_attribute_item"}:
            pending_attributes.append(child)
            continue
        if child.type in {"line_comment", "block_comment"}:
            continue
        if child.type in _RUST_CALLABLE_NODES:
            _add_rust_callable(source, child, pending_attributes, owners, state)
        elif child.type in _RUST_CONTAINER_NODES:
            _add_rust_container(source, child, pending_attributes, owners, state)
        else:
            _classify_rust_attributes(
                source, pending_attributes,
                f"unbound@{child.start_byte}", state, contracts=None)
            item_text = _node_text(source, child).strip()
            owner = "crate::" + "::".join(owners) if owners else "crate"
            if child.type in _RUST_BINDING_CONTEXT_NODES:
                state["binding_context"].append(item_text)
            elif child.type in _RUST_SEMANTIC_DECLARATION_NODES:
                declaration = f"{owner}: {item_text}"
                state["semantic_declarations"].append(declaration)
                if child.type in _RUST_BINDING_DECLARATION_NODES:
                    state["binding_declarations"].append(declaration)
            contains_item_macro = child.type in {"macro_invocation", "macro_definition"} or (
                child.type == "expression_statement" and
                any(node.type == "macro_invocation" for node in _walk(child)))
            if contains_item_macro:
                state["parse_errors"].append(
                    f"item-level Rust macros are unsupported at offset {child.start_byte}")
        pending_attributes = []
    _classify_rust_attributes(
        source, pending_attributes, f"unbound@{container.end_byte}",
        state, contracts=None)


def _add_rust_container(source: str, node, attributes: list,
                        owners: tuple[str, ...], state: dict) -> None:
    body = node.child_by_field_name("body")
    header_end = body.start_byte if body is not None else node.end_byte
    header = source.encode("utf-8")[node.start_byte:header_end].decode("utf-8").strip()
    kind = {"mod_item": "module", "impl_item": "impl", "trait_item": "trait"}[node.type]
    owner = f"{kind}:{header}"
    identity = "crate::" + "::".join((*owners, owner))
    _classify_rust_attributes(source, attributes, identity, state, contracts=None)
    if node.type in {"mod_item", "trait_item"} and \
            re.match(r"^pub(?:\([^)]*\))?\s+", header):
        state["api"].append(identity)
    if body is None:
        state["parse_errors"].append(
            f"external Rust {kind} ownership is unsupported at offset {node.start_byte}")
        return
    _collect_rust_items(source, body, (*owners, owner), state)


def _add_rust_callable(source: str, node, attributes: list,
                       owners: tuple[str, ...], state: dict) -> None:
    name_node = node.child_by_field_name("name")
    if name_node is None:
        state["parse_errors"].append(
            f"Rust callable has no parsed name at offset {node.start_byte}")
        return
    name = _node_text(source, name_node)
    body = node.child_by_field_name("body")
    signature_end = body.start_byte if body is not None else node.end_byte
    signature = _normalize(
        source.encode("utf-8")[node.start_byte:signature_end].decode("utf-8")
    ).removesuffix(";").rstrip()
    path = "::".join((*owners, name)) if owners else name
    identity = f"crate::{path}"
    contracts = []
    _classify_rust_attributes(source, attributes, identity, state, contracts)
    state["functions"].append(
        {"identity": identity, "signature": signature, "contracts": contracts})
    state["processed_callables"].add(node.start_byte)
    if re.match(r"^pub(?:\([^)]*\))?\s+", signature):
        state["api"].append(f"{identity}: {signature}")


def _classify_rust_attributes(source: str, attributes: list, identity: str,
                              state: dict, contracts: list[str] | None) -> None:
    for attribute_item in attributes:
        attribute = next(
            (child for child in attribute_item.named_children
             if child.type == "attribute"), None)
        if attribute is None or not attribute.named_children:
            state["parse_errors"].append(
                f"unsupported Rust attribute at offset {attribute_item.start_byte}")
            continue
        path_node = attribute.named_children[0]
        path = _node_text(source, path_node)
        name = path.rsplit("::", 1)[-1].lower()
        # Attribute contents include language literals. Preserve the parsed
        # token bytes exactly; whitespace inside a string or byte string is a
        # value, not formatting that may be collapsed safely.
        normalized = _node_text(source, attribute_item).strip()
        if name in _RUST_CONDITIONAL_ATTRIBUTE_NAMES:
            state["parse_errors"].append(
                f"conditional Rust attribute {path} is unsupported at offset "
                f"{attribute_item.start_byte}")
        elif name in _RUST_CONTRACT_NAMES:
            if contracts is None:
                state["parse_errors"].append(
                    f"unbound Rust contract attribute at offset {attribute_item.start_byte}")
            else:
                contracts.append(normalized)
        elif name in _RUST_PROOF_TRUST_NAMES:
            state["proof_trust"].append(f"{identity}: {normalized}")
        else:
            # Attribute macros can transform declarations. Preserve every
            # unclassified attribute in the proof-trust inventory so a change
            # cannot disappear merely because this front end does not know it.
            state["proof_trust"].append(
                f"{identity}: unclassified {normalized}")


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
