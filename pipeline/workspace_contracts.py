# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Deterministic, bounded retrieval of JML method contracts from workspace sources."""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict


_METHOD = re.compile(
    r"(?m)^\s*(?:public|protected)\s+(?:static\s+)?(?:synchronized\s+)?"
    r"([\w<>\[\], ?]+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[^{;]+)?[;{]")
_CLAUSE = re.compile(r"(?m)^\s*//@\s*(requires|ensures|assignable|signals)\s+(.+?;)\s*$")


@dataclass(frozen=True)
class ContractEntry:
    source: str
    owner: str
    method: str
    signature: str
    clauses: tuple[str, ...]


def index_workspace(files: dict[str, str], max_files: int = 80,
                    max_chars: int = 500_000) -> list[ContractEntry]:
    """Extract exact clauses; reject excess input rather than silently indexing a partial tree."""
    if len(files) > max_files or sum(len(value) for value in files.values()) > max_chars:
        raise ValueError("WORKSPACE_CONTEXT_TOO_LARGE")
    entries: list[ContractEntry] = []
    for source, code in sorted(files.items()):
        owner_match = re.search(r"\b(?:class|interface)\s+(\w+)", code)
        owner = owner_match.group(1) if owner_match else source.rsplit("/", 1)[-1].split(".")[0]
        previous_end = 0
        for match in _METHOD.finditer(code):
            prefix = code[previous_end:match.start()]
            clauses = tuple(f"{kind} {body}" for kind, body in _CLAUSE.findall(prefix))
            if clauses:
                entries.append(ContractEntry(source, owner, match.group(2),
                                             " ".join(match.group(0).split()), clauses))
            previous_end = match.end()
    return entries


def retrieve_contracts(requirement: str, files: dict[str, str], limit: int = 12) -> list[dict]:
    tokens = set(re.findall(r"[a-z][a-z0-9_]+", requirement.lower()))
    ranked = []
    for entry in index_workspace(files):
        names = {entry.owner.lower(), entry.method.lower()}
        score = len(tokens & names) * 10 + sum(name in requirement.lower() for name in names)
        if score:
            ranked.append((score, entry.source, entry.method, entry))
    ranked.sort(key=lambda item: (-item[0], item[1], item[2]))
    return [asdict(item[3]) for item in ranked[:limit]]


def contract_context(requirement: str, files: dict[str, str]) -> tuple[str, list[dict]]:
    entries = retrieve_contracts(requirement, files)
    if not entries:
        return requirement, []
    lines = [requirement, "", "Existing workspace contracts (exact, read-only context):"]
    for entry in entries:
        lines.append(f"- {entry['source']} :: {entry['signature']}")
        lines.extend(f"  //@ {clause}" for clause in entry["clauses"])
    lines.append("Caller contracts must establish applicable callee preconditions; do not rewrite these clauses.")
    return "\n".join(lines), entries
