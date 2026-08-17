# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Requirements -> invariant -> code traceability for certification evidence.

Deterministic matching only — no LLM: a requirement maps to a V2 invariant
when they share a state-field mention AND the requirement's numeric bound
appears in the invariant's constants, and to the first source line that
mentions the field and the bound. Unmapped requirements are reported as
UNMAPPED rows, never silently dropped. The matrix is certification-plumbing
evidence and carries no proof claim of its own.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_REQUIREMENT_LINE = re.compile(r"(?m)^\s*(?P<id>[A-Z]+-\d+)\s*[:.]?\s*(?P<text>.+?)\s*$")
_UPPER_PHRASES = re.compile(
    r"(?:must not exceed|not exceed|at most|no more than|"
    r"less than(?: or equal to)?|maximum(?: of)?|up to)\s+(\d+)", re.I)
_LOWER_PHRASES = re.compile(
    r"(?:at least|no fewer than|no less than|minimum(?: of)?|"
    r"greater than(?: or equal to)?)\s+(\d+)", re.I)

_SOURCE_SUFFIXES = (".java", ".rs", ".c", ".h", ".cc", ".cpp", ".cxx", ".py")


def parse_requirements(path: str | Path) -> list[dict]:
    """REQ-####-style lines from a requirements file, in file order."""
    requirements = []
    for match in _REQUIREMENT_LINE.finditer(Path(path).read_text(encoding="utf-8")):
        requirements.append({"id": match.group("id"), "text": match.group("text")})
    return requirements


def _dumped(node):
    return node.model_dump(mode="json") if hasattr(node, "model_dump") else node


def _walk(node, kinds):
    """Yield every value of the given AST `kind`s in a dumped expression."""
    if isinstance(node, dict):
        if node.get("kind") in kinds:
            yield node
        for child in node.values():
            yield from _walk(child, kinds)
    elif isinstance(node, list):
        for child in node:
            yield from _walk(child, kinds)


_SYMBOL = {"eq": "==", "neq": "!=", "lt": "<", "lte": "<=", "gt": ">",
           "gte": ">=", "add": "+", "sub": "-", "and": "&&", "or": "||",
           "implies": "==>"}


def _expression_text(node, top: bool = True) -> str:
    value = _dumped(node)
    kind = value.get("kind")
    if kind == "field":
        return value.get("name", "?")
    if kind in {"integer", "boolean"}:
        return str(value["value"])
    if kind == "not":
        return f"!({_expression_text(value['expression'])})"
    if kind == "old":
        return f"old({_expression_text(value['expression'])})"
    text = (f"{_expression_text(value['left'], top=False)} "
            f"{_SYMBOL.get(kind, kind)} "
            f"{_expression_text(value['right'], top=False)}")
    return text if top else f"({text})"


def _field_mentions(text: str, field_names: list[str]) -> set[str]:
    """State fields named by the requirement (prefix-tolerant word match)."""
    words = set(re.findall(r"[A-Za-z]+", text.lower()))
    mentioned = set()
    for name in field_names:
        target = name.lower().replace("_", "")
        for word in words:
            compact = word.replace("_", "")
            if compact == target or (len(target) >= 4 and compact.startswith(target)):
                mentioned.add(name)
                break
    return mentioned


def _bounds(text: str) -> set[int]:
    """Numeric bounds the requirement asserts over its fields."""
    values = {int(value) for value in _UPPER_PHRASES.findall(text)}
    values |= {int(value) for value in _LOWER_PHRASES.findall(text)}
    return values


def _source_files(source: str | Path) -> list[Path]:
    path = Path(source)
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(item for item in path.rglob("*")
                      if item.suffix.lower() in _SOURCE_SUFFIXES)
    return []


def _find_code_line(files: list[Path], fields: set[str],
                    bounds: set[int]) -> tuple[str | None, int | None]:
    """First line mentioning a mapped field (and its bound when known)."""
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            continue
        for number, line in enumerate(lines, 1):
            if any(re.search(rf"\b{re.escape(field)}\b", line) for field in fields):
                if not bounds or any(str(bound) in line for bound in bounds):
                    return path.name, number
    return None, None


def generate_traceability_matrix(domain: str | Path, source: str | Path,
                                 requirements: str | Path) -> dict:
    """Rows linking each requirement to its invariant and source line."""
    from .domain_v2_promotion import ReviewedDomainSpecV2, load_candidate
    try:
        spec = load_candidate(domain)
    except Exception:
        # reviewed artifacts carry publication metadata the candidate schema
        # refuses; both formats share the fields the matrix needs
        import json as _json
        spec = ReviewedDomainSpecV2.model_validate(
            _json.loads(Path(domain).read_text(encoding="utf-8")))
    field_names = [variable.name for variable in spec.state_variables]
    invariants = [{"id": item.id, "fields": {node.get("name") for node in
                                            _walk(_dumped(item.expression), {"field"})},
                   "constants": {node.get("value") for node in
                                 _walk(_dumped(item.expression), {"integer"})},
                   "text": _expression_text(item.expression)}
                  for item in spec.tlc_invariants]
    files = _source_files(source)

    rows = []
    for requirement in parse_requirements(requirements):
        mentioned = _field_mentions(requirement["text"], field_names)
        bounds = _bounds(requirement["text"])
        matched = None
        if mentioned:
            for invariant in invariants:
                if not (invariant["fields"] & mentioned):
                    continue
                if bounds and not (invariant["constants"] & bounds):
                    continue
                matched = invariant
                break
        code_file = code_line = None
        if matched:
            code_file, code_line = _find_code_line(
                files, matched["fields"] & mentioned, bounds)
        rows.append({"req": requirement["id"], "text": requirement["text"],
                     "invariant": matched["text"] if matched else None,
                     "invariant_id": matched["id"] if matched else None,
                     "code_line": code_line, "source": code_file,
                     "status": "MAPPED" if matched else "UNMAPPED"})
    mapped = sum(1 for row in rows if row["status"] == "MAPPED")
    return {"rows": rows, "coverage": {"mapped": mapped, "total": len(rows)},
            "domain": Path(domain).name}


def render_matrix_markdown(matrix: dict) -> str:
    lines = ["# Traceability Matrix", "",
             f"Domain: `{matrix['domain']}` — "
             f"{matrix['coverage']['mapped']}/{matrix['coverage']['total']} "
             "requirements mapped", "",
             "| Requirement | Invariant | Source | Status |",
             "| --- | --- | --- | --- |"]
    for row in matrix["rows"]:
        invariant = (f"`{row['invariant']}`" if row["invariant"] else "—")
        source = (f"{row['source']}:{row['code_line']}"
                  if row["code_line"] else "—")
        status = row["status"] if row["invariant"] else "UNMAPPED"
        lines.append(f"| {row['req']} | {invariant} | {source} | {status} |")
    lines += ["", "Deterministic field/bound matching; UNMAPPED rows need "
              "manual review. This matrix is certification evidence "
              "plumbing, not a proof claim."]
    return "\n".join(lines) + "\n"


def write_matrix(matrix: dict, out: str | Path, json_out: str | Path | None = None) -> Path:
    path = Path(out)
    path.write_text(render_matrix_markdown(matrix), encoding="utf-8")
    sidecar = Path(json_out) if json_out else path.with_suffix(".json")
    sidecar.write_text(json.dumps(
        {"status": "TRACEABILITY_GENERATED", **matrix}, indent=2) + "\n",
        encoding="utf-8")
    return path
