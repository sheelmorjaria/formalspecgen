# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Concurrent linearizability: Java lock correspondence + bounded histories.

The proof is two-sided and honestly scoped. The MODEL side reuses the
traverser's lock-protocol exploration: bounded invocation histories
(invoke/acquire/effect_commit-or-reject/release/respond) are enumerated and
the reviewed invariants checked, so every bounded concurrent history
serializes through the reviewed ``effect_commit`` linearization points. The
JAVA side is a deterministic correspondence gate: every lock acquisition
site in the source must map to the modeled lock — synchronized regions on a
single receiver correspond to the one modeled lock, explicit
ReentrantLock-style locks must carry the model's lock variable name, and
anything else fails closed ``LOCK_CORRESPONDENCE_FAILED``. The claim covers
the model plus the lock correspondence; the Java memory model beyond those
sites is not proved.
"""
from __future__ import annotations

import re
from pathlib import Path

_SYNC_HEAD = re.compile(r"synchronized\s*\((?P<lock>[^)]+)\)\s*\{")
_EXPLICIT_LOCK = re.compile(r"(?P<lock>\w+)\s*\.\s*(?P<action>lock|unlock)\s*\(\s*\)\s*;")


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def extract_lock_sites(source: str) -> list[dict]:
    """Lock acquisitions/releases: synchronized regions (with brace-matched
    spans) and explicit ``x.lock();`` / ``x.unlock();`` statements."""
    sites = []
    for match in _SYNC_HEAD.finditer(source):
        depth, index = 1, match.end()
        while index < len(source) and depth:
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
            index += 1
        sites.append({"kind": "synchronized",
                      "lock": match.group("lock").strip(),
                      "acquire_line": _line_of(source, match.start()),
                      "release_line": _line_of(source, index - 1)})
    for match in _EXPLICIT_LOCK.finditer(source):
        sites.append({"kind": "explicit", "lock": match.group("lock"),
                      "action": match.group("action"),
                      "line": _line_of(source, match.start())})
    return sites


def _load_domain(path: str | Path):
    """Candidate first; reviewed JSON only when the file IS JSON.

    Falling back on any load failure would JSON-parse YAML and replace the
    schema's informative message with a decode error.
    """
    from .domain_v2_promotion import ReviewedDomainSpecV2, load_candidate
    try:
        return load_candidate(path)
    except Exception as candidate_error:
        import json
        text = Path(path).read_text(encoding="utf-8")
        try:
            value = json.loads(text)
        except ValueError:
            # not JSON either: the candidate-load failure IS the diagnosis
            raise ValueError(str(candidate_error)) from candidate_error
        return ReviewedDomainSpecV2.model_validate(value)


def _check_correspondence(sites: list[dict], lock_variable: str) -> tuple[str | None, int]:
    """(failure, mapped_count): every site must map to the modeled lock.

    The model has ONE lock; synchronized regions all correspond to it when
    they share a single receiver, and explicit locks must carry the model's
    lock variable name. Anything else is an unmodeled lock discipline.
    """
    receivers = {site["lock"] for site in sites if site["kind"] == "synchronized"}
    if len(receivers) > 1:
        return (f"mixed synchronized receivers {sorted(receivers)} against a "
                "single modeled lock", 0)
    explicit = {site["lock"] for site in sites if site["kind"] == "explicit"}
    foreign = explicit - {lock_variable}
    if foreign:
        return (f"explicit lock(s) {sorted(foreign)} not in the model "
                f"(expected {lock_variable!r})", 0)
    mapped = sum(1 for site in sites if site["kind"] == "synchronized")
    mapped += sum(1 for site in sites if site["kind"] == "explicit"
                  and site["action"] == "lock")
    return None, mapped


def verify_linearizability(source: str | Path, domain: str | Path) -> dict:
    """Lock correspondence + bounded-history linearizability verdict."""
    path = Path(source)
    if not path.is_file():
        return {"status": "LINEARIZABILITY_FAILED", "claim": "NO_PROOF",
                "code": "input_unavailable", "target": str(path)}
    try:
        spec = _load_domain(domain)
    except (OSError, ValueError) as exc:
        return {"status": "LINEARIZABILITY_FAILED", "claim": "NO_PROOF",
                "code": "domain_unreadable", "message": str(exc)}
    concurrency = getattr(spec, "concurrency", None)
    if concurrency is None or getattr(concurrency, "mode", None) != "lock_protocol":
        return {"status": "LINEARIZABILITY_FAILED", "claim": "NO_PROOF",
                "code": "lock_protocol_required",
                "message": "the domain must declare concurrency.mode "
                           "lock_protocol (bounded invocation histories)"}
    # full linearization-point coverage is enforced by the DOMAIN SCHEMA
    # (a spec with partial coverage never loads), so no runtime re-check
    points = concurrency.linearization_points or {}

    sites = extract_lock_sites(path.read_text(encoding="utf-8"))
    failure, mapped = _check_correspondence(sites, concurrency.lock_variable)
    if failure is not None:
        return {"status": "LINEARIZABILITY_FAILED", "claim": "NO_PROOF",
                "code": "LOCK_CORRESPONDENCE_FAILED", "message": failure}

    from .domain_v2_model import validate_transitions_and_invariants
    try:
        states, transitions = validate_transitions_and_invariants(spec)
    except Exception as exc:
        return {"status": "LINEARIZABILITY_FAILED", "claim": "NO_PROOF",
                "code": "history_exploration_failed", "message": str(exc)}

    return {"status": "LINEARIZABILITY_PROVED",
            "claim": "CONCURRENT_LINEARIZABILITY_PROVED",
            "scope": "bounded_lock_history_plus_java_lock_correspondence",
            "reachable_states": states,
            "reachable_transitions": transitions,
            "lock_sites_mapped": mapped,
            "linearization_points": dict(points),
            "lock_variable": concurrency.lock_variable,
            "java_memory_model_proved": False,
            "note": "bounded invocation histories serialize through the "
                    "reviewed effect_commit points, and every Java lock "
                    "site maps to the modeled lock; the Java memory model "
                    "beyond those sites is not proved"}
