# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Repair-loop strategy (ported verbatim from formalspecDD).

Direction-agnostic: history entries are (artifact, vcs, tool_text) where `artifact` is
the Java impl in DD and the JML stub here. The loop is sample-first -> feedback-second,
with stall detection (VC-fingerprint repeat + artifact oscillation) and an N=5 cap.

This *is* the design-critique's Tier-1 guardrail: the self-repair loop is bounded, and
non-progress (same errors recurring, or the draft oscillating) causes an early stop
rather than a silent semantic drift. The orchestrator additionally surfaces EVERY
attempt to the human rather than trusting a final "validated" signal.
"""
import hashlib
from collections import Counter
from dataclasses import dataclass
from typing import List, Tuple

from .schemas import VC

MAX_ATTEMPTS = 5      # hard cap (samples + feedback combined)
RESAMPLE_BUDGET = 1   # independent fresh-generation budget
FEEDBACK_BUDGET = 4   # independent diagnostic-feedback budget
SAMPLES_FIRST = RESAMPLE_BUDGET  # compatibility alias
FEEDBACK_MAX = FEEDBACK_BUDGET   # compatibility alias

# history entry: (artifact, vcs, tool_text)
History = List[Tuple[str, List[VC], str]]


@dataclass
class Decision:
    action: str   # "sample" | "feedback" | "stop"
    reason: str = ""


def vc_fingerprint(vcs: List[VC], backend: str = "openjml"):
    """Order-independent signature of the failing validation rows."""
    from .lifecycle import failure_fingerprint
    return frozenset(failure_fingerprint(backend, v.category, v.method, v.line,
                                         v.detail or v.raw) for v in vcs)


def _artifact_hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()[:16]


def is_stalled(history: History) -> str:
    """Return a stall reason ('' if not stalled). Detects error repeat and oscillation."""
    if len(history) < 3:
        return ""
    fps = [vc_fingerprint(vcs) for _, vcs, _ in history]
    # error fingerprint repeat: latest failing set was seen before -> non-progress
    if fps[-1] and fps[-1] in fps[:-1]:
        return "error fingerprint repeated (no progress)"
    # artifact oscillation: same draft hash at i and i-2
    h = [_artifact_hash(c) for c, _, _ in history]
    if h[-1] in h[:-1]:
        distance = len(h) - 1 - h[:-1].index(h[-1])
        return f"candidate hash repeated/oscillated (cycle distance {distance})"
    return ""


def ambiguity_suspected(history: History):
    """If the same validation failure recurs across >=3 attempts, flag a possible gap in
    the NL (the spec keeps failing the same way -> the requirement may be underspecified).
    Returns the suspect (category, line, key) or None."""
    if len(history) < 3:
        return None
    per_attempt = [vc_fingerprint(vcs) for _, vcs, _ in history]
    cnt = Counter()
    for fp in per_attempt:
        for vc in fp:
            cnt[vc] += 1
    for vc, n in cnt.items():
        if n >= 3:
            return vc
    return None


def decide(history: History, last_verified: bool, samples_done: int,
           feedback_done: int, max_attempts: int = None,
           resample_budget: int | None = None,
           feedback_budget: int | None = None) -> Decision:
    resample_budget = RESAMPLE_BUDGET if resample_budget is None else resample_budget
    feedback_budget = FEEDBACK_BUDGET if feedback_budget is None else feedback_budget
    max_attempts = max_attempts or (resample_budget + feedback_budget)
    if last_verified:
        return Decision("stop", "VERIFIED")
    if len(history) == 0:
        return Decision("sample", "initial generation")
    if len(history) >= max_attempts:
        return Decision("stop", f"max attempts ({max_attempts}) reached")
    stall = is_stalled(history)
    if stall:
        return Decision("stop", "stalled: " + stall)
    if samples_done < resample_budget:
        return Decision("sample", f"fresh sample #{samples_done + 1}")
    if feedback_done < feedback_budget:
        return Decision("feedback", f"feedback round #{feedback_done + 1}")
    return Decision("stop", "feedback budget exhausted")
