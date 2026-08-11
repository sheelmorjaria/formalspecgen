# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Refine flow: a targeted update of a (possibly human-edited) stub that does NOT clobber
human-authoritative clauses.

The LLM emits an updated full stub; we diff it clause-by-clause against the current one and
flag any LOCKED clause the model altered as a CONFLICT for the human to approve before the
change is applied. Rationale (design-critique Tier-1 #3): a whole-file regeneration silently
overwrites human edits; we surface every change and refuse to auto-apply protected ones.

This is deliberately server-driven and non-destructive: refine() never mutates the caller's
stub — it returns the candidate + diff + conflicts, and the UI/human decides whether to apply.
"""
import time

from . import jml_io
from .schemas import RefineResult
from .validate import check_stub
from .llm import glm_refine, LLMError, _chat_fn


def refine(current_stub, instruction, locked_clauses=None, nl=None, model=None,
           provider="glm") -> RefineResult:
    t0 = time.time()
    locked = list(locked_clauses or [])
    try:
        draft, used, _usage = glm_refine(current_stub, instruction, locked, nl, model,
                                         chat_fn=_chat_fn(provider))
    except LLMError as e:
        return RefineResult(
            instruction=instruction, new_stub=current_stub, check_ok=False,
            check_errors=[f"[{e.code}] {e.message}"],
            diff={"added": [], "removed": [], "common": []}, conflicts=[],
            model=model or "", error=f"[{e.code}] {e.message}",
            duration_s=round(time.time() - t0, 1))

    new_stub = jml_io.normalize_line_clause_continuations(draft.stub)
    new_stub = jml_io.normalize_old_in_requires(new_stub)
    ok, errs = check_stub(new_stub)
    diff = jml_io.clause_diff(current_stub, new_stub)
    # A conflict is a LOCKED clause that no longer appears verbatim in the new stub.
    conflicts = [c for c in locked if not jml_io.contains_clause(new_stub, c)]

    if conflicts:
        return RefineResult(
            instruction=instruction, new_stub=current_stub, candidate_stub=new_stub,
            check_ok=False,
            check_errors=["TRUST_BOUNDARY_VIOLATION: candidate modified locked contract clauses"],
            diff=diff, conflicts=conflicts, assumptions=draft.assumptions,
            missing_info=draft.missing_info, model=used,
            error="TRUST_BOUNDARY_VIOLATION", status="TRUST_BOUNDARY_VIOLATION",
            terminal=True, duration_s=round(time.time() - t0, 1))

    return RefineResult(
        instruction=instruction, new_stub=new_stub, check_ok=ok, check_errors=errs,
        diff=diff, conflicts=conflicts, assumptions=draft.assumptions,
        missing_info=draft.missing_info, model=used,
        status="VALIDATED_CANDIDATE" if ok else "INVALID_CANDIDATE",
        candidate_stub=new_stub, duration_s=round(time.time() - t0, 1))
