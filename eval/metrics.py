"""Token-overlap metrics for the eval harness (clause recall/precision/F1).

Clause extraction now lives in pipeline.jml_io (shared with the refine flow) and
check-pass in pipeline.validate; the LLM-judge semantic score lives in pipeline.llm.glm_judge.
We re-export extract_clauses / check_pass here so run_eval's imports stay stable.
"""
import re

from pipeline.jml_io import extract_clauses  # re-exported
from pipeline.validate import check_stub


def check_pass(stub: str):
    """Re-export of pipeline.validate.check_stub -> (ok, errors)."""
    return check_stub(stub)


def _tok(clause: str):
    # words incl. JML keywords split off their backslash (\result -> result, \old -> old)
    return set(re.findall(r'[a-z_][a-z0-9_]*', clause))


def _best_coverage(need, cand_sets):
    best = 0.0
    for cs in cand_sets:
        inter = len(need & cs)
        cov = inter / len(need) if need else 0.0
        best = max(best, cov)
    return best


def clause_overlap(gold_clauses, cand_clauses):
    """Token-overlap recall/precision/F1 over JML clauses (robust to identifier renaming)."""
    g_sets = [s for s in (_tok(c) for c in gold_clauses) if s]
    c_sets = [s for s in (_tok(c) for c in cand_clauses) if s]
    if not g_sets or not c_sets:
        return {"recall": 0.0, "precision": 0.0, "f1": 0.0}
    recall = sum(_best_coverage(g, c_sets) for g in g_sets) / len(g_sets)
    precision = sum(_best_coverage(c, g_sets) for c in c_sets) / len(c_sets)
    f1 = (2 * recall * precision / (recall + precision)) if (recall + precision) else 0.0
    return {"recall": round(recall, 3), "precision": round(precision, 3), "f1": round(f1, 3)}
