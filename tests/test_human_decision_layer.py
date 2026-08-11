from unittest.mock import patch

import pytest

from pipeline import explain_vc, limitations, refine, strategy
from pipeline.llm import LLMError
from pipeline.schemas import SpecDraft, VC


ORIGINAL = """public class C {
//@ ensures \\result >= 0;
public int value() { return 0; }
}"""


def test_vc_explanations_cover_known_default_and_overflow_override():
    for category in ("ArithmeticOperationRange", "ArrayAccess", "PossiblyNullDeReference",
                     "Postcondition", "Precondition", "LoopInvariant", "LoopDecreases",
                     "Assignable"):
        result = explain_vc.explain_vc(category)
        assert result["explanation"] and result["advice"]
    default = explain_vc.explain_vc("UnknownVC")
    assert "could not establish" in default["explanation"]
    overflow = explain_vc.explain_vc("UnknownVC", "integer overflow in addition")
    assert "numeric range" in overflow["explanation"]


def test_limitation_retrieval_ranking_limits_and_prompt_guardrails():
    limitations.entries.cache_clear()
    fake = [
        {"id": "z", "keywords": ["array"], "warning": "array warning"},
        {"id": "a", "keywords": [r"\\sum", "aggregate sum"], "warning": "sum warning"},
        {"id": "b", "keywords": ["sum"], "warning": "token warning"},
    ]
    with patch.object(limitations, "entries", return_value=fake):
        ranked = limitations.retrieve(r"aggregate sum uses \\sum and array", limit=2)
        assert [item["id"] for item in ranked] == ["a", "b"]
        assert "RETRIEVED TOOLCHAIN GUARDRAILS" in limitations.prompt_guardrails("array")
        assert limitations.prompt_guardrails("unrelated mutex") == ""


def test_entries_loads_committed_json_and_is_cached():
    limitations.entries.cache_clear()
    first = limitations.entries()
    second = limitations.entries()
    assert first is second and first
    assert all({"id", "keywords", "warning"} <= item.keys() for item in first)


def test_refine_api_error_is_non_destructive():
    with (patch.object(refine, "_chat_fn", return_value=object()),
          patch.object(refine, "glm_refine", side_effect=LLMError("NETWORK", "offline"))):
        result = refine.refine(ORIGINAL, "repair", model="m")
    assert result.new_stub == ORIGINAL and not result.check_ok
    assert result.error == "[NETWORK] offline"
    assert result.diff == {"added": [], "removed": [], "common": []}


@pytest.mark.parametrize("valid,status", [(True, "VALIDATED_CANDIDATE"),
                                           (False, "INVALID_CANDIDATE")])
def test_refine_candidate_status_metadata_and_normalization(valid, status):
    candidate = """public class C {
//@ requires \\old(x) >= 0;
//@ ensures \\result >= 1;
public int value() { return 1; }
}"""
    draft = SpecDraft(candidate, assumptions=["x is bounded"], missing_info=["maximum x?"])
    with (patch.object(refine, "_chat_fn", return_value=object()),
          patch.object(refine, "glm_refine", return_value=(draft, "model-x", {})),
          patch.object(refine, "check_stub", return_value=(valid, [] if valid else ["bad"]))):
        result = refine.refine(ORIGINAL, "strengthen")
    assert result.status == status and result.check_ok is valid
    assert "requires x >= 0" in result.new_stub
    assert result.assumptions == ["x is bounded"] and result.model == "model-x"
    assert result.candidate_stub == result.new_stub


def _history(*rows):
    return [(code, [VC("A.java", line, category, detail=detail)], detail)
            for code, line, category, detail in rows]


def test_strategy_stall_fingerprint_ambiguity_and_short_history():
    assert strategy.is_stalled([]) == ""
    repeated = _history(("a", 1, "error", "same"),
                        ("b", 2, "other", "different"),
                        ("c", 1, "error", "same"))
    assert "error fingerprint repeated" in strategy.is_stalled(repeated)
    three = _history(("a", 1, "error", "same"),
                     ("b", 1, "error", "same"),
                     ("c", 1, "error", "same"))
    assert strategy.ambiguity_suspected(three)
    assert strategy.ambiguity_suspected(three[:2]) is None


def test_strategy_decision_terminal_and_budget_paths():
    failure = _history(("a", 1, "error", "one"))
    assert strategy.decide([], False, 0, 0).action == "sample"
    verified = strategy.decide(failure, True, 1, 0)
    assert verified.action == "stop" and verified.reason == "VERIFIED"
    capped = strategy.decide(failure, False, 1, 0, max_attempts=1)
    assert capped.action == "stop" and "max attempts" in capped.reason
    exhausted = strategy.decide(failure, False, 1, 4,
                                resample_budget=1, feedback_budget=4, max_attempts=9)
    assert exhausted.action == "stop" and "budget exhausted" in exhausted.reason
    stalled_history = _history(("a", 1, "error", "same"),
                               ("b", 2, "other", "different"),
                               ("c", 1, "error", "same"))
    stopped = strategy.decide(stalled_history, False, 1, 0, max_attempts=9)
    assert stopped.action == "stop" and "stalled" in stopped.reason
