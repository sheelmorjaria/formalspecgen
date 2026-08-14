from unittest.mock import patch

from pipeline.algorithm_discovery import STRATEGY_REGISTRY, discover_algorithms


def test_strategy_registry_contains_deterministic_prompts():
    assert "sliding_window" in STRATEGY_REGISTRY
    assert "O(n)" in STRATEGY_REGISTRY["sliding_window"]["complexity"]
    assert "two-pointer" in STRATEGY_REGISTRY["two_pointer"]["instruction"]
    for strategy in ("prefix_sum", "bit_manipulation", "dynamic_programming"):
        assert strategy in STRATEGY_REGISTRY
        assert STRATEGY_REGISTRY[strategy]["complexity"]


def test_discovery_collects_and_ranks_verified_candidates(tmp_path):
    source = tmp_path / "Spec.java"
    source.write_text("public class Spec {}", encoding="utf-8")

    def fake_candidate(_source, destination, strategy, _provider, _model):
        if strategy == "two_pointer":
            return {"strategy": strategy, "status": "VERIFIED", "complexity": "O(n)",
                    "file": str(destination)}
        return {"strategy": strategy, "status": "FAIL", "complexity": "O(n^2)",
                "code": "candidate_not_verified"}

    with patch("pipeline.algorithm_discovery._candidate", side_effect=fake_candidate):
        result = discover_algorithms(source, tmp_path / "out",
                                     strategies=["brute_force", "two_pointer"], max_workers=2)
    assert result["claim"] == "ALGORITHM_DISCOVERY_COMPLETE"
    assert [item["strategy"] for item in result["verified_candidates"]] == ["two_pointer"]
    assert result["failed_strategies"] == ["brute_force"]


def test_discovery_rejects_unknown_strategy(tmp_path):
    source = tmp_path / "Spec.java"
    source.write_text("public class Spec {}", encoding="utf-8")
    result = discover_algorithms(source, strategies=["unknown"])
    assert result["code"] == "unsupported_strategy"
