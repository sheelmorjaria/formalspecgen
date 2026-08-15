from unittest.mock import patch

from pipeline.algorithm_discovery import STRATEGY_REGISTRY, discover_algorithms, _candidate


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


def test_discovery_rejects_missing_input_and_no_verified_candidates(tmp_path):
    missing = discover_algorithms(tmp_path / "missing.java")
    assert missing["code"] == "input_unavailable"
    source = tmp_path / "Spec.java"; source.write_text("class Spec {}")
    with patch("pipeline.algorithm_discovery._candidate", return_value={"strategy": "brute_force", "status": "FAIL", "complexity": "O(n^2)"}):
        result = discover_algorithms(source, strategies=["brute_force"], max_workers=1)
    assert result["status"] == "FAIL" and result["claim"] == "NO_PROOF"


def test_candidate_generation_surface_verification_and_gate_failures(tmp_path):
    source = tmp_path / "Spec.java"; source.write_text("public class Spec {}")
    destination = tmp_path / "out.java"
    with patch("pipeline.algorithm_discovery._chat_fn", side_effect=RuntimeError("offline")):
        assert _candidate(source, destination, "hashmap", "ollama", None)["code"] == "generation_failed"
    with patch("pipeline.algorithm_discovery._chat_fn", return_value=lambda *_: ("class Changed {}", "m", {})), \
         patch("pipeline.algorithm_discovery.trusted_surface_matches", return_value=(False, ["method changed"])):
        assert _candidate(source, destination, "hashmap", "ollama", None)["code"] == "trusted_surface_changed"
    with patch("pipeline.algorithm_discovery._chat_fn", return_value=lambda *_: ("public class Spec {}", "m", {})), \
         patch("pipeline.algorithm_discovery.trusted_surface_matches", return_value=(True, [])), \
         patch("pipeline.algorithm_discovery.verify", return_value=(1, "bad")):
        assert _candidate(source, destination, "hashmap", "ollama", None)["code"] == "candidate_not_verified"
