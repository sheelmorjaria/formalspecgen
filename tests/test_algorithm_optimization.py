from pathlib import Path
from unittest.mock import patch

from pipeline.algorithm_optimization import optimize_algorithm


SOURCE = '''public class TwoSum {
    //@ requires nums != null;
    //@ ensures nums != null;
    public int solve(int[] nums) { return nums.length; }
}
'''


def test_optimization_rejects_explicit_complexity_regression(tmp_path):
    source = tmp_path / "TwoSum.java"; source.write_text(SOURCE)
    result = optimize_algorithm(source, tmp_path / "optimized.java", strategy="nested_loop")
    assert result["code"] == "complexity_regression_possible"


def test_optimization_rejects_unknown_and_missing_input(tmp_path):
    assert optimize_algorithm(tmp_path / "x.java", tmp_path / "out.java", strategy="unknown")["code"] == "unsupported_strategy"
    assert optimize_algorithm(tmp_path / "x.java", tmp_path / "out.java", strategy="hashmap")["code"] == "input_unavailable"


def test_optimization_generation_surface_candidate_and_gate_failures(tmp_path):
    source = tmp_path / "x.java"; source.write_text("public class X {}")
    with patch("pipeline.algorithm_optimization.verify", return_value=(0, "")), \
         patch("pipeline.algorithm_optimization._chat_fn", side_effect=RuntimeError("offline")):
        assert optimize_algorithm(source, tmp_path / "out.java", strategy="hashmap")["code"] == "optimization_generation_failed"
    with patch("pipeline.algorithm_optimization.verify", return_value=(0, "")), \
         patch("pipeline.algorithm_optimization._chat_fn", return_value=lambda *_: ("class Changed {}", "m", {})), \
         patch("pipeline.algorithm_optimization.trusted_surface_matches", return_value=(False, ["changed"])):
        assert optimize_algorithm(source, tmp_path / "out.java", strategy="hashmap")["code"] == "trusted_surface_changed"


def test_optimization_preserves_surface_and_mints_scoped_claim(tmp_path):
    source = tmp_path / "TwoSum.java"; source.write_text(SOURCE)
    destination = tmp_path / "optimized" / "TwoSum.java"
    with patch("pipeline.algorithm_optimization.verify", side_effect=[(0, "baseline"), (0, "optimized")]), \
            patch("pipeline.algorithm_optimization._chat_fn",
                  return_value=lambda *_args: ("```java\n" + SOURCE + "```", "test-model", {})), \
            patch("pipeline.algorithm_optimization.verify_contract_preserving_refactor",
                  return_value={"status": "VERIFIED", "claim": "REFACTOR_CONTRACT_PRESERVED"}):
        result = optimize_algorithm(source, destination, strategy="hashmap")
    assert result["claim"] == "ALGORITHM_OPTIMIZATION_VERIFIED"
    assert result["behavior_equivalence_proved"] is False
    assert destination.exists()
