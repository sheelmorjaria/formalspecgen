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
