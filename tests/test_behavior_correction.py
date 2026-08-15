from unittest.mock import patch

from pipeline.behavior_correction import correct_behavior


SOURCE = """public class UnsafeService {
    //@ requires arr != null;
    public int getElement(int[] arr, int index) { return arr[index]; }
}
"""
STRENGTHENED = """public class UnsafeService {
    //@ requires arr != null;
    //@ ensures (0 <= index && index < arr.length) ==> \\result == arr[index];
    //@ ensures !(0 <= index && index < arr.length) ==> \\result == -1;
    public int getElement(int[] arr, int index) {
        if (index < 0 || index >= arr.length) return -1;
        return arr[index];
    }
}
"""


def test_correct_behavior_mints_hash_bound_claim(tmp_path):
    source = tmp_path / "UnsafeService.java"
    source.write_text(SOURCE)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify", side_effect=[(1, "Postcondition"), (0, "")]):
        chat.return_value.return_value = (STRENGTHENED, "test", {})
        result = correct_behavior(source, "CWE-125", tmp_path / "out")
    assert result["claim"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert result["mitigated_cwe"] == "CWE-125"
    assert result["baseline_contract_hash"] != result["strengthened_contract_hash"]
    assert result["corrected_implementation_hash"]


def test_correct_behavior_fails_closed_after_retries(tmp_path):
    source = tmp_path / "UnsafeService.java"
    source.write_text(SOURCE)
    with patch("pipeline.behavior_correction._chat_fn") as chat, \
         patch("pipeline.behavior_correction.verify", return_value=(1, "bad")):
        chat.return_value.return_value = (SOURCE, "test", {})
        result = correct_behavior(source, "CWE-125", tmp_path / "out", max_attempts=2)
    assert result["status"] == "CORRECTION_FAILED"
    assert result["claim"] == "NO_PROOF"
