import subprocess
from unittest.mock import patch

from pipeline.verify_cpp import verify_cpp


def test_cpp_verifier_builds_harness_for_classes(tmp_path):
    source = tmp_path / "Counter.cpp"
    source.write_text("class Counter { public: void tick() {} int value() { return 1; } };", encoding="utf-8")
    result = type("R", (), {"returncode": 0, "stdout": "ESBMC: Verification successful", "stderr": ""})()
    with patch("pipeline.verify_cpp.subprocess.run", return_value=result) as run:
        verdict = verify_cpp(source, unwind=3)
    assert verdict["status"] == "VERIFIED"
    assert verdict["claim"] == "BOUNDED_CPP_PROOF"
    assert run.call_args.args[0][2:4] == ["--unwind", "3"]


def test_cpp_verifier_handles_generic_units_and_tool_failures(tmp_path):
    source = tmp_path / "main.cpp"; source.write_text("int main() { return 0; }", encoding="utf-8")
    failed = type("R", (), {"returncode": 1, "stdout": "failed", "stderr": ""})()
    with patch("pipeline.verify_cpp.subprocess.run", return_value=failed):
        assert verify_cpp(source)["status"] == "VERIFY_FAILED"
    with patch("pipeline.verify_cpp.subprocess.run", side_effect=FileNotFoundError):
        assert verify_cpp(source)["status"] == "TOOL_MISSING"
    with patch("pipeline.verify_cpp.subprocess.run", side_effect=subprocess.TimeoutExpired("esbmc", 1)):
        assert verify_cpp(source)["status"] == "TIMEOUT"
