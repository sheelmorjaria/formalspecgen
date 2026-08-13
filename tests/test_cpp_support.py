from unittest.mock import patch

from pipeline.cpp_support import check_cpp_syntax


def test_cpp_syntax_gate_reports_compiler_outcomes():
    with patch("pipeline.cpp_support.shutil.which", return_value=None):
        assert check_cpp_syntax("int main(){}")["status"] == "TOOL_MISSING"
    with patch("pipeline.cpp_support.shutil.which", return_value="g++"), \
         patch("pipeline.cpp_support.subprocess.run") as run:
        run.return_value = type("Result", (), {
            "returncode": 0, "stdout": "", "stderr": ""})()
        assert check_cpp_syntax("int main(){}")["status"] == "CPP_CHECKED"
        run.return_value = type("Result", (), {
            "returncode": 1, "stdout": "", "stderr": "bad"})()
        assert check_cpp_syntax("bad")["status"] == "CPP_CHECK_FAILED"
        from subprocess import TimeoutExpired
        run.side_effect = TimeoutExpired("g++", 1)
        assert check_cpp_syntax("int main(){}")["status"] == "TIMEOUT"
