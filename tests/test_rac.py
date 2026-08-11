import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from pipeline import rac
from pipeline.llm import LLMError


SOURCE = "public class Sample { public int value() { return 1; } }"
TEST_SOURCE = "public class SampleRuntimeTest {}"


def _runs(*results):
    iterator = iter(results)
    return lambda _command: next(iterator)


def test_collect_rac_rejects_source_without_class():
    result = rac.collect_rac_evidence("// no class")
    assert result == {"status": "INVALID_SOURCE", "inputs": [],
                      "message": "no public class found"}


def test_collect_rac_reports_compile_and_test_generation_failures():
    with patch.object(rac, "_run", _runs((1, "bad contract"))):
        result = rac.collect_rac_evidence(SOURCE)
    assert result["status"] == "RAC_COMPILE_FAILED"

    with (patch.object(rac, "_run", _runs((0, ""))),
          patch.object(rac, "generate_rac_tests",
                       side_effect=LLMError("API_ERROR", "offline"))):
        result = rac.collect_rac_evidence(SOURCE)
    assert result == {"status": "TESTGEN_ERROR", "inputs": [],
                      "message": "[API_ERROR] offline"}


def test_collect_rac_reports_generated_test_compile_failure():
    with (patch.object(rac, "_run", _runs((0, ""), (1, "bad test"))),
          patch.object(rac, "generate_rac_tests",
                       return_value=("class HiddenTest {}", "model-a", {}))):
        result = rac.collect_rac_evidence(SOURCE)
    assert result["status"] == "TEST_COMPILE_FAILED"
    assert result["test_code"] == "class HiddenTest {}"
    assert result["model"] == "model-a"


def test_collect_rac_returns_counterexample_evidence_not_proof():
    output = """FORMALSPEC_INPUT: amount=-1
verify: JML postcondition is false
[ 2 tests successful ]
[ 1 tests failed ]
"""
    commands = []

    def run(command):
        commands.append(command)
        return [(0, ""), (0, ""), (1, output)][len(commands) - 1]

    with (patch.object(rac, "_run", run),
          patch.object(rac, "generate_rac_tests",
                       return_value=(TEST_SOURCE, "model-b", {}))):
        result = rac.collect_rac_evidence(SOURCE)
    assert result["status"] == "RUNTIME_FAILURES_FOUND"
    assert result["claim"] == "COUNTEREXAMPLE_EVIDENCE"
    assert result["proof"] is False
    assert result["regeneration_recommended"] is True
    assert result["inputs"] == ["amount=-1"]
    assert result["passed"] == 2 and result["failed"] == 1
    assert "SampleRuntimeTest" in commands[-1]


def test_collect_rac_no_failure_remains_runtime_sample():
    output = "[ 3 tests successful ]\n[ 0 tests failed ]"
    with (patch.object(rac, "_run", _runs((0, ""), (0, ""), (0, output))),
          patch.object(rac, "generate_rac_tests",
                       return_value=(TEST_SOURCE, "model", {}))):
        result = rac.collect_rac_evidence(SOURCE)
    assert result["status"] == "NO_RUNTIME_FAILURE_FOUND"
    assert result["claim"] == "RUNTIME_SAMPLE"
    assert result["proof"] is False
    assert result["regeneration_recommended"] is False


def test_collect_integration_requires_orchestrator():
    result = rac.collect_integration_evidence({"Service.java": SOURCE})
    assert result["status"] == "NO_ORCHESTRATOR"


def test_collect_integration_failure_paths():
    files = {"BankOrchestrator.java": "public class BankOrchestrator {}"}
    with patch.object(rac, "_run", _runs((1, "compile failed"))):
        assert rac.collect_integration_evidence(files)["status"] == "RAC_COMPILE_FAILED"

    with (patch.object(rac, "_run", _runs((0, ""))),
          patch.object(rac, "generate_rac_tests",
                       side_effect=LLMError("API_ERROR", "no model"))):
        assert rac.collect_integration_evidence(files)["status"] == "TESTGEN_ERROR"

    with (patch.object(rac, "_run", _runs((0, ""), (1, "bad junit"))),
          patch.object(rac, "generate_rac_tests",
                       return_value=("class Generated {}", "m", {}))):
        result = rac.collect_integration_evidence(files)
    assert result["status"] == "TEST_COMPILE_FAILED"
    assert result["model"] == "m"


def test_collect_integration_pass_and_failure_evidence():
    files = {"BankOrchestrator.java": "public class BankOrchestrator {}"}
    for summary, expected in [
        ("[ 2 tests successful ]\n[ 0 tests failed ]", "TESTS_PASSED"),
        ("FORMALSPEC_INPUT: timeout=true\nJML invariant failed\n"
         "[ 1 tests successful ]\n[ 1 tests failed ]", "TESTS_FAILED"),
    ]:
        with (patch.object(rac, "_run", _runs((0, ""), (0, ""), (0, summary))),
              patch.object(rac, "generate_rac_tests",
                           return_value=(TEST_SOURCE, "integration-model", {}))):
            result = rac.collect_integration_evidence(files)
        assert result["status"] == expected
        assert "not a proof" in result["disclaimer"]


def test_run_normalizes_process_timeout_and_missing_tool():
    completed = SimpleNamespace(returncode=3, stdout="out", stderr="err")
    with patch.object(rac.subprocess, "run", return_value=completed) as run:
        assert rac._run(["tool"]) == (3, "outerr")
        assert run.call_args.kwargs["timeout"] == rac.config.RAC_TIMEOUT

    with patch.object(rac.subprocess, "run", side_effect=subprocess.TimeoutExpired("x", 1)):
        code, message = rac._run(["tool"])
    assert code == 124 and "timed out" in message

    with patch.object(rac.subprocess, "run", side_effect=FileNotFoundError(2, "missing", "tool")):
        assert rac._run(["tool"]) == (127, "<tool not found: tool>")


def test_summary_count_handles_present_and_missing_labels():
    assert rac._summary_count("[ 17 tests successful ]", "tests successful") == 17
    assert rac._summary_count("nothing", "tests failed") == 0
