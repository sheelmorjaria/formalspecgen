from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline import verify
from pipeline.execution import ExecutionObservation


class FakeExecutor:
    def __init__(self, status="COMPLETED", exit_code=0, output=""):
        self.status = status
        self.exit_code = exit_code
        self.output = output
        self.request = None

    def execute(self, request):
        self.request = request
        compliance = "NOT_ENFORCED" if self.status == "SANDBOX_UNAVAILABLE" else "ENFORCED"
        return ExecutionObservation(
            status=self.status, exit_code=self.exit_code, output=self.output,
            requested_policy={}, enforced_policy={} if compliance == "ENFORCED" else None,
            policy_compliance=compliance,
            snapshot_manifest_sha256=request.snapshot.manifest_sha256,
            timed_out=self.status == "TIMEOUT", message="sandbox unavailable",
            tool=request.tool, command=request.command,
            readonly_paths=tuple(str(path) for path in request.readonly_paths))


def _tool_and_source(tmp_path, name="A.java"):
    tool = tmp_path / "openjml"
    tool.write_text("tool", encoding="utf-8")
    source = tmp_path / name
    source.write_text(f"class {Path(name).stem} {{}}", encoding="utf-8")
    return tool, source


def test_command_omits_missing_specs_and_supports_multiple_files(tmp_path):
    missing = tmp_path / "missing-specs"
    with (patch.object(verify.config, "OPENJML", "ojml"),
          patch.object(verify.config, "OPENJML_SPECS", str(missing))):
        assert verify._command("esc", ["A.java", Path("B.java")]) == [
            "ojml", "-esc", "A.java", "B.java"]
    specs = tmp_path / "specs"; specs.mkdir()
    with (patch.object(verify.config, "OPENJML", "ojml"),
          patch.object(verify.config, "OPENJML_SPECS", str(specs))):
        assert verify._command("check", ["A.java"]) == [
            "ojml", "-check", "--specs-path", str(specs), "A.java"]


def test_dropped_vc_and_tool_result_detection():
    assert verify.has_dropped_vc("Not yet supported feature: x")
    assert verify.has_dropped_vc("Not implemented for static checking")
    assert not verify.has_dropped_vc("all obligations checked")
    assert verify._tool_result(1, "Could not locate the internal specifications files")[0] == 125
    assert verify._tool_result(6, "ordinary VC failure") == (6, "ordinary VC failure")


@pytest.mark.parametrize("function,args", [
    (verify.verify, ("A.java",)),
    (verify.verify_files, (["A.java", "B.java"],)),
])
def test_verify_wrappers_reject_unknown_modes(function, args):
    with pytest.raises(ValueError, match="mode must be one of"):
        function(*args, mode="prove")


def test_verify_selects_default_timeouts_and_combines_output(tmp_path):
    tool, source = _tool_and_source(tmp_path)
    executor = FakeExecutor(exit_code=6, output="stdoutstderr")
    with patch.object(verify.config, "OPENJML", str(tool)):
        assert verify.verify(source, mode="esc", executor=executor) == (6, "stdoutstderr")
    assert executor.request.policy.timeout_s == verify.config.ESC_TIMEOUT
    assert executor.request.policy.max_processes == 128
    assert executor.request.command[-1] == "/input/A.java"

    executor = FakeExecutor(exit_code=6)
    with patch.object(verify.config, "OPENJML", str(tool)):
        verify.verify(source, mode="parse", timeout=9, executor=executor)
    assert executor.request.policy.timeout_s == 9


def test_verify_normalizes_timeout_and_missing_binary(tmp_path):
    tool, source = _tool_and_source(tmp_path)
    with patch.object(verify.config, "OPENJML", str(tool)):
        assert verify.verify(source, timeout=3, executor=FakeExecutor(
            status="TIMEOUT", exit_code=124)) == (
                verify.TIMEOUT_EXIT, "<openjml -check timed out after 3s>")
    with patch.object(verify.config, "OPENJML", str(tmp_path / "missing")):
        code, message = verify.verify(source)
    assert code == 127 and "binary not found" in message


def test_verify_files_success_timeout_missing_and_default_timeout(tmp_path):
    tool, first = _tool_and_source(tmp_path)
    second = tmp_path / "B.java"; second.write_text("class B {}", encoding="utf-8")
    executor = FakeExecutor(output="ok")
    with patch.object(verify.config, "OPENJML", str(tool)):
        assert verify.verify_files([first, second], mode="check", executor=executor) == (0, "ok")
    assert executor.request.policy.timeout_s == verify.config.CHECK_TIMEOUT

    with patch.object(verify.config, "OPENJML", str(tool)):
        assert verify.verify_files([first], mode="esc", timeout=4, executor=FakeExecutor(
            status="TIMEOUT", exit_code=124)) == (
                verify.TIMEOUT_EXIT, "<openjml -esc timed out after 4s>")
    with patch.object(verify.config, "OPENJML", str(tmp_path / "missing")):
        assert verify.verify_files([first])[0] == 127


def test_verify_fails_closed_when_sandbox_is_unavailable(tmp_path):
    tool, source = _tool_and_source(tmp_path)
    with patch.object(verify.config, "OPENJML", str(tool)):
        code, message = verify.verify(
            source, executor=FakeExecutor(status="SANDBOX_UNAVAILABLE", exit_code=125))
    assert code == verify.TOOL_ERROR_EXIT
    assert "policy not enforced" in message


def test_verify_rejects_missing_and_duplicate_snapshot_inputs(tmp_path):
    tool, source = _tool_and_source(tmp_path)
    with patch.object(verify.config, "OPENJML", str(tool)):
        code, message = verify.verify(tmp_path / "missing.java", executor=FakeExecutor())
        assert code == verify.TOOL_ERROR_EXIT and "source file unavailable" in message

        other = tmp_path / "other"; other.mkdir()
        duplicate = other / source.name
        duplicate.write_text("class A {}", encoding="utf-8")
        code, message = verify.verify_files([source, duplicate], executor=FakeExecutor())
        assert code == verify.TOOL_ERROR_EXIT and "duplicate" in message


def test_verify_resolves_path_tool_and_rejects_excess_output(tmp_path):
    _tool, source = _tool_and_source(tmp_path)
    resolved = tmp_path / "resolved-openjml"
    resolved.write_text("tool", encoding="utf-8")
    executor = FakeExecutor(
        status="OUTPUT_LIMIT_EXCEEDED", exit_code=126, output="partial")
    with patch.object(verify.config, "OPENJML", "openjml"), \
         patch.object(verify.shutil, "which", return_value=str(resolved)):
        code, message = verify.verify(source, executor=executor)
    assert code == verify.TOOL_ERROR_EXIT
    assert message == "partial\n<openjml resource failure: OUTPUT_LIMIT_EXCEEDED>"


def test_detailed_result_preserves_exact_execution_and_specs_path(tmp_path):
    tool, source = _tool_and_source(tmp_path)
    specs = tmp_path / "specs"
    specs.mkdir()
    executor = FakeExecutor(output="ok")
    with patch.object(verify.config, "OPENJML", str(tool)), \
         patch.object(verify.config, "OPENJML_SPECS", str(specs)):
        result = verify.verify_detailed(source, mode="esc", executor=executor)
    assert result.exit_code == 0 and result.observation is not None
    assert result.observation.command == executor.request.command
    assert "--specs-path" in result.observation.command
    assert str(specs.resolve()) in result.observation.command
    assert result.as_dict()["execution"]["snapshot_manifest_sha256"] == \
        executor.request.snapshot.manifest_sha256


def test_jml_input_preserves_reviewed_bytes_and_executes_as_java(tmp_path):
    tool, source = _tool_and_source(tmp_path, "Probe.jml")
    executor = FakeExecutor(output="ok")
    with patch.object(verify.config, "OPENJML", str(tool)):
        result = verify.verify_detailed(source, mode="esc", executor=executor)
    assert result.exit_code == 0
    assert executor.request.command[-1] == "/input/Probe.java"
    records = {item["path"]: item for item in executor.request.snapshot.manifest}
    assert set(records) == {"Probe.java", "reviewed/Probe.jml"}
    assert records["Probe.java"]["sha256"] == records["reviewed/Probe.jml"]["sha256"]


@pytest.mark.parametrize("exit_code,status", [
    (0, "VERIFIED"), (6, "VERIFY_FAILED"), (1, "COMPILE_FAILED"),
    (124, "TIMEOUT"), (125, "TOOL_ERROR"), (127, "TOOL_MISSING"),
    (42, "UNKNOWN_EXIT_42"),
])
def test_classify_all_exit_categories(exit_code, status):
    assert verify.classify(exit_code) == status
