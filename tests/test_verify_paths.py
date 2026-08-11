import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pipeline import verify


def test_command_omits_missing_specs_and_supports_multiple_files(tmp_path):
    missing = tmp_path / "missing-specs"
    with (patch.object(verify.config, "OPENJML", "ojml"),
          patch.object(verify.config, "OPENJML_SPECS", str(missing))):
        assert verify._command("esc", ["A.java", Path("B.java")]) == [
            "ojml", "-esc", "A.java", "B.java"]


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


def test_verify_selects_default_timeouts_and_combines_output():
    completed = SimpleNamespace(returncode=6, stdout="stdout", stderr="stderr")
    with patch.object(verify.subprocess, "run", return_value=completed) as run:
        assert verify.verify("A.java", mode="esc") == (6, "stdoutstderr")
    assert run.call_args.kwargs["timeout"] == verify.config.ESC_TIMEOUT
    assert run.call_args.kwargs["encoding"] == "utf-8"

    with patch.object(verify.subprocess, "run", return_value=completed) as run:
        verify.verify("A.java", mode="parse", timeout=9)
    assert run.call_args.kwargs["timeout"] == 9


def test_verify_normalizes_timeout_and_missing_binary():
    with patch.object(verify.subprocess, "run",
                      side_effect=subprocess.TimeoutExpired("openjml", 3)):
        assert verify.verify("A.java", timeout=3) == (
            verify.TIMEOUT_EXIT, "<openjml -check timed out after 3s>")
    with patch.object(verify.subprocess, "run", side_effect=FileNotFoundError):
        code, message = verify.verify("A.java")
    assert code == 127 and "binary not found" in message


def test_verify_files_success_timeout_missing_and_default_timeout():
    completed = SimpleNamespace(returncode=0, stdout="ok", stderr="")
    with patch.object(verify.subprocess, "run", return_value=completed) as run:
        assert verify.verify_files(["A.java", "B.java"], mode="check") == (0, "ok")
    assert run.call_args.kwargs["timeout"] == verify.config.CHECK_TIMEOUT

    with patch.object(verify.subprocess, "run",
                      side_effect=subprocess.TimeoutExpired("openjml", 4)):
        assert verify.verify_files(["A.java"], mode="esc", timeout=4) == (
            verify.TIMEOUT_EXIT, "<openjml -esc timed out after 4s>")
    with patch.object(verify.subprocess, "run", side_effect=FileNotFoundError):
        assert verify.verify_files(["A.java"])[0] == 127


@pytest.mark.parametrize("exit_code,status", [
    (0, "VERIFIED"), (6, "VERIFY_FAILED"), (1, "COMPILE_FAILED"),
    (124, "TIMEOUT"), (125, "TOOL_ERROR"), (127, "TOOL_MISSING"),
    (42, "UNKNOWN_EXIT_42"),
])
def test_classify_all_exit_categories(exit_code, status):
    assert verify.classify(exit_code) == status
