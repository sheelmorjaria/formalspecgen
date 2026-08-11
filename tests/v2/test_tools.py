import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from pipeline.domain_v2_tools import (
    V2ToolProvenanceError, get_tlc_provenance, require_tlc_provenance,
    run_tlc_artifacts,
)


def completed(code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def test_dynamic_tlc_version_capture_records_exact_command():
    runner=Mock(return_value=completed(stdout="TLC2 Version 2.19 of 08 August 2024\n"))
    value=get_tlc_provenance("/tools/tla2tools.jar",java="/jdk/bin/java",runner=runner)
    assert value == {"version":"2.19 of 08 August 2024",
      "command":["/jdk/bin/java","-jar","/tools/tla2tools.jar","-help"],
      "status":"OK","exit_status":0}
    runner.assert_called_once_with(value["command"],capture_output=True,text=True,timeout=10)


@pytest.mark.parametrize("result", [completed(), completed(2,stderr="bad option")])
def test_missing_version_is_explicit_and_blocks_validation(result):
    value=get_tlc_provenance("tlc.jar",runner=Mock(return_value=result))
    assert value["status"] == "TOOL_VERSION_UNAVAILABLE"
    with pytest.raises(V2ToolProvenanceError): require_tlc_provenance(value)


def test_version_execution_failure_is_distinct_and_blocks_validation():
    runner=Mock(side_effect=subprocess.TimeoutExpired(["java"],10))
    value=get_tlc_provenance("tlc.jar",runner=runner)
    assert value["status"] == "TOOL_EXECUTION_FAILED"
    assert value["diagnostic"] == "TimeoutExpired"
    with pytest.raises(V2ToolProvenanceError): require_tlc_provenance(value)


def test_successful_tlc_execution_records_exit_status_and_uses_temp_files():
    def runner(command,**kwargs):
        root=Path(kwargs["cwd"])
        assert (root/"Model.tla").read_text() == "---- MODULE Model ----\n===="
        assert (root/"Model.cfg").read_text() == "SPECIFICATION Spec"
        return completed(stdout="Model checking completed. No error has been found.")
    value=run_tlc_artifacts("---- MODULE Model ----\n====","SPECIFICATION Spec",
      module_name="Model",tlc_jar="tlc.jar",runner=runner)
    assert value["status"] == "VERIFIED" and value["exit_status"] == 0
    assert value["command"][-3:] == ["-config","Model.cfg","Model.tla"]


def test_tlc_failure_and_execution_exception_are_not_verification():
    value=run_tlc_artifacts("x","y",module_name="Model",tlc_jar="tlc.jar",
      runner=Mock(return_value=completed(12,stderr="counterexample")))
    assert value["status"] == "TLC_FAILED" and value["exit_status"] == 12
    value=run_tlc_artifacts("x","y",module_name="Model",tlc_jar="tlc.jar",
      runner=Mock(side_effect=OSError("missing")))
    assert value["status"] == "TOOL_EXECUTION_FAILED"
    with pytest.raises(ValueError,match="unsafe"):
        run_tlc_artifacts("x","y",module_name="../bad",tlc_jar="tlc.jar")


def test_valid_provenance_passes_through_unchanged():
    value={"status":"OK","version":"2.19"}
    assert require_tlc_provenance(value) is value


def test_real_tlc_help_exit_status_is_not_mistaken_for_version_failure():
    result=completed(1,stdout="TLC - model checker - Version 2.19 of 08 August 2024\n")
    value=get_tlc_provenance("tlc.jar",runner=Mock(return_value=result))
    assert value["status"] == "OK"
    assert value["exit_status"] == 1
