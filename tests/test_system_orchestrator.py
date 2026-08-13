import json
import copy
from pathlib import Path
from unittest.mock import MagicMock, patch

from pipeline.system_orchestrator import parse_system, verify_system


def system_value(tmp_path):
    architecture = {"name": "Shop", "description": "shop", "components": [
        {"id": "order", "name": "Order", "layer": "entities", "kind": "class",
         "operations": [], "dependencies": []},
        {"id": "payment", "name": "Payment", "layer": "entities", "kind": "class",
         "operations": [], "dependencies": []}], "use_cases": []}
    composition = {"schema_version": 1, "system_name": "Shop",
        "architecture": architecture,
        "bindings": [{"component": "order", "module_name": "order"},
                     {"component": "payment", "module_name": "payment"}],
        "use_cases": [{"name": "Checkout", "steps": [
            {"component": "order", "operation": "Place"},
            {"component": "payment", "operation": "Pay"}]}]}
    return {"schema_version": 1, "system_name": "Shop", "composition": composition,
        "components": [{"component": name, "interface_file": str(tmp_path / f"{name}.rs"),
            "reviewed_domain": str(tmp_path / f"{name}.json"),
            "validation_evidence": str(tmp_path / f"{name}.validation.json")}
            for name in ("order", "payment")]}


def popen_factory(outcomes):
    def popen(command, **_kwargs):
        component = Path(command[2]).stem
        verdict = Path(command[command.index("--json") + 1])
        verdict.write_text(json.dumps(outcomes[component][1]), encoding="utf-8")
        process = MagicMock(returncode=outcomes[component][0])
        process.communicate.return_value = ("done", "")
        return process
    return popen


def test_system_parses_and_spawns_one_isolated_process_per_component(tmp_path):
    value = system_value(tmp_path)
    assert len(parse_system(value).components) == 2
    gate = MagicMock(return_value={"status": "COMPOSITION_VERIFIED",
                                   "claim": "SCOPED_COMPOSITION_PROOF"})
    verified = {name: (0, {"final_status": "VERIFIED", "claim": "DEDUCTIVE_PROOF"})
                for name in ("order", "payment")}
    result = verify_system(value, out_dir=tmp_path / "runs", max_workers=2,
                           popen=popen_factory(verified), composition_gate=gate)
    assert result["status"] == "SYSTEM_SYNTHESIS_VERIFIED"
    assert len(result["components"]) == 2
    assert all(item["command"][1] == "implement" for item in result["components"])
    gate.assert_called_once()


def test_system_component_failure_blocks_composition(tmp_path):
    gate = MagicMock()
    outcomes = {"order": (0, {"claim": "DEDUCTIVE_PROOF"}),
                "payment": (1, {"claim": "NO_PROOF"})}
    result = verify_system(system_value(tmp_path), out_dir=tmp_path / "runs",
                           popen=popen_factory(outcomes), composition_gate=gate)
    assert result["status"] == "SYSTEM_SYNTHESIS_FAILED"
    assert result["code"] == "component_verification_failed"
    gate.assert_not_called()


def test_system_fails_closed_on_schema_worker_and_composition_boundaries(tmp_path):
    assert verify_system({}, out_dir=tmp_path)["code"] == "invalid_system_artifact"
    assert verify_system(system_value(tmp_path), out_dir=tmp_path,
                         max_workers=0)["code"] == "invalid_worker_count"
    outcomes = {name: (0, {"claim": "DEDUCTIVE_PROOF"})
                for name in ("order", "payment")}
    result = verify_system(system_value(tmp_path), out_dir=tmp_path / "runs",
        popen=popen_factory(outcomes), composition_gate=lambda _value: {"status": "CHECK_FAILED"})
    assert result["code"] == "composition_verification_failed"


def test_system_schema_rejects_duplicate_missing_and_mismatched_components(tmp_path):
    value = system_value(tmp_path)
    duplicate = copy.deepcopy(value); duplicate["components"][1]["component"] = "order"
    assert verify_system(duplicate, out_dir=tmp_path)["code"] == "invalid_system_artifact"
    missing = copy.deepcopy(value); missing["components"].pop()
    assert verify_system(missing, out_dir=tmp_path)["code"] == "invalid_system_artifact"
    mismatch = copy.deepcopy(value); mismatch["system_name"] = "Other"
    assert verify_system(mismatch, out_dir=tmp_path)["code"] == "invalid_system_artifact"
    unsafe = copy.deepcopy(value); unsafe["components"][0]["component"] = "../order"
    assert verify_system(unsafe, out_dir=tmp_path)["code"] == "invalid_system_artifact"
    assert parse_system(json.dumps(value)).system_name == "Shop"


def test_system_missing_verdict_and_process_launch_failure_are_component_failures(tmp_path):
    def no_verdict(command, **_kwargs):
        process = MagicMock(returncode=0)
        process.communicate.return_value = ("", "")
        return process
    result = verify_system(system_value(tmp_path), out_dir=tmp_path / "missing",
                           popen=no_verdict)
    assert result["code"] == "component_verification_failed"
    assert all(item["verdict"]["final_status"] == "MISSING_VERDICT"
               for item in result["components"])

    def cannot_launch(*_args, **_kwargs):
        raise OSError("executable missing")
    result = verify_system(system_value(tmp_path), out_dir=tmp_path / "launch",
                           popen=cannot_launch)
    assert result["code"] == "component_verification_failed"
    assert all(item["exit_code"] == 127 for item in result["components"])


def test_system_uses_default_composition_gate(tmp_path):
    outcomes = {name: (0, {"claim": "DEDUCTIVE_PROOF"})
                for name in ("order", "payment")}
    with patch("pipeline.composition_render.verify_composition",
            return_value={"status": "COMPOSITION_VERIFIED",
                          "claim": "SCOPED_COMPOSITION_PROOF"}) as gate:
        result = verify_system(system_value(tmp_path), out_dir=tmp_path / "default",
                               popen=popen_factory(outcomes))
    assert result["status"] == "SYSTEM_SYNTHESIS_VERIFIED"
    gate.assert_called_once()
