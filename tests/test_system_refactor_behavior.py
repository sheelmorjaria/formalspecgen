from pathlib import Path
from unittest.mock import patch

from pipeline.system_orchestrator import refactor_system


def _component(tmp_path, pattern="extract-method"):
    source = tmp_path / "Legacy.java"
    source.write_text("public class Legacy { public void process() {} }", encoding="utf-8")
    return {"component": "legacy", "file": str(source), "pattern": pattern, "method": "process"}


def test_refactor_system_extracts_components_and_preserves_contract(tmp_path):
    item = _component(tmp_path)
    inspection = {"status": "INSPECTED", "findings": [{"code": "long-method", "method": "process"}]}
    transformed = {"status": "TRANSFORMED", "source": "public class Legacy {}"}
    proof = {"status": "VERIFIED", "claim": "REFACTOR_CONTRACT_PRESERVED"}
    with patch("pipeline.system_orchestrator.inspect_java_file", return_value=inspection), \
         patch("pipeline.system_orchestrator.extract_method_from_inspection", return_value=transformed), \
         patch("pipeline.system_orchestrator.verify_contract_preserving_refactor", return_value=proof):
        result = refactor_system({"components": [item]}, out_dir=tmp_path / "out")
    assert result["status"] == "SYSTEM_REFACTOR_VERIFIED"
    assert result["claim"] == "SYSTEM_REFACTOR_CONTRACTS_PRESERVED"
    assert result["components"][0]["pattern"] == "extract-method"


def test_refactor_system_factory_and_composition_gate(tmp_path):
    item = _component(tmp_path, "factory-method")
    inspection = {"status": "INSPECTED", "findings": [{"code": "conditional-object-creation", "method": "create"}]}
    item["method"] = "create"
    transformed = {"status": "TRANSFORMED", "files": {"Legacy.java": "class Legacy {}", "Factory.java": "interface Factory {}"}}
    proof = {"status": "VERIFIED", "claim": "MULTIFILE_REFACTOR_CONTRACT_PRESERVED"}
    composition = {"status": "COMPOSITION_VERIFIED", "claim": "SCOPED_COMPOSITION_PROOF"}
    with patch("pipeline.system_orchestrator.inspect_java_file", return_value=inspection), \
         patch("pipeline.system_orchestrator.extract_factory_from_inspection", return_value=transformed), \
         patch("pipeline.system_orchestrator.verify_multifile_contract_refactor", return_value=proof), \
         patch("pipeline.composition_render.verify_composition", return_value=composition):
        result = refactor_system({"components": [item], "composition": {"schema_version": 1}}, out_dir=tmp_path / "out")
    assert result["claim"] == "SYSTEM_COMPOSITION_PROOF"
    assert result["composition"]["status"] == "COMPOSITION_VERIFIED"


def test_refactor_system_fails_closed_for_empty_source_transform_and_composition(tmp_path):
    assert refactor_system({"components": []}, out_dir=tmp_path)["code"] == "invalid_refactor_artifact"
    missing = {"components": [{"component": "missing", "file": str(tmp_path / "missing.java")}]} 
    assert refactor_system(missing, out_dir=tmp_path)["status"] == "SYSTEM_REFACTOR_FAILED"
    item = _component(tmp_path)
    inspection = {"status": "INSPECTED", "findings": []}
    with patch("pipeline.system_orchestrator.inspect_java_file", return_value=inspection):
        result = refactor_system({"components": [item]}, out_dir=tmp_path / "none")
    assert result["components"][0]["code"] == "no_supported_refactoring_finding"
    with patch("pipeline.system_orchestrator.inspect_java_file", return_value={"findings": [{"code": "long-method", "method": "process"}]}), \
         patch("pipeline.system_orchestrator.extract_method_from_inspection", return_value={"status": "FAIL"}):
        result = refactor_system({"components": [item]}, out_dir=tmp_path / "transform")
    assert result["components"][0]["code"] == "refactor_transform_failed"
