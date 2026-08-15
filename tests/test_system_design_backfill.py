# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Backfill coverage: staged design_system flow, reviewed-domain lowering, system refactor."""
import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline import system_design
from pipeline.staged_architecture import UnifiedArchitecture
from pipeline.system_orchestrator import refactor_system
from pipeline.unified_system_runner import (
    _domain_dict,
    _load_reviewed_domain,
    lower_component,
    run_unified_system,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

# The requirement quotes a reviewed V2 domain so the deterministic binder in
# design_system_staged attaches it to the matching component.
DOMAIN_REQUIREMENT = ("Use the reviewed 'inventory' domain for the Inventory component "
                      "and keep a separate bounded Ledger component.")


def _scripted_chat(replies):
    """Answer prompts by unique substring; per-marker queues pop one reply per call."""
    def chat(messages, _model, _temperature):
        prompt = messages[-1]["content"]
        for marker, queue in replies.items():
            if marker in prompt:
                assert queue, f"script exhausted for marker: {marker}"
                return queue.pop(0), "scripted", {}
        raise AssertionError(f"unscripted prompt: {prompt[:80]}")
    return chat


def _run_staged(replies, tlc, requirement=DOMAIN_REQUIREMENT, **kwargs):
    chat = _scripted_chat(replies)
    with patch.object(system_design, "_chat_fn",
                      side_effect=lambda provider, json_schema=None: chat) as chat_fn, \
         patch.object(system_design, "check_tla", return_value=tlc):
        result = system_design.design_system_staged(requirement, **kwargs)
    return result, chat_fn


def _happy_replies(components_replies=None):
    return {
        "List components": (components_replies or [json.dumps([
            {"name": "Inventory", "type": "core", "desc": "bounded stock on hand"},
            {"name": "Ledger", "type": "core", "desc": "counts recorded entries"}])]),
        "List operations for Inventory": [json.dumps([
            {"name": "reserve", "params": [], "requires": "stock > 0",
             "ensures": "stock >= 0", "returns": "void"}])],
        "List operations for Ledger": [json.dumps([
            {"name": "record", "params": [], "requires": "true",
             "ensures": "true", "returns": "void"}])],
        "state variables": [json.dumps([
            {"name": "entries", "type": "int", "bound": [0, 10], "initial": 0}])],
        "transitions key": [json.dumps({"transitions": [{
            "operation_name": "record", "precondition": "entries < 10",
            "effects": [{"target": "entries", "value": "entries + 1"}],
            "frame": ["entries"]}]})],
        "use-case steps": [json.dumps([
            {"component": "Inventory", "operation": "reserve"},
            {"component": "Ledger", "operation": "record"}])],
    }


def test_staged_design_happy_path_binds_domain_and_verifies():
    result, chat_fn = _run_staged(_happy_replies(), {"status": "VERIFIED"})
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "BOUNDED_ARCHITECTURE_EVIDENCE"
    by_name = {item["name"]: item for item in result["architecture"]["components"]}
    assert by_name["Inventory"]["domain"] == "inventory"
    assert by_name["Inventory"]["state_variables"] == []
    assert by_name["Inventory"]["transitions"] == []
    assert by_name["Ledger"]["state_variables"][0]["name"] == "entries"
    assert by_name["Ledger"]["transitions"][0]["operation_name"] == "record"
    assert "MODULE GeneratedSystem" in result["tla"] and "SPECIFICATION Spec" in result["cfg"]
    # The transition stage is the only one elicited through the structured json_schema seam.
    assert any(call.kwargs.get("json_schema") for call in chat_fn.call_args_list)


def test_staged_design_returns_design_failed_when_tlc_rejects_model():
    result, _ = _run_staged(_happy_replies(), {"status": "DEADLOCK"})
    assert result["status"] == "DESIGN_FAILED"
    assert result["message"] == "DEADLOCK" and result["tlc"]["status"] == "DEADLOCK"


def test_staged_design_nudges_empty_response_then_recovers():
    recovered = json.dumps([
        {"name": "Inventory", "type": "core", "desc": "bounded stock on hand"},
        {"name": "Ledger", "type": "core", "desc": "counts recorded entries"}])
    result, _ = _run_staged(_happy_replies(components_replies=["", recovered]),
                            {"status": "VERIFIED"})
    assert result["status"] == "VERIFIED"


def test_staged_design_repairs_malformed_json_then_recovers():
    recovered = json.dumps([
        {"name": "Inventory", "type": "core", "desc": "bounded stock on hand"},
        {"name": "Ledger", "type": "core", "desc": "counts recorded entries"}])
    result, _ = _run_staged(_happy_replies(components_replies=["{not json", recovered]),
                            {"status": "VERIFIED"})
    assert result["status"] == "VERIFIED"


def test_staged_design_fails_closed_after_fragment_repair_budget():
    result, _ = _run_staged({"List components": ["garbage", "still garbage"]},
                            {"status": "VERIFIED"}, max_attempts=2)
    assert result["status"] == "STAGED_GENERATION_FAILED"
    assert "FRAGMENT_REPAIR_FAILED" in result["message"]


def _core_with_domain():
    return UnifiedArchitecture.model_validate({"name": "S", "components": [{
        "name": "Inventory", "type": "core", "domain": "inventory",
        "operations": [{"name": "reserve", "params": [],
                        "contract": {"requires": "stock > 0", "ensures": "stock >= 0"}}],
    }]}).components[0]


def test_load_reviewed_domain_lowers_core_component_from_domain_model():
    reviewed = _load_reviewed_domain("inventory", REPO_ROOT / "domains" / "v2")
    assert reviewed.review_status == "reviewed"
    assert _domain_dict(reviewed) == reviewed.model_dump(mode="json")
    source = lower_component(_core_with_domain(), domain=reviewed)
    assert "public class Inventory" in source and "private int stock" in source
    assert "public void reserve()" in source


def test_lower_component_renders_boolean_domain_operations():
    source = lower_component(_core_with_domain(), domain={
        "state_variables": [{"name": "stock"}],
        "operations": [{"name": "isAvailable", "return_type": "boolean"}]})
    assert "public boolean isAvailable()" in source
    assert "        return false;" in source


def test_load_reviewed_domain_rejects_invalid_reviewed_spec(tmp_path):
    domains = tmp_path / "v2"
    domains.mkdir(parents=True)
    (domains / "broken.json").write_text(json.dumps({"review_status": "reviewed"}))
    with pytest.raises(ValueError, match="INVALID_REVIEWED_DOMAIN"):
        _load_reviewed_domain("broken", domains)


def test_run_unified_system_lowers_domain_component_and_proves_composition(tmp_path):
    artifact = tmp_path / "architecture.json"
    artifact.write_text(json.dumps({"name": "S", "components": [
        _core_with_domain().model_dump()]}))
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps({"status": "VERIFIED"}))
    domains = tmp_path / "domains" / "v2"
    domains.mkdir(parents=True)
    shutil.copyfile(REPO_ROOT / "domains" / "v2" / "inventory.json", domains / "inventory.json")
    verdict = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    with patch("pipeline.unified_system_runner.subprocess.run", return_value=verdict) as esc:
        result = run_unified_system(artifact, evidence, tmp_path / "out")
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "SYSTEM_COMPOSITION_PROOF"
    assert esc.call_args.args[0][-1].endswith("openjml") or "openjml" in esc.call_args.args[0][0]
    assert json.loads((tmp_path / "out" / "composition_verdict.json").read_text())["status"] == "VERIFIED"


def test_run_unified_system_fails_closed_on_missing_artifact(tmp_path):
    result = run_unified_system(tmp_path / "missing.json", tmp_path / "evidence.json",
                                tmp_path / "out")
    assert result["status"] == "UNIFIED_SYSTEM_FAILED"
    assert result["claim"] == "NO_PROOF" and result["message"]


def _java_source(tmp_path):
    source = tmp_path / "Ledger.java"
    source.write_text("public class Ledger { void entry() {} }\n")
    return source


def _refactor_patches(inspection):
    return (patch("pipeline.system_orchestrator.inspect_java_file", return_value=inspection),
            patch("pipeline.system_orchestrator.extract_method_from_inspection",
                  return_value={"status": "TRANSFORMED",
                                "source": "public class Ledger {}\n"}),
            patch("pipeline.system_orchestrator.verify_contract_preserving_refactor",
                  return_value={"status": "VERIFIED"}))


def test_refactor_system_rejects_nonpositive_worker_count(tmp_path):
    result = refactor_system({"components": [{"component": "Ledger", "file": "x"}]},
                             out_dir=tmp_path / "out", max_workers=0)
    assert result["status"] == "SYSTEM_SYNTHESIS_FAILED"
    assert result["code"] == "invalid_refactor_artifact"


def test_refactor_system_recovers_method_name_from_finding_message(tmp_path):
    source = _java_source(tmp_path)
    inspection = {"findings": [{"code": "long-method",
                                "message": "Method entry spans 30 lines"}]}
    patches = _refactor_patches(inspection)
    with patches[0], patches[1] as extract, patches[2]:
        result = refactor_system({"components": [{"component": "Ledger", "file": str(source)}]},
                                 out_dir=tmp_path / "out")
    assert result["status"] == "SYSTEM_REFACTOR_VERIFIED"
    assert result["claim"] == "SYSTEM_REFACTOR_CONTRACTS_PRESERVED"
    component = result["components"][0]
    assert component["method"] == "entry" and component["pattern"] == "extract-method"
    assert extract.call_args.args[2] == "entry"
    assert (tmp_path / "out" / "Ledger.java").read_text() == "public class Ledger {}\n"


def test_refactor_system_fails_closed_when_composition_gate_rejects(tmp_path):
    source = _java_source(tmp_path)
    inspection = {"findings": [{"code": "long-method", "method": "entry",
                                "message": "Method entry spans 30 lines"}]}
    patches = _refactor_patches(inspection)
    with patches[0], patches[1], patches[2], \
         patch("pipeline.composition_render.verify_composition",
               return_value={"status": "COMPOSITION_FAILED"}) as composition:
        result = refactor_system({"components": [{"component": "Ledger", "file": str(source)}],
                                  "composition": {"system_name": "S"}},
                                 out_dir=tmp_path / "out")
    assert result["status"] == "SYSTEM_REFACTOR_FAILED"
    assert result["code"] == "composition_verification_failed"
    assert result["composition"]["status"] == "COMPOSITION_FAILED"
    assert result["global_behavior_equivalence_proved"] is False
    assert composition.call_args.args[0] == {"system_name": "S"}
