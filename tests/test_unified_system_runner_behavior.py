import json
from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline.unified_system_runner import (
    _load_reviewed_domain,
    load_bound_artifact,
    lower_component,
    run_unified_system,
)
from pipeline.staged_architecture import UnifiedArchitecture


def _artifact():
    return {"name": "InventorySystem", "components": [{
        "name": "InventoryService", "type": "core", "file": "InventoryService.java",
        "state_variables": [{"name": "stock", "type": "int", "bound": [0, 5], "initial": 5}],
        "operations": [{"name": "reserve", "params": [],
                        "contract": {"requires": "stock > 0", "ensures": "true"}}],
        "transitions": [],
    }]}


def test_lower_component_supports_core_interface_adapter_and_rejects_language():
    arch = UnifiedArchitecture.model_validate({"name": "S", "components": [
        {"name": "Port", "type": "interface", "operations": [{"name": "pay", "params": [],
          "contract": {"requires": "amount > 0", "ensures": "result"}}]},
        {"name": "Adapter", "type": "adapter", "implements": "Port", "operations": []},
        {"name": "Core", "type": "core", "state_variables": [{"name": "stock", "type": "int", "bound": [0, 5], "initial": 2}], "operations": []},
    ]})
    port, adapter, core = arch.components
    assert "interface Port" in lower_component(port)
    assert "UNVERIFIED EXTERNAL BOUNDARY" in lower_component(adapter, interface=port)
    assert "private int stock" in lower_component(core)
    with pytest.raises(ValueError, match="UNSUPPORTED_UNIFIED_LOWERING_LANGUAGE"):
        lower_component(core, language="rust")


def test_load_bound_artifact_and_unified_runner_no_proof_when_only_boundary(tmp_path):
    artifact = tmp_path / "architecture.json"; evidence = tmp_path / "evidence.json"
    artifact.write_text(json.dumps({"name": "S", "components": [
        {"name": "Adapter", "type": "adapter", "implements": "Port", "operations": []}
    ]}))
    evidence.write_text(json.dumps({"status": "VERIFIED"}))
    loaded, _, digest = load_bound_artifact(artifact, evidence)
    assert loaded.name == "S" and len(digest) == 64
    result = run_unified_system(artifact, evidence, tmp_path / "out")
    assert result["claim"] == "NO_PROOF"
    assert result["external_io_safety_proved"] is False


def test_unified_runner_reports_openjml_failure_and_domain_errors(tmp_path, monkeypatch):
    artifact = tmp_path / "architecture.json"; evidence = tmp_path / "evidence.json"
    artifact.write_text(json.dumps(_artifact())); evidence.write_text(json.dumps({"status": "VERIFIED"}))
    with patch("pipeline.unified_system_runner.subprocess.run", return_value=type("R", (), {"returncode": 1, "stdout": "bad", "stderr": "esc"})()):
        result = run_unified_system(artifact, evidence, tmp_path / "out")
    assert result["status"] == "VERIFY_FAILED"
    bad_evidence = tmp_path / "bad.json"; bad_evidence.write_text(json.dumps({"status": "PENDING"}))
    with pytest.raises(ValueError, match="ARCHITECTURE_EVIDENCE_NOT_VERIFIED"):
        load_bound_artifact(artifact, bad_evidence)
    domains = tmp_path / "domains"; domains.mkdir()
    with pytest.raises(ValueError, match="REVIEWED_DOMAIN_NOT_FOUND"):
        _load_reviewed_domain("missing", domains)


def test_unified_runner_handles_timeout_and_invalid_reviewed_domain(tmp_path):
    artifact = tmp_path / "architecture.json"; evidence = tmp_path / "evidence.json"
    artifact.write_text(json.dumps(_artifact())); evidence.write_text(json.dumps({"status": "VERIFIED"}))
    import subprocess
    with patch("pipeline.unified_system_runner.subprocess.run", side_effect=subprocess.TimeoutExpired("openjml", 1)):
        result = run_unified_system(artifact, evidence, tmp_path / "timeout")
    assert result["status"] == "VERIFY_FAILED" and "timed out" in result["esc_output"]
    domains = tmp_path / "domains" / "v2"; domains.mkdir(parents=True)
    (domains / "inventory.json").write_text(json.dumps({"review_status": "candidate"}))
    with pytest.raises(ValueError, match="DOMAIN_NOT_REVIEWED"):
        _load_reviewed_domain("inventory", domains)
