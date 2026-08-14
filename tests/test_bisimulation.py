import json

from pipeline.bisimulation import verify_bisimulation_inputs


def test_bisimulation_preflight_binds_mapping_and_hashes(tmp_path):
    baseline = tmp_path / "Legacy.java"; baseline.write_text("class Legacy {}")
    refactored = tmp_path / "refactored"; refactored.mkdir()
    (refactored / "IdleState.java").write_text("class IdleState {}")
    mapping = tmp_path / "mapping.json"; mapping.write_text(json.dumps({"0": "IdleState"}))
    result = verify_bisimulation_inputs(baseline, refactored, mapping)
    assert result["status"] == "BISIMULATION_PREFLIGHT_READY"
    assert result["behavior_equivalence_proved"] is False
    assert result["mapping"] == {"0": "IdleState"}
    assert result["contract_surface_preserved"] is True


def test_bisimulation_preflight_rejects_invalid_mapping(tmp_path):
    baseline = tmp_path / "Legacy.java"; baseline.write_text("class Legacy {}")
    refactored = tmp_path / "Modern.java"; refactored.write_text("class Modern {}")
    mapping = tmp_path / "mapping.json"; mapping.write_text(json.dumps({"0": "not-valid!"}))
    assert verify_bisimulation_inputs(baseline, refactored, mapping)["status"] == \
        "BISIMULATION_MAPPING_INVALID"


def test_bisimulation_preflight_rejects_unresolved_state_type(tmp_path):
    baseline = tmp_path / "Legacy.java"; baseline.write_text("class Legacy {}")
    refactored = tmp_path / "Modern.java"; refactored.write_text("class Modern {}")
    mapping = tmp_path / "mapping.json"; mapping.write_text(json.dumps({"0": "IdleState"}))
    result = verify_bisimulation_inputs(baseline, refactored, mapping)
    assert result["status"] == "BISIMULATION_STATE_UNRESOLVED"


def test_bisimulation_preflight_reports_public_surface_changes(tmp_path):
    baseline = tmp_path / "Legacy.java"; baseline.write_text("class Legacy { public int run(int x) { return x; } }")
    refactored = tmp_path / "Modern.java"; refactored.write_text("class IdleState { public int run() { return 0; } }")
    mapping = tmp_path / "mapping.json"; mapping.write_text(json.dumps({"0": "IdleState"}))
    result = verify_bisimulation_inputs(baseline, refactored, mapping)
    assert result["status"] == "BISIMULATION_SURFACE_MISMATCH"
    assert result["contract_surface_preserved"] is False
