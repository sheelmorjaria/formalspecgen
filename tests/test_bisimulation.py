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
