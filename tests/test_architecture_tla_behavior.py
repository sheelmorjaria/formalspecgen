from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline.architecture_tla_renderer import render_architecture_tla, render_transition
from pipeline.architecture_tlc_gate import publish_architecture, validate_architecture_with_tlc
from pipeline.staged_architecture import StateVariableFragment, TransitionFragment


def transition():
    return TransitionFragment.model_validate({
        "operation_name": "increment",
        "precondition": {"kind": "lt", "left": {"kind": "field", "name": "count"}, "right": {"kind": "integer", "value": 2}},
        "effects": [{"target": "count", "value": {"kind": "add", "left": {"kind": "field", "name": "count"}, "right": {"kind": "integer", "value": 1}}}],
        "frame": ["count"],
    })


def test_tla_renderer_emits_bounded_model_and_rejects_unbounded_state():
    state = StateVariableFragment(name="count", type="int", bound=(0, 2), initial=0)
    tla, cfg = render_architecture_tla([state], [("Increment", transition())], "Counter")
    assert "MODULE Counter" in tla and "count \\in 0..2" in tla
    assert "Next == Increment" in tla and "SPECIFICATION Spec" in cfg
    assert "count'" in render_transition("Increment", transition(), ["count", "flag"])
    with pytest.raises(ValueError, match="no bounded state"):
        render_architecture_tla([], [])
    with pytest.raises(ValueError, match="every integer state"):
        render_architecture_tla([StateVariableFragment(name="count", type="int", bound=None)], [])


def test_tlc_gate_maps_success_timeout_tool_missing_and_failures(tmp_path):
    tla, cfg = tmp_path / "x.tla", tmp_path / "x.cfg"
    tla.write_text("---- MODULE X ----\n====")
    cfg.write_text("SPECIFICATION Spec")
    result = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    with patch("pipeline.architecture_tlc_gate.subprocess.run", return_value=result):
        assert validate_architecture_with_tlc(tla, cfg, "tlc.jar")["status"] == "VERIFIED"
    for text, expected in [("deadlock found", "DEADLOCK"), ("Invariant violated", "INVARIANT_VIOLATED"), ("other", "TLC_FAILED")]:
        failed = type("R", (), {"returncode": 1, "stdout": text, "stderr": ""})()
        with patch("pipeline.architecture_tlc_gate.subprocess.run", return_value=failed):
            assert validate_architecture_with_tlc(tla, cfg, "tlc.jar")["status"] == expected
    with patch("pipeline.architecture_tlc_gate.subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("java", 1)):
        assert validate_architecture_with_tlc(tla, cfg, "tlc.jar")["status"] == "TIMEOUT"
    with patch("pipeline.architecture_tlc_gate.subprocess.run", side_effect=OSError("missing")):
        assert validate_architecture_with_tlc(tla, cfg, "tlc.jar")["status"] == "TOOL_MISSING"


def test_architecture_publication_is_hash_bound_and_fail_closed(tmp_path):
    artifact = {"name": "Counter", "components": []}
    evidence = publish_architecture(artifact, {"status": "VERIFIED", "exit_code": 0}, tmp_path / "a.json")
    assert evidence["claim"] == "BOUNDED_ARCHITECTURE_EVIDENCE"
    assert (tmp_path / "a.evidence.json").exists()
    with pytest.raises(ValueError, match="publication refused"):
        publish_architecture(artifact, {"status": "DEADLOCK"}, tmp_path / "bad.json")
