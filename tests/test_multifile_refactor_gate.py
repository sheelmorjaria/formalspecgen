from types import SimpleNamespace
from unittest.mock import patch

from pipeline import cli
from pipeline.refactor_gate import verify_multifile_contract_refactor


BASELINE = '''public class Service {
    //@ requires value >= 0;
    //@ ensures \\result >= value;
    public int run(int value) { return value + 1; }
}
'''
PRIMARY = '''public class Service {
    private final Helper helper = new Helper();
    //@ requires value >= 0;
    //@ ensures \\result >= value;
    public int run(int value) { return helper.run(value); }
}
'''
HELPER = '''public class Helper {
    //@ requires value >= 0;
    //@ ensures \\result >= value;
    public int run(int value) { return value + 1; }
}
'''


def _fixture(tmp_path):
    baseline = tmp_path / "baseline" / "Service.java"
    refactored = tmp_path / "refactored"
    baseline.parent.mkdir(parents=True); refactored.mkdir(parents=True)
    baseline.write_text(BASELINE, encoding="utf-8")
    (refactored / "Service.java").write_text(PRIMARY, encoding="utf-8")
    (refactored / "Helper.java").write_text(HELPER, encoding="utf-8")
    return baseline, refactored


def test_multifile_gate_hash_binds_joint_esc_without_equivalence_claim(tmp_path):
    baseline, refactored = _fixture(tmp_path)
    with patch("pipeline.refactor_gate.verify", side_effect=[(0, ""), (0, "proved")]), \
         patch("pipeline.refactor_gate.verify_files", side_effect=[(0, ""), (0, "proved")]):
        result = verify_multifile_contract_refactor(baseline, refactored)
    assert result["claim"] == "MULTIFILE_REFACTOR_CONTRACT_PRESERVED"
    assert [item["path"] for item in result["refactored_manifest"]] == [
        "Helper.java", "Service.java"]
    assert result["refactored_fileset_deductive_proof"]
    assert not result["behavior_equivalence_proved"]
    assert not result["heap_topology_equivalence_proved"]
    assert not result["refactor_verified"]


def test_multifile_gate_rejects_input_and_primary_surface_boundaries(tmp_path):
    baseline, refactored = _fixture(tmp_path)
    assert verify_multifile_contract_refactor(tmp_path / "missing.java", refactored)["code"] == \
        "source_unavailable"
    text = tmp_path / "Service.txt"; text.write_text(BASELINE)
    assert verify_multifile_contract_refactor(text, refactored)["code"] == "unsupported_language"
    assert verify_multifile_contract_refactor(baseline, tmp_path / "missing")["code"] == \
        "refactored_directory_unavailable"
    (refactored / "Service.java").unlink()
    assert verify_multifile_contract_refactor(baseline, refactored)["code"] == \
        "primary_source_missing"

    baseline, refactored = _fixture(tmp_path / "identity")
    (refactored / "Service.java").write_text(PRIMARY.replace("class Service", "class Changed"))
    assert verify_multifile_contract_refactor(baseline, refactored)["code"] == \
        "primary_class_identity_changed"
    baseline, refactored = _fixture(tmp_path / "contract")
    (refactored / "Service.java").write_text(PRIMARY.replace("\\result >= value", "\\result > value"))
    assert verify_multifile_contract_refactor(baseline, refactored)["code"] == \
        "primary_contract_surface_changed"
    baseline, refactored = _fixture(tmp_path / "api")
    (refactored / "Service.java").write_text(PRIMARY.replace("run(int value)", "run(long value)"))
    assert verify_multifile_contract_refactor(baseline, refactored)["code"] == \
        "primary_method_surface_changed"


def test_multifile_gate_blocks_each_proof_failure_and_vacuity(tmp_path):
    baseline, refactored = _fixture(tmp_path)
    with patch("pipeline.refactor_gate.verify", return_value=(1, "bad")):
        assert verify_multifile_contract_refactor(baseline, refactored)["code"] == \
            "baseline_not_verified"
    cases = [([(1, "bad")], "check"), ([(0, ""), (6, "vc")], "esc"),
             ([(0, ""), (0, "dropped")], "esc")]
    for responses, gate in cases:
        with patch("pipeline.refactor_gate.verify", side_effect=[(0, ""), (0, "proved")]), \
             patch("pipeline.refactor_gate.verify_files", side_effect=responses), \
             patch("pipeline.refactor_gate.has_dropped_vc",
                   side_effect=[False, responses[-1][1] == "dropped"]):
            result = verify_multifile_contract_refactor(baseline, refactored)
        assert result["code"] == "refactored_system_not_verified"
        assert result["verification"]["gate"] == gate


def test_verify_refactor_cli_routes_directory_to_multifile_gate(tmp_path):
    baseline, refactored = _fixture(tmp_path)
    args = cli.build_parser().parse_args(["verify-refactor", str(baseline), str(refactored)])
    ui = SimpleNamespace(console=SimpleNamespace(print=lambda *_args, **_kwargs: None))
    with patch("pipeline.refactor_gate.verify_multifile_contract_refactor",
               return_value={"status": "VERIFIED",
                             "claim": "MULTIFILE_REFACTOR_CONTRACT_PRESERVED"}) as gate:
        assert cli.command_verify_refactor(args, ui) == 0
    gate.assert_called_once()
