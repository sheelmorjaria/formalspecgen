import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from pipeline import cli


def _ui():
    return cli.TerminalUI(Console(file=io.StringIO(), force_terminal=False), lambda _: "")


def test_security_cli_commands_write_verdicts_and_return_status(tmp_path):
    ui = _ui()
    source = tmp_path / "Example.java"; source.write_text("class Example {}")
    with patch("pipeline.security_assessment.assess_security", return_value={"status": "VERIFIED_SECURE", "claim": "SECURITY"}):
        args = SimpleNamespace(source=str(source), no_sast=True, json=str(tmp_path / "security.json"))
        assert cli.command_assess_security(args, ui) == 0
    with patch("pipeline.security_poc.inspect_security", return_value={"status": "INSPECTED", "findings": []}):
        args = SimpleNamespace(source=str(source), json=str(tmp_path / "vulns.json"))
        assert cli.command_security_inspect(args, ui) == 0
    report = tmp_path / "report.json"; report.write_text("[]")
    with patch("pipeline.security_poc.generate_pocs", return_value={"status": "POCS_GENERATED", "generated": ["x"]}):
        args = SimpleNamespace(report=str(report), target=str(source), out_dir=str(tmp_path / "pocs"), json=None)
        assert cli.command_security_exploit(args, ui) == 0
    with patch("pipeline.remediation.remediate", return_value={"status": "REMEDIATION_VERIFIED", "claim": "REMEDIATION_VERIFIED"}):
        args = SimpleNamespace(target=str(source), report=str(report), out_dir=str(tmp_path / "fixed"), provider="ollama", model=None, json=None)
        assert cli.command_remediate(args, ui) == 0
    assert (tmp_path / "security.json").exists()


def test_security_cli_failure_paths_return_nonzero(tmp_path):
    ui = _ui(); source = tmp_path / "Example.java"; source.write_text("class Example {}")
    with patch("pipeline.security_assessment.assess_security", return_value={"status": "SECURITY_VIOLATION"}):
        assert cli.command_assess_security(SimpleNamespace(source=str(source), no_sast=False, json=str(tmp_path / "a.json")), ui) == 1
    with patch("pipeline.algorithm_optimization.optimize_algorithm", return_value={"status": "FAIL", "code": "NO_PROOF"}):
        args = SimpleNamespace(source=str(source), out=str(tmp_path / "out.java"), strategy="hashmap", provider="ollama", model=None, json=None)
        assert cli.command_optimize_algorithm(args, ui) == 1
    with patch("pipeline.algorithm_discovery.discover_algorithms", return_value={"status": "FAILED", "verified_candidates": []}):
        args = SimpleNamespace(source=str(source), out_dir=str(tmp_path / "d"), strategies="all", provider="ollama", model=None, max_workers=1, json=None)
        assert cli.command_discover_algorithms(args, ui) == 1


def test_design_system_cli_success_failure_and_exception(tmp_path):
    ui = _ui(); out = tmp_path / "architecture.json"; evidence = tmp_path / "evidence.json"
    args = SimpleNamespace(requirement="checkout", provider="ollama", staged=False, max_attempts=1,
                           timeout=1, lang="java", out_file=str(out), json=str(evidence))
    result = {"status": "VERIFIED", "architecture": {"name": "Checkout"}, "tlc": {}}
    with patch("pipeline.cli.design_system", return_value=result):
        assert cli.command_design_system(args, ui) == 0
    assert json.loads(out.read_text())["name"] == "Checkout"
    with patch("pipeline.cli.design_system", return_value={"status": "STALLED", "message": "retry"}):
        assert cli.command_design_system(args, ui) == 1
    with patch("pipeline.cli.design_system", side_effect=RuntimeError("provider down")):
        assert cli.command_design_system(args, ui) == 1


def test_verify_cli_dispatches_cpp_modes_and_unknown_language(tmp_path):
    ui = _ui(); source = tmp_path / "Counter.cpp"; source.write_text("int main(){}")
    args = SimpleNamespace(source=str(source), mode="check", backend=None, json=None)
    assert cli.command_verify(args, ui) == 1
    with patch("pipeline.verify_cpp.verify_cpp", return_value={"status": "VERIFIED", "exit_code": 0, "output": "ok"}):
        args.mode = "esc"
        assert cli.command_verify(args, ui) == 0
    unknown = tmp_path / "input.xyz"; unknown.write_text("x")
    args = SimpleNamespace(source=str(unknown), mode="esc", backend=None, json=None)
    assert cli.command_verify(args, ui) == 1


def test_verify_refactor_signing_requires_json_and_handles_sign_failure(tmp_path):
    ui = _ui(); baseline = tmp_path / "a.java"; refactored = tmp_path / "b.java"
    baseline.write_text("class A {}"); refactored.write_text("class A {}")
    args = SimpleNamespace(baseline=str(baseline), refactored=str(refactored), signing_key="key", json=None)
    assert cli.command_verify_refactor(args, ui) == 2
    args.json = str(tmp_path / "verdict.json")
    with patch("pipeline.refactor_gate.verify_contract_preserving_refactor", return_value={"status": "VERIFIED"}), \
         patch("pipeline.domain_v2_promotion.sign_artifact", side_effect=ValueError("gpg missing")):
        assert cli.command_verify_refactor(args, ui) == 2


def test_validate_architecture_cli_fails_on_bad_artifact_and_tlc(tmp_path):
    ui = _ui(); args = SimpleNamespace(artifact=str(tmp_path / "missing.json"), timeout=1, json=None)
    assert cli.command_validate_architecture(args, ui) == 1


def test_correct_behavior_strategy_flag_routes_to_correction(tmp_path):
    from pipeline import cli
    source = tmp_path / "BatchRunner.java"
    source.write_text("public class BatchRunner { public void run(int n) { } }\n")
    verdict_path = tmp_path / "verdict.json"
    ok = {"status": "BEHAVIOR_CORRECTION_VERIFIED",
          "claim": "BEHAVIOR_CORRECTION_VERIFIED", "strategy": "bound-loop"}
    with patch("pipeline.behavior_correction.correct_behavior",
               return_value=dict(ok)) as correct:
        args = cli.build_parser().parse_args(
            ["correct-behavior", str(source), "--cwe", "CWE-400",
             "--strategy", "bound-loop", "--out-dir", str(tmp_path / "c"),
             "--json", str(verdict_path)])
        code = cli.command_correct_behavior(args, _ui())
    assert code == 0
    assert correct.call_args.kwargs["strategy"] == "bound-loop"
    import json
    assert json.loads(verdict_path.read_text())["strategy"] == "bound-loop"
