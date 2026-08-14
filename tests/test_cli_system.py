import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from pipeline import cli


def test_system_cli_writes_aggregate_verdict_and_registers_parser(tmp_path):
    artifact = tmp_path / "system.json"
    artifact.write_text("{}", encoding="utf-8")
    destination = tmp_path / "verdict.json"
    ui = cli.TerminalUI(Console(file=io.StringIO(), force_terminal=False), lambda _: "")
    args = SimpleNamespace(artifact=str(artifact), out_dir=str(tmp_path / "runs"),
        max_workers=2, executable="formalspecgen", json=str(destination))
    verdict = {"status": "SYSTEM_SYNTHESIS_VERIFIED",
               "claim": "SYSTEM_COMPOSITION_PROOF", "components": [{}, {}]}
    with patch("pipeline.system_orchestrator.verify_system", return_value=verdict) as verify:
        assert cli.command_system(args, ui) == 0
    assert verify.call_args.kwargs["max_workers"] == 2
    assert json.loads(destination.read_text())["status"] == "SYSTEM_SYNTHESIS_VERIFIED"

    parser = cli.build_parser()
    parsed = parser.parse_args(["system", "system.json", "--out-dir", "runs"])
    assert parsed.command == "system" and parsed.max_workers == 4
    refactor = parser.parse_args(["system", "plan.json", "--mode", "refactor", "--out-dir", "runs"])
    assert refactor.mode == "refactor"
    assert "system" in cli._REPL_COMMANDS


def test_system_cli_refactor_mode_writes_contract_verdict(tmp_path):
    artifact = tmp_path / "plan.json"
    artifact.write_text(json.dumps({"components": []}), encoding="utf-8")
    destination = tmp_path / "refactor.json"
    ui = cli.TerminalUI(Console(file=io.StringIO(), force_terminal=False), lambda _: "")
    args = SimpleNamespace(artifact=str(artifact), out_dir=str(tmp_path / "runs"),
        max_workers=2, executable="formalspecgen", mode="refactor", json=str(destination))
    verdict = {"status": "SYSTEM_REFACTOR_VERIFIED",
               "claim": "SYSTEM_REFACTOR_CONTRACTS_PRESERVED", "components": [],
               "global_behavior_equivalence_proved": False}
    with patch("pipeline.system_orchestrator.refactor_system", return_value=verdict) as refactor:
        assert cli.command_system(args, ui) == 0
    refactor.assert_called_once_with({"components": []}, out_dir=str(tmp_path / "runs"), max_workers=2)
    assert json.loads(destination.read_text())["global_behavior_equivalence_proved"] is False


def test_system_cli_fails_closed_on_failure_and_unreadable_artifact(tmp_path):
    ui = cli.TerminalUI(Console(file=io.StringIO(), force_terminal=False), lambda _: "")
    args = SimpleNamespace(artifact=str(tmp_path / "missing.json"), out_dir=str(tmp_path),
        max_workers=1, executable="formalspecgen", json=None)
    assert cli.command_system(args, ui) == 2
    artifact = tmp_path / "system.json"; artifact.write_text("{}", encoding="utf-8")
    args.artifact = str(artifact)
    with patch("pipeline.system_orchestrator.verify_system",
               return_value={"status": "SYSTEM_SYNTHESIS_FAILED", "claim": "NO_PROOF"}):
        assert cli.command_system(args, ui) == 1
