"""Tests for `system --mode correct`: parallel sub-agent behavior correction."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from pipeline.system_orchestrator import correct_system, inspect_architecture_for_cwes


def _write_component(root: Path, name: str, body: str) -> Path:
    source = root / f"{name}.java"
    source.write_text(body, encoding="utf-8")
    return source


class _FakeProcess:
    def __init__(self, verdict: dict, exit_code: int = 0):
        self.verdict, self.returncode = verdict, exit_code

    def communicate(self):
        return "", ""

    def _install(self, written: dict, command: list[str]):
        # record the correction verdict where the command's --json points
        json_index = command.index("--json") + 1
        verdict_path = Path(command[json_index])
        verdict_path.parent.mkdir(parents=True, exist_ok=True)
        verdict_path.write_text(json.dumps(self.verdict), encoding="utf-8")
        written[str(verdict_path)] = self.verdict
        # correct-behavior also writes the corrected copy (source basename) beside the verdict
        corrected = verdict_path.parent / Path(command[2]).name
        corrected.write_text("public class Corrected {}", encoding="utf-8")
        written[str(corrected)] = True


def test_inspect_architecture_ranks_findings_into_a_correction_plan(tmp_path):
    payment = _write_component(tmp_path, "PaymentService",
                               "public class PaymentService { }")
    inventory = _write_component(tmp_path, "InventoryService",
                                 "public class InventoryService { }")
    clean = _write_component(tmp_path, "CleanService", "public class CleanService { }")

    def inspector(source):
        reports = {
            payment.name: {"findings": [{"cwe": "CWE-89", "severity": "HIGH"}]},
            inventory.name: {"findings": [{"cwe": "CWE-125", "severity": "HIGH"},
                                          {"cwe": "CWE-190", "severity": "MEDIUM"}]},
        }
        return reports.get(Path(source).name, {"findings": []})

    plan = inspect_architecture_for_cwes(
        [{"component": "payments", "file": str(payment)},
         {"component": "inventory", "file": str(inventory)},
         {"component": "clean", "file": str(clean)}], inspector=inspector)
    by_component = {item["component"]: item for item in plan}
    assert by_component["payments"]["cwe"] == "CWE-89"
    assert by_component["inventory"]["cwe"] == "CWE-125"  # severity-ranked
    assert by_component["clean"]["status"] == "FAIL"
    assert by_component["clean"]["code"] == "no_cwe_finding"
    assert by_component["payments"]["status"] == "PLANNED"


def test_correct_system_spawns_isolated_correctors_then_composition_gate(tmp_path):
    payment = _write_component(tmp_path, "PaymentService",
                               "public class PaymentService { }")
    inventory = _write_component(tmp_path, "InventoryService",
                                 "public class InventoryService { }")
    artifact = {
        "components": [
            {"component": "payments", "file": str(payment), "cwe": "CWE-89"},
            {"component": "inventory", "file": str(inventory), "cwe": "CWE-125"},
        ],
        "composition": {
            "system_name": "HardenedSystem",
            "files": {"payments": str(payment), "inventory": str(inventory)},
            "bindings": [{"component": "payments", "operation": "charge"},
                         {"component": "inventory", "operation": "reserve"}],
            "use_cases": [],
        },
    }
    written: dict[str, object] = {}
    popen_calls: list[list[str]] = []

    def popen(command, **kwargs):
        popen_calls.append(command)
        process = _FakeProcess({"status": "BEHAVIOR_CORRECTION_VERIFIED",
                                "claim": "BEHAVIOR_CORRECTION_VERIFIED",
                                "mitigated_cwe": "CWE-89"})
        process._install(written, command)
        return process

    composition_gate_calls: list[object] = []

    def composition_gate(value, *args, **kwargs):
        composition_gate_calls.append(value)
        return {"status": "COMPOSITION_VERIFIED", "claim": "SYSTEM_COMPOSITION_PROOF"}

    result = correct_system(artifact, out_dir=tmp_path / "out", max_workers=2,
                            popen=popen, composition_gate=composition_gate)

    # Step 2: exactly one isolated correct-behavior invocation per component.
    assert len(popen_calls) == 2
    for command in popen_calls:
        assert command[1] == "correct-behavior"
        assert "--cwe" in command and "--provider" in command
        assert "--json" in command
    cwes = {command[command.index("--cwe") + 1] for command in popen_calls}
    assert cwes == {"CWE-89", "CWE-125"}

    # Step 3: the composition gate ran against the corrected copies.
    assert len(composition_gate_calls) == 1
    corrected_files = composition_gate_calls[0]["files"]
    assert all("out" in path for path in corrected_files.values())
    assert set(corrected_files) == {"payments", "inventory"}

    assert result["status"] == "SYSTEM_CORRECTION_VERIFIED"
    assert result["claim"] == "SYSTEM_COMPOSITION_PROOF"
    assert result["global_behavior_equivalence_proved"] is False
    assert result["concurrent_component_execution_proved"] is False
    assert result["certificate_sha256"]
    assert (tmp_path / "out" / "architecture_correction_plan.json").exists()
    plan = json.loads((tmp_path / "out" / "architecture_correction_plan.json")
                      .read_text(encoding="utf-8"))
    assert {item["component"] for item in plan["components"]} == {"payments", "inventory"}


def test_correct_system_fails_closed_on_component_and_composition_failure(tmp_path):
    source = _write_component(tmp_path, "AuthService", "public class AuthService { }")
    artifact = {"components": [{"component": "auth", "file": str(source),
                                "cwe": "CWE-798"}]}

    def failing_popen(command, **kwargs):
        process = _FakeProcess({"status": "CORRECTION_FAILED", "claim": "NO_PROOF"})
        process._install({}, command)
        return process

    result = correct_system(artifact, out_dir=tmp_path / "out", popen=failing_popen,
                            composition_gate=lambda *a, **k: {"status": "NOT_REACHED"})
    assert result["status"] == "SYSTEM_CORRECTION_FAILED"
    assert result["global_behavior_equivalence_proved"] is False
    assert result["components"][0]["verdict"]["status"] == "CORRECTION_FAILED"

    def ok_popen(command, **kwargs):
        process = _FakeProcess({"status": "BEHAVIOR_CORRECTION_VERIFIED",
                                "claim": "BEHAVIOR_CORRECTION_VERIFIED"})
        process._install({}, command)
        return process

    broken_gate = lambda *a, **k: {"status": "COMPOSITION_CHECK_FAILED",
                                   "claim": "NO_PROOF"}
    with_composition = {**artifact, "composition": {
        "system_name": "Auth", "files": {"auth": str(source)},
        "bindings": [], "use_cases": []}}
    result = correct_system(with_composition, out_dir=tmp_path / "out2", popen=ok_popen,
                            composition_gate=broken_gate)
    assert result["status"] == "SYSTEM_CORRECTION_FAILED"
    assert result["code"] == "composition_verification_failed"


def test_correct_system_validates_artifact_and_missing_sources(tmp_path):
    result = correct_system({"components": []}, out_dir=tmp_path / "out")
    assert result["status"] == "SYSTEM_CORRECTION_FAILED"
    assert result["code"] == "invalid_correction_artifact"

    result = correct_system({"components": [{"component": "x", "file": str(tmp_path / "Nope.java")}]},
                            out_dir=tmp_path / "out")
    assert result["code"] == "source_unavailable"

    # A component with neither an explicit CWE nor an inspectable finding fails closed.
    source = _write_component(tmp_path, "S", "public class S { }")
    result = correct_system({"components": [{"component": "s", "file": str(source)}]},
                            out_dir=tmp_path / "out3",
                            inspector=lambda source: {"findings": []})
    assert result["code"] == "no_cwe_finding"


def test_correct_system_without_composition_verifies_isolated_corrections(tmp_path):
    source = _write_component(tmp_path, "SoloService", "public class SoloService { }")
    artifact = {"components": [{"component": "solo", "file": str(source), "cwe": "CWE-476"}]}

    def popen(command, **kwargs):
        process = _FakeProcess({"status": "BEHAVIOR_CORRECTION_VERIFIED",
                                "claim": "BEHAVIOR_CORRECTION_VERIFIED"})
        process._install({}, command)
        return process

    result = correct_system(artifact, out_dir=tmp_path / "out", popen=popen,
                            inspector=lambda source: {"findings": []})
    assert result["status"] == "SYSTEM_CORRECTION_VERIFIED"
    assert result["claim"] == "ISOLATED_BEHAVIOR_CORRECTIONS_VERIFIED"
    assert result["composition"] is None


def test_cli_system_correct_mode_routes_and_exits(tmp_path, monkeypatch):
    import pipeline.cli as cli

    source = _write_component(tmp_path, "CliService", "public class CliService { }")
    artifact = tmp_path / "plan.json"
    artifact.write_text(json.dumps(
        {"components": [{"component": "cli", "file": str(source), "cwe": "CWE-476"}]}),
        encoding="utf-8")
    recorded = {}

    def correct_system(value, **kwargs):
        recorded.update(kwargs)
        return {"status": "SYSTEM_CORRECTION_VERIFIED",
                "claim": "ISOLATED_BEHAVIOR_CORRECTIONS_VERIFIED",
                "components": [], "composition": None}

    import pipeline.system_orchestrator as orchestrator
    with patch.object(orchestrator, "correct_system", correct_system):
        exit_code = cli.main(["system", str(artifact), "--mode", "correct",
                              "--out-dir", str(tmp_path / "out"), "--max-workers", "2",
                              "--provider", "ollama", "--max-attempts", "5",
                              "--json", str(tmp_path / "v.json")])
    assert exit_code == 0
    assert recorded["provider"] == "ollama"
    assert recorded["max_attempts"] == 5
    assert recorded["executable"] == "formalspecgen"
    verdict = json.loads((tmp_path / "v.json").read_text(encoding="utf-8"))
    assert verdict["status"] == "SYSTEM_CORRECTION_VERIFIED"


def test_correct_system_oserror_missing_verdict_and_model_passthrough(tmp_path):
    source = _write_component(tmp_path, "FlakyService", "public class FlakyService { }")
    artifact = {"components": [{"component": "flaky", "file": str(source), "cwe": "CWE-476"}],
                "composition": {"system_name": "F", "files": {"flaky": str(source)},
                                "bindings": [], "use_cases": []}}
    commands = []

    def broken_popen(command, **kwargs):
        commands.append(command)
        raise OSError("spawn failed")

    result = correct_system(artifact, out_dir=tmp_path / "o1", popen=broken_popen)
    assert result["status"] == "SYSTEM_CORRECTION_FAILED"
    assert result["components"][0]["exit_code"] == 127
    assert result["components"][0]["verdict"]["status"] == "MISSING_VERDICT"

    class _NoInstall(_FakeProcess):
        def _install(self, written, command):
            pass  # verdict file never written -> MISSING_VERDICT path

    def silent_popen(command, **kwargs):
        commands.append(command)
        return _NoInstall({"status": "WOULD_BE_IGNORED"})

    result = correct_system(artifact, out_dir=tmp_path / "o2",
                            provider="ollama", model="qwen3-coder:30b",
                            popen=silent_popen)
    assert result["status"] == "SYSTEM_CORRECTION_FAILED"
    assert result["components"][0]["verdict"]["status"] == "MISSING_VERDICT"
    assert "--model" in commands[-1]
    assert "qwen3-coder:30b" in commands[-1]

    # composition referencing a component with no corrected copy fails closed
    class _GateRecording:
        def __call__(self, value, *a, **k):
            self.value = value
            return {"status": "COMPOSITION_VERIFIED"}

    gate = _GateRecording()
    result = correct_system(artifact, out_dir=tmp_path / "o3",
                            popen=lambda c, **k: _installing_popen(c, omit=["flaky"]),
                            composition_gate=gate)
    assert result["status"] == "SYSTEM_CORRECTION_FAILED"
    assert result["code"] == "component_correction_failed"  # missing copy fails the branch


def _installing_popen(command, omit=()):
    process = _FakeProcess({"status": "BEHAVIOR_CORRECTION_VERIFIED",
                            "claim": "BEHAVIOR_CORRECTION_VERIFIED"})
    class _Selective(process.__class__):
        pass
    json_index = command.index("--json") + 1
    verdict_path = Path(command[json_index])
    verdict_path.parent.mkdir(parents=True, exist_ok=True)
    verdict_path.write_text(json.dumps(process.verdict), encoding="utf-8")
    component = verdict_path.parent.name
    if component not in omit:
        corrected = verdict_path.parent / Path(command[2]).name
        corrected.write_text("public class C {}", encoding="utf-8")
    return _FakeProcess(process.verdict)
