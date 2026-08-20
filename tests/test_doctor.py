# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import subprocess
from pathlib import Path

from pipeline import doctor


def _completed(command, **_kwargs):
    return subprocess.CompletedProcess(command, 0, stdout=f"{Path(command[0]).name} 1.0\n", stderr="")


def test_doctor_reports_claim_effects_without_minting(monkeypatch, tmp_path):
    jar = tmp_path / "tla2tools.jar"
    jar.write_bytes(b"jar")
    monkeypatch.setattr(doctor.config, "OPENJML", "openjml")
    monkeypatch.setattr(doctor.config, "PRUSTI_BIN", "prusti-rustc")
    monkeypatch.setattr(doctor.config, "FRAMAC_BIN", "frama-c")
    monkeypatch.setattr(doctor.config, "DAFNY_BIN", "dafny")
    monkeypatch.setattr(doctor.config, "JAVA_BIN", "java")
    monkeypatch.setattr(doctor.config, "TLC_JAR", str(jar))
    monkeypatch.setattr(doctor.config, "KANI_BIN", "cargo")
    available = {"openjml", "java", "cargo", "z3"}
    report = doctor.inspect_environment(
        runner=_completed, which=lambda name: f"/tools/{name}" if name in available else None)
    by_name = {item["name"]: item for item in report["capabilities"]}
    assert by_name["OpenJML"]["status"] == "READY"
    assert by_name["TLC"]["status"] == "READY"
    assert by_name["Kani"]["configured_command"] == ["cargo", "kani", "--version"]
    assert by_name["herd7"]["status"] == "ABSENT"
    assert by_name["herd7"]["judge_pending"] == "herd7_or_rc11"
    assert report["claim"] == "NO_PROOF"
    assert report["evidence_minted"] is False
    domains = {item["name"]: item for item in report["domains"]}
    assert domains["smart_lock"]["maturity"] == "scaffold"
    assert domains["smart_lock"]["evidence_ceiling"] == "NO_PROOF"
    assert domains["traffic_light_controller"]["maturity"] == "bounded-evidence"
    assert domains["traffic_light_controller"]["critical_implementation_available"] is False
    lane = next(item for item in report["lanes"] if item["lane"] == "M55_vfs")
    assert lane["current_step"] == 4
    assert lane["step_status"] == "complete"
    assert lane["maturity"] == "production"
    assert lane["claims_available"] == [
        "BOUNDED_ARCHITECTURE_EVIDENCE", "SOURCE_MODEL_REFINEMENT",
        "HARDWARE_MEMORY_BOUND_PROVED"]
    assert lane["claims_locked"] == []
    assert doctor.required_failures(report, ["OpenJML", "herd7", "unknown"]) == ["herd7", "unknown"]


def test_doctor_exposes_kani_invocation_mismatch(monkeypatch):
    monkeypatch.setattr(doctor.config, "KANI_BIN", "cargo-kani")
    report = doctor.inspect_environment(
        runner=_completed, which=lambda name: f"/tools/{name}" if name == "cargo" else None)
    kani = next(item for item in report["capabilities"] if item["name"] == "Kani")
    assert kani["status"] == "MISCONFIGURED"
    assert "generic lane" in kani["message"]
    assert report["status"] == "ATTENTION_REQUIRED"


def test_probe_fails_closed_on_timeout():
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("tool", 5)
    result = doctor._probe("Judge", ["judge", "--version"], ["CLAIM"], "judge",
                           runner=timeout, which=lambda _name: "/tools/judge", source="PATH")
    assert result["status"] == "ERROR"
    assert result["smoke_test"] == "timeout"
