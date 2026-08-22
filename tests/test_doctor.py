# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
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
    monkeypatch.setattr(doctor.config, "TLAPM_BIN", "tlapm")
    available = {"openjml", "java", "cargo", "z3"}
    report = doctor.inspect_environment(
        runner=_completed, which=lambda name: f"/tools/{name}" if name in available else None)
    by_name = {item["name"]: item for item in report["capabilities"]}
    assert by_name["OpenJML"]["status"] == "READY"
    assert by_name["TLC"]["status"] == "READY"
    assert by_name["Kani"]["configured_command"] == ["cargo", "kani", "--version"]
    assert by_name["herd7"]["status"] == "ABSENT"
    assert by_name["herd7"]["judge_pending"] == "herd7_or_rc11"
    assert by_name["TLAPS"]["status"] == "ABSENT"
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


def test_probe_fails_closed_on_execution_error():
    def broken(*_args, **_kwargs):
        raise OSError("cannot execute")
    result = doctor._probe("Judge", ["judge"], ["CLAIM"], "judge",
                           runner=broken, which=lambda _name: "/tools/judge",
                           source="PATH")
    assert result["status"] == "ERROR"
    assert result["smoke_test"] == "execution_failed"


def test_doctor_reports_foundational_judges_and_hash_field(monkeypatch):
    monkeypatch.setattr(doctor.config, "OPAM_BIN", "opam")
    monkeypatch.setattr(doctor.config, "VERUS_BIN", "verus")
    available = {"opam", "verus"}
    report = doctor.inspect_environment(
        runner=_completed,
        which=lambda name: f"/tools/{name}" if name in available else None)
    by_name = {item["name"]: item for item in report["capabilities"]}
    assert by_name["Rocq"]["status"] == "READY"
    assert by_name["RefinedRust"]["status"] == "READY"
    assert by_name["RefinedRust"]["invocation_environment"] == {
        "opam_switch": "refinedrust"}
    assert by_name["Verus"]["status"] == "READY"
    assert "executable_sha256" in by_name["Verus"]
    assert report["claim"] == "NO_PROOF"


def test_doctor_reports_repository_local_tlaps_with_hash(monkeypatch, tmp_path):
    tlapm = tmp_path / "tlapm"
    tlapm.write_bytes(b"qualified-tlapm")
    tlapm.chmod(0o755)
    monkeypatch.setattr(doctor.config, "TLAPM_BIN", str(tlapm))
    report = doctor.inspect_environment(runner=_completed, which=lambda _name: None)
    tlaps = next(item for item in report["capabilities"] if item["name"] == "TLAPS")
    assert tlaps["status"] == "READY"
    assert tlaps["configuration_source"] == "default"
    assert tlaps["executable_sha256"] == hashlib.sha256(b"qualified-tlapm").hexdigest()


def test_doctor_loads_hash_bound_refinedrust_boundary_ledger(monkeypatch, tmp_path):
    ledger = tmp_path / "boundaries.json"
    raw = json.dumps({"schema_version": 1, "boundaries": [
        {"id": "generic_local_trait_impl_registration",
         "status": "QUALIFIED_SUPPORTED"},
    ]}).encode()
    ledger.write_bytes(raw)
    monkeypatch.setattr(doctor.config, "REFINEDRUST_BOUNDARY_LEDGER", str(ledger))
    report = doctor.inspect_environment(runner=_completed, which=lambda _name: None)
    boundaries = report["refinedrust_boundaries"]
    assert boundaries["status"] == "LOADED"
    assert boundaries["claim"] == "NO_PROOF"
    assert boundaries["sha256"] == hashlib.sha256(raw).hexdigest()
    assert boundaries["boundaries"][0]["status"] == "QUALIFIED_SUPPORTED"


def test_doctor_fails_closed_for_malformed_boundary_ledger(monkeypatch, tmp_path):
    ledger = tmp_path / "boundaries.json"
    ledger.write_text("bad-json")
    monkeypatch.setattr(doctor.config, "REFINEDRUST_BOUNDARY_LEDGER", str(ledger))
    boundaries = doctor._refinedrust_boundaries()
    assert boundaries["status"] == "UNAVAILABLE"
    assert boundaries["sha256"] is None
    assert boundaries["boundaries"] == []


def test_executable_hash_reads_real_tool_bytes(tmp_path):
    executable = tmp_path / "judge"
    executable.write_bytes(b"judge-bytes")
    assert doctor._executable_sha256(str(executable)) == hashlib.sha256(
        b"judge-bytes").hexdigest()
    assert doctor._executable_sha256(None) is None


def test_doctor_binds_verus_bundle_components(monkeypatch, tmp_path):
    bundle = tmp_path / "verus-bundle"
    bundle.mkdir()
    for name in ("verus", "rust_verify", "z3", "vstd.vir", "version.json"):
        path = bundle / name
        path.write_bytes(name.encode())
        path.chmod(0o755)
    monkeypatch.setattr(doctor.config, "VERUS_BIN", str(bundle / "verus"))
    report = doctor.inspect_environment(runner=_completed, which=lambda _name: None)
    verus = next(item for item in report["capabilities"] if item["name"] == "Verus")
    assert verus["status"] == "READY"
    assert set(verus["judge_executables"]) == {
        "verus", "rust_verify", "z3", "vstd.vir", "version.json"}
    assert verus["judge_executables"]["z3"]["sha256"] == hashlib.sha256(b"z3").hexdigest()


def test_doctor_loads_verus_semantic_boundary_ledger(monkeypatch, tmp_path):
    ledger = tmp_path / "verus-boundaries.json"
    raw = json.dumps({"schema_version": 1, "trusted_escape_hatches_used": False,
                      "bridges": [{"id": "get_mut_frame_semantics",
                                   "status": "NO_PROOF"}]}).encode()
    ledger.write_bytes(raw)
    monkeypatch.setattr(doctor.config, "VERUS_BOUNDARY_LEDGER", str(ledger))
    report = doctor.inspect_environment(runner=_completed, which=lambda _name: None)
    boundaries = report["verus_boundaries"]
    assert boundaries["status"] == "LOADED"
    assert boundaries["claim"] == "NO_PROOF"
    assert boundaries["sha256"] == hashlib.sha256(raw).hexdigest()
    assert boundaries["trusted_escape_hatches_used"] is False
    assert boundaries["bridges"][0]["id"] == "get_mut_frame_semantics"


def test_doctor_fails_closed_for_malformed_verus_ledger(monkeypatch, tmp_path):
    ledger = tmp_path / "verus-boundaries.json"
    ledger.write_text("bad-json")
    monkeypatch.setattr(doctor.config, "VERUS_BOUNDARY_LEDGER", str(ledger))
    boundaries = doctor._verus_boundaries()
    assert boundaries["status"] == "UNAVAILABLE"
    assert boundaries["sha256"] is None
    assert boundaries["bridges"] == []
