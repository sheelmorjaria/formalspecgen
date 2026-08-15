"""Chained CLI E2E tests: modernization and security lanes on real OpenJML.

Unlike the per-command tests in tests/, these drive multiple `formalspecgen`
subcommands in sequence against one fixture so the commands are validated as a
cohesive pipeline. The LLM is replaced by static fixtures at the module-local
`_chat_fn` seam (the pattern established in tests/test_remediation.py); every
proof claim comes from real OpenJML ESC runs.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline import cli

pytestmark = pytest.mark.toolchain

# ---------------------------------------------------------------- fixtures ---

NULL_OBJECT_SERVICE = """public class Service {
    private /*@ nullable @*/ Logger logger;

    public Service() {
        this.logger = null;
    }

    //@ requires input != null;
    //@ ensures true;
    public void process(String input) {
        if (this.logger != null) {
            this.logger.log(input);
        }
    }

    public void retry(String input) {
        if (this.logger != null) {
            this.logger.log(input);
        }
    }
}
"""

LOGGER_INTERFACE = "interface Logger { void log(String input); }\n"


def _legacy_calculator() -> str:
    """A >60-line addBoth with overflow-ruled-out JML (ESC checks int ranges)."""
    padding = "        temp = temp + 0;\n" * 55
    return (
        "public class LegacyCalculator {\n"
        "    private /*@ spec_public @*/ int total;\n"
        "\n"
        "    //@ requires 0 <= a && a <= 1000;\n"
        "    //@ requires 0 <= b && b <= 1000;\n"
        "    //@ requires -1000000 <= total && total + a + b <= 1000000;\n"
        "    //@ ensures total == \\old(total) + a + b;\n"
        "    //@ assignable total;\n"
        "    public void addBoth(int a, int b) {\n"
        "        int temp = total;\n"
        f"{padding}"
        "        temp = temp + a;\n"
        "        temp = temp + b;\n"
        "        total = temp;\n"
        "    }\n"
        "}\n"
    )


UNSAFE_ARRAY = """public class UnsafeArray {
    //@ requires arr != null;
    public int get(int[] arr, int index) {
        return arr[index];
    }
}
"""

UNSAFE_ARRAY_STRENGTHENED = """public class UnsafeArray {
    //@ requires arr != null;
    //@ ensures 0 <= index && index < arr.length ==> \\result == arr[index];
    //@ ensures !(0 <= index && index < arr.length) ==> \\result == -1;
    public int get(int[] arr, int index) {
        if (0 <= index && index < arr.length) {
            return arr[index];
        }
        return -1;
    }
}
"""

NULL_DEREF_SERVICE = """public class NullDerefService {
    private /*@ nullable @*/ String label;

    public NullDerefService() {
        this.label = null;
    }

    //@ requires input != null;
    public int measure(String input) {
        return this.label.length();
    }
}
"""

NULL_DEREF_STRENGTHENED = """public class NullDerefService {
    private /*@ nullable @*/ String label;

    public NullDerefService() {
        this.label = null;
    }

    //@ requires input != null;
    //@ ensures \\result >= 0;
    public int measure(String input) {
        if (this.label != null) {
            return this.label.length();
        }
        return 0;
    }
}
"""

# ------------------------------------------------------------------ helpers ---


def _run(step: list[str]) -> int:
    return cli.main(step)


def _verdict(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# -------------------------------------------------------------------- tests ---


def test_null_object_chain_fails_closed_on_strengthened_contract(tmp_path, openjml_tool):
    """inspect -> security-inspect -> apply-refactor null-object -> verify-refactor.

    The Null Object transform deliberately strengthens the contract (removes
    `nullable`, adds a constructor `ensures != null`), so the multifile gate
    must refuse to mint MULTIFILE_REFACTOR_CONTRACT_PRESERVED. The fail-closed
    verdict is the regression pin, not a bug.
    """
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    (baseline / "Service.java").write_text(NULL_OBJECT_SERVICE, encoding="utf-8")
    (baseline / "Logger.java").write_text(LOGGER_INTERFACE, encoding="utf-8")
    inspection = tmp_path / "inspection.json"
    security = tmp_path / "security.json"
    refactor = tmp_path / "refactor.json"
    refactored = tmp_path / "refactored"

    assert _run(["inspect", str(baseline / "Service.java"), "--json", str(inspection)]) == 0
    findings = _verdict(inspection)["findings"]
    assert any(f["code"] == "repeated-null-check" and f["suggested_pattern"] == "Null Object"
               for f in findings)

    assert _run(["security-inspect", str(baseline / "Service.java"),
                 "--json", str(security)]) == 0
    security_verdict = _verdict(security)
    assert security_verdict["findings"] == []
    assert security_verdict["status"] == "NO_FINDINGS"

    assert _run(["apply-refactor", str(baseline / "Service.java"),
                 "--inspection", str(inspection), "--pattern", "null-object",
                 "--method", "process", "--out", str(refactored),
                 "--json", str(refactor)]) == 1
    applied = _verdict(refactor)
    assert applied["transformation"]["status"] == "TRANSFORMED"
    assert applied["transformation"]["pattern"] == "Null Object"
    primary = (refactored / "Service.java").read_text(encoding="utf-8")
    assert "new NullLogger()" in primary
    assert "nullable" not in primary
    null_logger = (refactored / "NullLogger.java").read_text(encoding="utf-8")
    assert "implements Logger" in null_logger
    assert (refactored / "Logger.java").exists()

    verdict = tmp_path / "final.json"
    assert _run(["verify-refactor", str(baseline / "Service.java"), str(refactored),
                 "--json", str(verdict)]) == 1
    final = _verdict(verdict)
    assert final["status"] == "FAIL"
    assert final["code"] == "primary_contract_surface_changed"
    assert final["claim"] == "NO_PROOF"
    assert final["behavior_equivalence_proved"] is False


def test_extract_method_chain_preserves_contract(tmp_path, openjml_tool):
    """inspect -> apply-refactor extract-method -> verify-refactor.

    Real OpenJML ESC proves both revisions; Z3 discharges the arithmetic
    postcondition through the extracted private helper.
    """
    baseline_dir = tmp_path / "baseline"
    baseline_dir.mkdir()
    source = baseline_dir / "LegacyCalculator.java"
    source.write_text(_legacy_calculator(), encoding="utf-8")
    inspection = tmp_path / "inspection.json"
    refactored = tmp_path / "refactored" / "LegacyCalculator.java"
    applied_json = tmp_path / "applied.json"
    verdict = tmp_path / "verdict.json"

    assert _run(["inspect", str(source), "--json", str(inspection)]) == 0
    assert any(f["code"] == "long-method" and "addBoth" in f.get("message", "")
               for f in _verdict(inspection)["findings"])

    assert _run(["apply-refactor", str(source), "--inspection", str(inspection),
                 "--pattern", "extract-method", "--method", "addBoth",
                 "--out", str(refactored), "--json", str(applied_json)]) == 0
    transformed = (tmp_path / "refactored" / "LegacyCalculator.java").read_text(encoding="utf-8")
    assert "addBothExtracted" in transformed

    assert _run(["verify-refactor", str(source), str(refactored),
                 "--json", str(verdict)]) == 0
    result = _verdict(verdict)
    assert result["claim"] == "REFACTOR_CONTRACT_PRESERVED"
    assert result["contract_surface_preserved"] is True
    assert result["behavior_equivalence_proved"] is False


def test_cwe125_security_chain_corrects_bounds_with_proof(tmp_path, openjml_tool):
    """security-inspect -> correct-behavior -> verify on an unbounded array read.

    The LLM strengthening step is a static fixture; the CWE-125 elimination is
    proven by real OpenJML ESC on the strengthened source.
    """
    source = tmp_path / "UnsafeArray.java"
    source.write_text(UNSAFE_ARRAY, encoding="utf-8")
    security = tmp_path / "security.json"
    corrections = tmp_path / "corrections"
    correction_json = corrections / "correction_verdict.json"
    verify_json = tmp_path / "verify.json"

    assert _run(["security-inspect", str(source), "--json", str(security)]) == 0
    findings = _verdict(security)["findings"]
    assert _verdict(security)["status"] == "VULNERABILITIES_FOUND"
    assert any(f["cwe"] == "CWE-125" for f in findings)

    with patch("pipeline.behavior_correction._chat_fn",
               return_value=lambda *_args: (UNSAFE_ARRAY_STRENGTHENED, "fixture", {})):
        assert _run(["correct-behavior", str(source), "--cwe", "CWE-125",
                     "--out-dir", str(corrections)]) == 0
    corrected = corrections / "UnsafeArray.java"
    assert corrected.exists()
    assert "index < arr.length" in corrected.read_text(encoding="utf-8")
    correction = _verdict(correction_json)
    assert correction["status"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert correction["formal_proof"] == "DEDUCTIVE_PROOF"
    assert correction["mitigated_cwe"] == "CWE-125"

    # A bare verify mints VERIFIED; the DEDUCTIVE_PROOF claim belongs to the
    # correction verdict that ran the strengthen->prove loop.
    assert _run(["verify", str(corrected), "--mode", "esc", "--json", str(verify_json)]) == 0
    assert _verdict(verify_json)["status"] == "VERIFIED"


def test_cwe476_security_chain_corrects_null_deref_with_proof(tmp_path, openjml_tool):
    """security-inspect -> correct-behavior on an unguarded nullable deref.

    The guarded twin of this fixture (test_null_object_chain...) yields
    NO_FINDINGS and goes down the deterministic Null Object lane instead.
    """
    source = tmp_path / "NullDerefService.java"
    source.write_text(NULL_DEREF_SERVICE, encoding="utf-8")
    security = tmp_path / "security.json"
    corrections = tmp_path / "corrections"
    correction_json = corrections / "correction_verdict.json"

    assert _run(["security-inspect", str(source), "--json", str(security)]) == 0
    findings = _verdict(security)["findings"]
    assert _verdict(security)["status"] == "VULNERABILITIES_FOUND"
    assert any(f["cwe"] == "CWE-476" for f in findings)

    with patch("pipeline.behavior_correction._chat_fn",
               return_value=lambda *_args: (NULL_DEREF_STRENGTHENED, "fixture", {})):
        assert _run(["correct-behavior", str(source), "--cwe", "CWE-476",
                     "--out-dir", str(corrections)]) == 0
    corrected = corrections / "NullDerefService.java"
    assert "this.label != null" in corrected.read_text(encoding="utf-8")
    correction = _verdict(correction_json)
    assert correction["status"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert correction["formal_proof"] == "DEDUCTIVE_PROOF"
    assert correction["mitigated_cwe"] == "CWE-476"
