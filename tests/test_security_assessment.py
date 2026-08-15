from unittest.mock import patch

from pipeline.security_assessment import (assess_security, map_formal_failure_to_cwe,
                                          map_formal_vcs, run_semgrep)


def test_formal_vc_labels_map_to_cwes():
    findings = map_formal_vcs("ArithmeticOperationRange and underflow PossiblyNegativeIndex NegativeArraySize")
    assert {item["cwe"] for item in findings} == {"CWE-190", "CWE-191", "CWE-125", "CWE-131"}


def test_native_prover_failures_share_universal_cwe_mapping():
    assert map_formal_failure_to_cwe("framac", "RTE: signed_overflow")['cwe'] == "CWE-190"
    assert map_formal_failure_to_cwe("prusti", "precondition of method: index")['cwe'] == "CWE-125"
    assert map_formal_failure_to_cwe("esbmc", "array bounds violation")['cwe'] == "CWE-125"


def test_security_assessment_fails_closed_on_formal_failure(tmp_path):
    source = tmp_path / "X.java"
    source.write_text("class X {}", encoding="utf-8")
    with patch("pipeline.security_assessment.verify", return_value=(1, "ArithmeticOperationRange")), \
         patch("pipeline.security_assessment.run_semgrep",
               return_value={"status": "CLEAN", "findings": []}):
        result = assess_security(source)
    assert result["status"] == "SECURITY_VIOLATION"
    assert result["formal_findings"][0]["cwe"] == "CWE-190"


def test_semgrep_tool_missing_is_explicit(tmp_path):
    source = tmp_path / "X.java"
    source.write_text("class X {}", encoding="utf-8")
    with patch("pipeline.security_assessment.subprocess.run",
               side_effect=FileNotFoundError):
        result = run_semgrep(source)
    assert result["status"] == "TOOL_MISSING"


def test_semgrep_normalizes_custom_rule_findings(tmp_path):
    source = tmp_path / "X.java"; source.write_text("class X {}")
    process = type("P", (), {"stdout": '{"results":[{"check_id":"CWE-327-WEAK-CRYPTO", "start":{"line":4}, "extra":{"severity":"WARNING", "message":"weak"}}]}', "stderr": "", "returncode": 0})()
    with patch("pipeline.security_assessment.subprocess.run", return_value=process):
        result = run_semgrep(source)
    assert result["status"] == "FINDINGS"
    assert result["findings"][0]["cwe"] == "CWE-327"


def test_semgrep_normalizes_command_injection_rule(tmp_path):
    source = tmp_path / "X.java"; source.write_text("class X {}")
    process = type("P", (), {"stdout": '{"results":[{"check_id":"CWE-78-COMMAND-INJECTION", "start":{"line":2}, "extra":{"severity":"ERROR", "message":"command"}}]}', "stderr": "", "returncode": 1})()
    with patch("pipeline.security_assessment.subprocess.run", return_value=process):
        result = run_semgrep(source)
    assert result["findings"][0]["cwe"] == "CWE-78"


def test_semgrep_normalizes_web_crypto_and_permission_rules(tmp_path):
    source = tmp_path / "X.java"; source.write_text("class X {}")
    ids = ["CWE-79-XSS-CONCATENATION", "CWE-326-WEAK-RSA-KEY", "CWE-732-WORLD-WRITABLE-PERMISSIONS"]
    payload = {"results": [{"check_id": item, "start": {"line": 1}, "extra": {"severity": "ERROR"}} for item in ids]}
    process = type("P", (), {"stdout": __import__("json").dumps(payload), "stderr": "", "returncode": 1})()
    with patch("pipeline.security_assessment.subprocess.run", return_value=process):
        result = run_semgrep(source)
    assert {item["cwe"] for item in result["findings"]} == {"CWE-79", "CWE-326", "CWE-732"}


def test_semgrep_timeout_and_invalid_output_are_explicit(tmp_path):
    source = tmp_path / "X.java"; source.write_text("class X {}")
    from subprocess import TimeoutExpired
    with patch("pipeline.security_assessment.subprocess.run", side_effect=TimeoutExpired("semgrep", 1)):
        assert run_semgrep(source)["status"] == "TIMEOUT"
    process = type("P", (), {"stdout": "not-json", "stderr": "bad", "returncode": 2})()
    with patch("pipeline.security_assessment.subprocess.run", return_value=process):
        assert run_semgrep(source)["status"] == "INVALID_OUTPUT"


def test_security_assessment_mints_clean_skipped_and_incomplete_statuses(tmp_path):
    source = tmp_path / "X.java"; source.write_text("class X {}")
    with patch("pipeline.security_assessment.verify", return_value=(0, "")), \
         patch("pipeline.security_assessment.run_semgrep", return_value={"status": "CLEAN", "findings": []}):
        assert assess_security(source)["status"] == "VERIFIED_SECURE"
    with patch("pipeline.security_assessment.verify", return_value=(0, "")):
        assert assess_security(source, run_sast=False)["status"] == "FORMALLY_VERIFIED_SAST_SKIPPED"
    for sast_status in ("TOOL_MISSING", "TIMEOUT", "INVALID_OUTPUT"):
        with patch("pipeline.security_assessment.verify", return_value=(0, "")), \
             patch("pipeline.security_assessment.run_semgrep", return_value={"status": sast_status, "findings": []}):
            assert assess_security(source)["status"] == "SECURITY_ASSESSMENT_INCOMPLETE"


def test_security_assessment_blocks_high_severity_sast_and_maps_unknowns(tmp_path):
    source = tmp_path / "X.java"; source.write_text("class X {}")
    with patch("pipeline.security_assessment.verify", return_value=(0, "")), \
         patch("pipeline.security_assessment.run_semgrep", return_value={"status": "FINDINGS", "findings": [{"severity": "ERROR", "cwe": "CWE-22"}]}):
        result = assess_security(source)
    assert result["status"] == "SECURITY_VIOLATION"
    assert map_formal_failure_to_cwe("unknown", "unrecognized diagnostic")["cwe"] == "UNKNOWN"
    assert map_formal_failure_to_cwe("openjml", "ArithmeticOperationRange underflow")["cwe"] == "CWE-191"
    assert map_formal_failure_to_cwe("openjml", "PossiblyNull dereference")["cwe"] == "CWE-476"
