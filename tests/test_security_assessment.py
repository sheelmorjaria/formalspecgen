from unittest.mock import patch

from pipeline.security_assessment import assess_security, map_formal_vcs, run_semgrep


def test_formal_vc_labels_map_to_cwes():
    findings = map_formal_vcs("ArithmeticOperationRange and PossiblyNegativeIndex")
    assert {item["cwe"] for item in findings} == {"CWE-190", "CWE-125"}


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
