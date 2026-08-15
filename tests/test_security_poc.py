import json
from unittest.mock import patch

from pipeline.security_poc import _poc_for, generate_pocs, inspect_security


def test_security_inspect_maps_formal_findings(tmp_path):
    source = tmp_path / "Service.java"
    source.write_text("class Service {}", encoding="utf-8")
    with patch("pipeline.security_poc.run_semgrep", return_value={"status": "CLEAN", "findings": []}), \
         patch("pipeline.security_poc.verify", return_value=(1, "Service.java:2: PossiblyNegativeIndex")):
        result = inspect_security(source)
    assert result["status"] == "VULNERABILITIES_FOUND"
    assert result["findings"][0]["cwe"] == "CWE-125"


def test_security_exploit_generates_safe_poc_template(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": [{"cwe": "CWE-125", "vc": "PossiblyNegativeIndex"}]}),
                      encoding="utf-8")
    target = tmp_path / "Service.java"
    target.write_text("class Service {}", encoding="utf-8")
    result = generate_pocs(report, target, tmp_path / "pocs")
    assert result["status"] == "POCS_GENERATED"
    assert result["exploit_proven"] is False
    assert result["generated"][0]["executed"] is False


def test_security_poc_templates_cover_polyglot_and_web_findings(tmp_path):
    java = tmp_path / "Service.java"; java.write_text("public class Service { public int get(int[] a, int i) { return a[i]; } }")
    rust = tmp_path / "service.rs"; rust.write_text("pub fn get(a: &[i32], i: usize) -> i32 { a[i] }")
    c_file = tmp_path / "service.c"; c_file.write_text("int get(int *a, int i) { return a[i]; }")
    assert "get" in _poc_for({"cwe": "CWE-89"}, java, 1)[1]
    assert "should_panic" in _poc_for({"cwe": "CWE-125"}, rust, 2)[1]
    assert "assert.h" in _poc_for({"cwe": "CWE-125"}, c_file, 3)[1]
    for cwe in ("CWE-22", "CWE-502", "CWE-190", "CWE-476"):
        assert _poc_for({"cwe": cwe}, java, 4) is not None


def test_security_inspect_routes_non_java_and_directory(tmp_path):
    rust = tmp_path / "service.rs"; rust.write_text("fn main() {}")
    with patch("pipeline.security_poc.verify", return_value=(1, "precondition of method index")):
        result = inspect_security(tmp_path)
    assert result["findings"][0]["cwe"] == "CWE-125"
    assert result["files_checked"][0]["file"].endswith("service.rs")


def test_security_exploit_reports_unsupported_finding(tmp_path):
    report = tmp_path / "report.json"; report.write_text('{"findings":[{"cwe":"CWE-999"}]}')
    target = tmp_path / "Service.java"; target.write_text("class Service {}")
    result = generate_pocs(report, target, tmp_path / "pocs")
    assert result["status"] == "NO_SUPPORTED_POC"
