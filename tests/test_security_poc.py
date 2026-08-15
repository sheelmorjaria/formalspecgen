import json
from unittest.mock import patch

from pipeline.security_poc import generate_pocs, inspect_security


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
