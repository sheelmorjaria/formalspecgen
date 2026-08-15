import json
from unittest.mock import patch

from pipeline.remediation import remediate


SOURCE = "public class Service { public int get(int[] a, int i) { return a[i]; } }\n"


def test_remediation_mints_claim_only_after_esc(tmp_path):
    target = tmp_path / "Service.java"; target.write_text(SOURCE, encoding="utf-8")
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": [{"cwe": "CWE-125", "message": "index"}]}),
                      encoding="utf-8")
    with patch("pipeline.remediation._chat_fn",
               return_value=lambda *_args: ("```java\n" + SOURCE + "```", "test-model", {})), \
         patch("pipeline.remediation.verify", return_value=(0, "proved")):
        result = remediate(target, report, tmp_path / "patched")
    assert result["claim"] == "REMEDIATION_VERIFIED"
    assert result["poc_status"] == "NOT_EXECUTED"
    assert (tmp_path / "patched" / "Service.java").exists()


def test_remediation_does_not_claim_on_failed_esc(tmp_path):
    target = tmp_path / "Service.java"; target.write_text(SOURCE, encoding="utf-8")
    report = tmp_path / "report.json"; report.write_text('[{"cwe":"CWE-125"}]')
    with patch("pipeline.remediation._chat_fn",
               return_value=lambda *_args: (SOURCE, "test-model", {})), \
         patch("pipeline.remediation.verify", return_value=(1, "bad vc")):
        result = remediate(target, report, tmp_path / "patched")
    assert result["status"] == "REMEDIATION_FAILED"


def test_remediation_handles_missing_invalid_and_empty_reports(tmp_path):
    target = tmp_path / "Service.java"; target.write_text(SOURCE, encoding="utf-8")
    assert remediate(tmp_path / "missing.java", tmp_path / "missing.json")["code"] == "input_unavailable"
    invalid = tmp_path / "invalid.json"; invalid.write_text("not-json")
    assert remediate(target, invalid)["code"] == "invalid_report"
    empty = tmp_path / "empty.json"; empty.write_text('{"findings": []}')
    assert remediate(target, empty)["status"] == "NO_REMEDIATION_REQUIRED"


def test_remediation_reports_generation_failure(tmp_path):
    target = tmp_path / "Service.rs"; target.write_text("fn main() {}")
    report = tmp_path / "report.json"; report.write_text('{"findings":[{"cwe":"CWE-125"}]}')
    with patch("pipeline.remediation._chat_fn", side_effect=RuntimeError("offline")):
        result = remediate(target, report, tmp_path / "patched")
    assert result["code"] == "patch_generation_failed"
