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
