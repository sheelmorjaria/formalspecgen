import json

from pipeline.codebase_analysis import analyze_codebase


def test_analyze_codebase_extracts_components_and_unreviewed_domain(tmp_path):
    source = tmp_path / "legacy"; source.mkdir()
    (source / "InventoryService.java").write_text("public class InventoryService { private int stock; }")
    (source / "PaymentGateway.java").write_text("public interface PaymentGateway { boolean pay(); }")
    result = analyze_codebase(source, tmp_path / "extracted")
    assert result["status"] == "EXTRACTED"
    assert {item["name"] for item in result["components"]} == {"InventoryService", "PaymentGateway"}
    assert result["validation"]["status"] == "NOT_RUN"
    domain = json.loads((tmp_path / "extracted" / "inventoryservice.v2.json").read_text())
    assert domain["review_status"] == "unreviewed"
    assert domain["warnings"] == ["UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW"]
    architecture = json.loads((tmp_path / "extracted" / "extracted_architecture.json").read_text())
    assert architecture["review_status"] == "unreviewed"


def test_analyze_codebase_fails_missing_and_records_parse_errors(tmp_path):
    assert analyze_codebase(tmp_path / "missing")["code"] == "input_unavailable"
    source = tmp_path / "legacy"; source.mkdir()
    (source / "Broken.java").write_text("public class Broken {")
    result = analyze_codebase(source, tmp_path / "out")
    assert result["status"] == "EXTRACTED"
    assert result["warnings"][0]["code"] == "UNPARSEABLE_SOURCE"


def test_analyze_codebase_extracts_bounded_state_without_manual_review_warning(tmp_path):
    source = tmp_path / "legacy"; source.mkdir()
    (source / "SafeCounter.java").write_text(
        "public class SafeCounter { private int count; public void inc() { if (count < 5) count++; } }")
    result = analyze_codebase(source, tmp_path / "out")
    domain = json.loads((tmp_path / "out" / "safecounter.v2.json").read_text())
    assert domain["state_variables"] == [{"name": "count", "type": "int", "bound": [0, 5]}]
    assert domain["warnings"] == []
    assert not any(item["code"] == "UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW" for item in result["warnings"])
