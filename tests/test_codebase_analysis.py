import json
from unittest.mock import patch

from pipeline.codebase_analysis import analyze_codebase


def test_analyze_codebase_extracts_components_and_unreviewed_domain(tmp_path):
    source = tmp_path / "legacy"; source.mkdir()
    (source / "InventoryService.java").write_text("public class InventoryService { private int stock; }")
    (source / "PaymentGateway.java").write_text("public interface PaymentGateway { boolean pay(); }")
    result = analyze_codebase(source, tmp_path / "extracted", project_root=tmp_path)
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
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    assert result["status"] == "EXTRACTED"
    assert result["warnings"][0]["code"] == "UNPARSEABLE_SOURCE"


def test_analyze_codebase_extracts_bounded_state_without_manual_review_warning(tmp_path):
    source = tmp_path / "legacy"; source.mkdir()
    (source / "SafeCounter.java").write_text(
        "public class SafeCounter { private int count; public void inc() { if (count < 5) count++; } }")
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    domain = json.loads((tmp_path / "out" / "safecounter.v2.json").read_text())
    assert domain["state_variables"] == [{"name": "count", "type": "int", "bound": [0, 5]}]
    assert domain["warnings"] == []
    assert not any(item["code"] == "UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW" for item in result["warnings"])


def test_analyze_codebase_extracts_rust_c_and_cpp_components(tmp_path):
    source = tmp_path / "mixed"; source.mkdir()
    (source / "counter.rs").write_text("struct Counter { count: i32, }")
    (source / "meter.c").write_text("struct Meter { int value; };")
    (source / "gauge.cpp").write_text("class Gauge { int level; };")
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    names = {item["name"] for item in result["components"]}
    assert names == {"Counter", "Meter", "Gauge"}
    assert {item["language"] for item in result["components"]} == {"rs", "c", "cpp"}
    # skeletons for all three languages, plus the C V2 candidate registration
    assert len(result["domains"]) == 4
    assert any(str(path).endswith("domains/candidates/meter.v2.yaml")
               for path in result["domains"])


def test_analyze_rust_struct_metadata(tmp_path):
    (tmp_path / "sensor.rs").write_text("pub struct Sensor { pub value: i32, }")
    result = analyze_codebase(tmp_path, project_root=tmp_path)
    comp = result["components"][0]
    assert comp["name"] == "Sensor" and comp["lang"] == "rs"
    assert comp["fields"] == [{"name": "value", "type": "int"}]


def test_analyze_c_struct_metadata(tmp_path):
    (tmp_path / "counter.c").write_text("struct Counter { int count; };")
    result = analyze_codebase(tmp_path, project_root=tmp_path)
    comp = result["components"][0]
    assert comp["name"] == "Counter" and comp["lang"] == "c"
    assert comp["fields"] == [{"name": "count", "type": "int"}]


def test_tree_sitter_fallback_extracts_java(tmp_path):
    (tmp_path / "Weird.java").write_text("class Weird { int x; }")
    with patch("pipeline.codebase_analysis.extract_components_ts", return_value=None):
        result = analyze_codebase(tmp_path, project_root=tmp_path)
    assert result["components"][0]["name"] == "Weird"
