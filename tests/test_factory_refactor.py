import json
from types import SimpleNamespace
from unittest.mock import patch

import javalang

from pipeline import cli
from pipeline.deterministic_refactor import (
    _factory_files, extract_factory_from_inspection, source_file_name,
)
from pipeline.java_inspection import inspect_java_file


SOURCE = '''public class Creator {
    //@ requires kind != null;
    //@ ensures \\result != null;
    public Product create(String kind) {
        if (kind.equals("alpha")) return new Alpha();
        else return new Beta();
    }
}
'''


def _fixture(tmp_path, source=SOURCE):
    baseline = tmp_path / "baseline" / "Creator.java"
    baseline.parent.mkdir(parents=True); baseline.write_text(source, encoding="utf-8")
    evidence = tmp_path / "inspection.json"
    evidence.write_text(json.dumps(inspect_java_file(baseline)), encoding="utf-8")
    return baseline, evidence


def test_factory_extraction_generates_three_parseable_hash_bound_files(tmp_path):
    baseline, evidence = _fixture(tmp_path)
    result = extract_factory_from_inspection(baseline, evidence, "create")
    assert result["claim"] == "DETERMINISTIC_MULTIFILE_REFACTOR_CANDIDATE"
    assert sorted(result["files"]) == [
        "Creator.java", "DefaultProductFactory.java", "ProductFactory.java"]
    assert "return productFactory.create(kind);" in result["files"]["Creator.java"]
    assert "if (kind.equals" in result["files"]["DefaultProductFactory.java"]
    assert result["files"]["ProductFactory.java"].count("ensures") == 1
    for source in result["files"].values():
        javalang.parse.parse(source)
    assert not result["formal_preservation_proved"]


def test_factory_extraction_fails_closed_on_binding_and_shape(tmp_path):
    baseline, evidence = _fixture(tmp_path)
    value = json.loads(evidence.read_text())
    for mutation in [{**value, "source_sha256": "0" * 64},
                     {**value, "findings": []}, {**value, "status": "FAIL"}]:
        evidence.write_text(json.dumps(mutation))
        assert extract_factory_from_inspection(baseline, evidence, "create")["code"] == \
            "inspection_binding_mismatch"
    evidence.write_text(json.dumps(value))
    assert extract_factory_from_inspection(baseline, evidence, "missing")["code"] == \
        "inspection_binding_mismatch"

    shapes = [
        SOURCE.replace("new Alpha()", "new Alpha(kind)"),
        SOURCE.replace("if (kind.equals(\"alpha\")) return new Alpha();\n        else return new Beta();",
                       "return new Alpha();"),
        SOURCE.replace("kind.equals(\"alpha\")", "isAlpha()"),
    ]
    for index, source in enumerate(shapes):
        candidate, candidate_evidence = _fixture(tmp_path / str(index), source)
        inspection = json.loads(candidate_evidence.read_text())
        inspection["findings"] = [{"code": "conditional-object-creation", "method": "create"}]
        candidate_evidence.write_text(json.dumps(inspection))
        assert extract_factory_from_inspection(candidate, candidate_evidence, "create")["code"] == \
            "unsupported_factory_shape"


def test_factory_external_input_parse_collision_and_span_boundaries(tmp_path):
    baseline, evidence = _fixture(tmp_path)
    assert extract_factory_from_inspection(tmp_path / "missing.java", evidence, "create")["code"] == \
        "input_unavailable"
    evidence.write_text("not json")
    assert extract_factory_from_inspection(baseline, evidence, "create")["code"] == \
        "input_unavailable"

    bad = tmp_path / "Bad.java"; bad.write_text("public class Bad {")
    bad_evidence = tmp_path / "bad.json"
    import hashlib
    bad_evidence.write_text(json.dumps({"status": "INSPECTED", "claim": "STATIC_INSPECTION",
        "source_sha256": hashlib.sha256(bad.read_bytes()).hexdigest(),
        "findings": [{"code": "conditional-object-creation", "method": "create"}]}))
    assert extract_factory_from_inspection(bad, bad_evidence, "create")["code"] == \
        "unsupported_java_syntax"

    baseline, evidence = _fixture(tmp_path / "duplicate")
    duplicate = baseline.read_text().replace("\n}\n", '''
    public Product create(int kind) { if (kind == 1) return new Alpha(); else return new Beta(); }
}
''')
    baseline.write_text(duplicate)
    inspection = inspect_java_file(baseline)
    inspection["findings"] = [{"code": "conditional-object-creation", "method": "create"}]
    evidence.write_text(json.dumps(inspection))
    assert extract_factory_from_inspection(baseline, evidence, "create")["code"] == \
        "method_not_unique"

    baseline, evidence = _fixture(tmp_path / "collision",
                                  SOURCE.replace("public class Creator {",
                                                 "public class Creator {\n    private ProductFactory existing;"))
    assert extract_factory_from_inspection(baseline, evidence, "create")["code"] == \
        "unsupported_method_span"
    assert source_file_name("public class Named {}") == "Named.java"
    try:
        source_file_name("class Hidden {}")
    except ValueError as exc:
        assert "public primary" in str(exc)
    else:
        raise AssertionError("non-public primary was accepted")

    baseline, evidence = _fixture(tmp_path / "span")
    with patch("pipeline.deterministic_refactor._factory_files", side_effect=ValueError("span")):
        assert extract_factory_from_inspection(baseline, evidence, "create")["code"] == \
            "unsupported_method_span"
    fake = SimpleNamespace(position=SimpleNamespace(line=1), name="create", parameters=[])
    try:
        _factory_files("public Product create();", fake, "Product")
    except ValueError as exc:
        assert "span" in str(exc)
    else:
        raise AssertionError("invalid factory span was accepted")


def test_factory_action_writes_directory_and_invokes_multifile_gate(tmp_path):
    baseline, evidence = _fixture(tmp_path)
    destination = tmp_path / "out"
    verdict = tmp_path / "verdict.json"
    args = cli.build_parser().parse_args(["apply-refactor", str(baseline),
        "--inspection", str(evidence), "--pattern", "factory-method", "--method", "create",
        "--out", str(destination), "--json", str(verdict)])
    ui = SimpleNamespace(console=SimpleNamespace(print=lambda *_args, **_kwargs: None))
    proof = {"status": "VERIFIED", "claim": "MULTIFILE_REFACTOR_CONTRACT_PRESERVED"}
    with patch("pipeline.refactor_gate.verify_multifile_contract_refactor",
               return_value=proof) as gate:
        assert cli.command_apply_refactor(args, ui) == 0
    gate.assert_called_once_with(str(baseline), destination)
    assert (destination / "ProductFactory.java").exists()
    assert json.loads(verdict.read_text())["claim"] == \
        "MULTIFILE_REFACTOR_CONTRACT_PRESERVED"
