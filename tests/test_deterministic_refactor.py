import hashlib
import json
from types import SimpleNamespace
from unittest.mock import patch

import javalang

from pipeline import cli
from pipeline.deterministic_refactor import (
    _extract, _leading_jml_contract, extract_method_from_inspection,
)
from pipeline.java_inspection import inspect_java_file
from pipeline.refactor_gate import public_method_surface


def _fixture(tmp_path):
    statements = "\n".join(f"        total += {index};" for index in range(61))
    source = f'''public class Calculator {{
    //@ requires seed >= 0;
    //@ ensures \\result >= seed;
    public int calculate(int seed) {{
        int total = seed;
{statements}
        return total;
    }}
}}
'''
    baseline = tmp_path / "baseline" / "Calculator.java"
    baseline.parent.mkdir(parents=True); baseline.write_text(source, encoding="utf-8")
    inspection = inspect_java_file(baseline)
    evidence = tmp_path / "inspection.json"
    evidence.write_text(json.dumps(inspection), encoding="utf-8")
    return baseline, evidence, source


def test_extract_method_is_deterministic_hash_bound_and_api_preserving(tmp_path):
    baseline, evidence, source = _fixture(tmp_path)
    first = extract_method_from_inspection(baseline, evidence, "calculate")
    second = extract_method_from_inspection(baseline, evidence, "calculate")
    assert first == second
    assert first["claim"] == "DETERMINISTIC_REFACTOR_CANDIDATE"
    assert "return calculateExtracted(seed);" in first["source"]
    assert "private int calculateExtracted(int seed)" in first["source"]
    assert first["source"].count("//@ ensures \\result >= seed;") == 2
    assert public_method_surface(source) == public_method_surface(first["source"])
    javalang.parse.parse(first["source"])
    assert not first["formal_preservation_proved"]


def test_refactor_rejects_bad_evidence_and_method_boundaries(tmp_path):
    baseline, evidence, _ = _fixture(tmp_path)
    missing = extract_method_from_inspection(tmp_path / "missing.java", evidence, "calculate")
    assert missing["code"] == "input_unavailable"
    value = json.loads(evidence.read_text())
    for mutation in [
        {**value, "status": "FAIL"}, {**value, "claim": "NO_PROOF"},
        {**value, "source_sha256": "0" * 64},
    ]:
        evidence.write_text(json.dumps(mutation), encoding="utf-8")
        assert extract_method_from_inspection(baseline, evidence, "calculate")["code"] == \
            "inspection_binding_mismatch"
    evidence.write_text(json.dumps(value), encoding="utf-8")
    assert extract_method_from_inspection(baseline, evidence, "missing")["code"] == \
        "method_not_unique"
    no_long = {**value, "findings": []}
    evidence.write_text(json.dumps(no_long), encoding="utf-8")
    assert extract_method_from_inspection(baseline, evidence, "calculate")["code"] == \
        "method_not_inspected_long"


def test_refactor_rejects_abstract_collision_parse_and_span_failures(tmp_path):
    cases = [
        ("public abstract class C { public abstract int run(); }", "unsupported_method_shape"),
        ("public class C { public int run(){return 1;} private int runExtracted(){return 1;} }",
         "helper_name_collision"),
    ]
    for index, (source, expected) in enumerate(cases):
        path = tmp_path / f"C{index}.java"; path.write_text(source, encoding="utf-8")
        line = 1
        evidence = tmp_path / f"e{index}.json"
        evidence.write_text(json.dumps({"status": "INSPECTED", "claim": "STATIC_INSPECTION",
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "findings": [{"code": "long-method", "line": line}]}), encoding="utf-8")
        assert extract_method_from_inspection(path, evidence, "run")["code"] == expected

    bad = tmp_path / "Bad.java"; bad.write_text("public class Bad {", encoding="utf-8")
    bad_evidence = tmp_path / "bad.json"
    bad_evidence.write_text(json.dumps({"status": "INSPECTED", "claim": "STATIC_INSPECTION",
        "source_sha256": hashlib.sha256(bad.read_bytes()).hexdigest(), "findings": []}))
    assert extract_method_from_inspection(bad, bad_evidence, "run")["code"] == \
        "unsupported_java_syntax"

    baseline, evidence, _ = _fixture(tmp_path / "span")
    with patch("pipeline.deterministic_refactor._extract", side_effect=ValueError("span")):
        assert extract_method_from_inspection(baseline, evidence, "calculate")["code"] == \
            "unsupported_method_span"


def test_apply_refactor_cli_writes_candidate_and_runs_gate(tmp_path):
    baseline, evidence, _ = _fixture(tmp_path)
    destination = tmp_path / "refactored" / "Calculator.java"
    verdict = tmp_path / "verdict.json"
    args = cli.build_parser().parse_args(["apply-refactor", str(baseline),
        "--inspection", str(evidence), "--method", "calculate", "--out", str(destination),
        "--json", str(verdict)])
    ui = SimpleNamespace(console=SimpleNamespace(print=lambda *_args, **_kwargs: None))
    proof = {"status": "VERIFIED", "claim": "REFACTOR_CONTRACT_PRESERVED"}
    with patch("pipeline.refactor_gate.verify_contract_preserving_refactor", return_value=proof):
        assert cli.dispatch(args, ui, None, {}) == 0
    assert destination.exists() and "calculateExtracted" in destination.read_text()
    assert json.loads(verdict.read_text())["claim"] == "REFACTOR_CONTRACT_PRESERVED"

    with patch("pipeline.refactor_gate.verify_contract_preserving_refactor",
               return_value={"status": "FAIL", "claim": "NO_PROOF"}):
        assert cli.command_apply_refactor(args, ui) == 1
    with patch("pipeline.deterministic_refactor.extract_method_from_inspection",
               return_value={"status": "FAIL", "claim": "NO_PROOF"}):
        assert cli.command_apply_refactor(args, ui) == 1


def test_void_extraction_and_defensive_span_helpers(tmp_path):
    statements = "\n".join("        value++;" for _ in range(61))
    source = f"""public class Worker {{
    //@ assignable value;
    public void work() {{
{statements}
    }}
    private int value;
}}
"""
    baseline = tmp_path / "Worker.java"; baseline.write_text(source, encoding="utf-8")
    inspection = inspect_java_file(baseline)
    evidence = tmp_path / "worker.json"; evidence.write_text(json.dumps(inspection))
    result = extract_method_from_inspection(baseline, evidence, "work")
    assert "    workExtracted();" in result["source"]
    assert "return workExtracted" not in result["source"]

    fake = SimpleNamespace(position=SimpleNamespace(line=1), name="run", parameters=[],
                           return_type=None)
    try:
        _extract("public void run();", fake, "runExtracted")
    except ValueError as exc:
        assert "span" in str(exc)
    else:
        raise AssertionError("invalid method span was accepted")
    prefix = "\n//@ ensures true;\n"
    assert "ensures true" in _leading_jml_contract(prefix + "public void run() {}", len(prefix))
