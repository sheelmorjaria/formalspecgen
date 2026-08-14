import json

import javalang

from pipeline.deterministic_refactor import extract_facade_from_inspection
from pipeline.java_inspection import inspect_java_file


def test_facade_profile_emits_public_surface_wrapper(tmp_path):
    fields = "\n".join(f"    private int f{i};" for i in range(10))
    methods = "\n".join(f"    public int m{i}(int x) {{ return x; }}" for i in range(15))
    source_text = f"public class Legacy {{\n{fields}\n{methods}\n}}\n"
    source = tmp_path / "Legacy.java"
    source.write_text(source_text, encoding="utf-8")
    evidence = tmp_path / "inspection.json"
    evidence.write_text(json.dumps(inspect_java_file(source)), encoding="utf-8")
    result = extract_facade_from_inspection(source, evidence)
    assert result["status"] == "TRANSFORMED"
    facade = result["files"]["LegacyFacade.java"]
    assert "private final Legacy delegate;" in facade
    assert "return delegate.m0(x);" in facade
    javalang.parse.parse(facade)


def test_facade_profile_requires_hash_bound_god_class_finding(tmp_path):
    source = tmp_path / "Legacy.java"
    source.write_text("public class Legacy { public void run() {} }", encoding="utf-8")
    evidence = tmp_path / "inspection.json"
    evidence.write_text(json.dumps(inspect_java_file(source)), encoding="utf-8")
    result = extract_facade_from_inspection(source, evidence)
    assert result["status"] == "FAIL"
    assert result["code"] == "inspection_binding_mismatch"
