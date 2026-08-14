import json

import javalang

from pipeline.deterministic_refactor import extract_decorator_from_inspection
from pipeline.java_inspection import inspect_java_file


SOURCE = '''public class Example implements Service {
    private final Service delegate;
    public Example(Service delegate) { this.delegate = delegate; }
    public void run() { Logger.info("run"); delegate.run(); }
    public void reset() { Metrics.increment("reset"); delegate.reset(); }
}
'''


def test_decorator_profile_emits_wrapper_and_preserves_baseline(tmp_path):
    source = tmp_path / "Example.java"
    source.write_text(SOURCE, encoding="utf-8")
    evidence = tmp_path / "inspection.json"
    evidence.write_text(json.dumps(inspect_java_file(source)), encoding="utf-8")
    result = extract_decorator_from_inspection(source, evidence)
    assert result["status"] == "TRANSFORMED"
    assert result["files"]["Example.java"] == SOURCE
    wrapper = result["files"]["ExampleDecorator.java"]
    assert "implements Service" in wrapper
    assert "delegate.run();" in wrapper
    for content in result["files"].values():
        javalang.parse.parse(content)


def test_decorator_profile_rejects_parameterized_methods(tmp_path):
    source = tmp_path / "Example.java"
    source.write_text(SOURCE.replace("void run()", "void run(int value)"), encoding="utf-8")
    evidence = tmp_path / "inspection.json"
    evidence.write_text(json.dumps(inspect_java_file(source)), encoding="utf-8")
    result = extract_decorator_from_inspection(source, evidence)
    assert result["status"] == "FAIL"
    assert result["code"] == "unsupported_decorator_shape"
