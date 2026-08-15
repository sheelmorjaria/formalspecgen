import json
import javalang

from pipeline.deterministic_refactor import extract_null_object_from_inspection
from pipeline.java_inspection import inspect_java_file


SOURCE = """public class OrderService {
    private Logger logger;
    public OrderService() { this.logger = null; }
    public void first() { if (logger != null) { logger.log(); } }
    public void second() { if (logger != null) { logger.log(); } }
}
"""


def test_null_object_refactor_generates_interface_null_impl_and_rewrites_primary(tmp_path):
    source = tmp_path / "OrderService.java"; source.write_text(SOURCE)
    evidence = tmp_path / "inspection.json"; evidence.write_text(json.dumps(inspect_java_file(source)))
    result = extract_null_object_from_inspection(source, evidence)
    assert result["status"] == "TRANSFORMED"
    assert sorted(result["files"]) == ["Logger.java", "NullLogger.java", "OrderService.java"]
    assert "interface Logger" in result["files"]["Logger.java"]
    assert "class NullLogger implements Logger" in result["files"]["NullLogger.java"]
    primary = result["files"]["OrderService.java"]
    assert "new NullLogger()" in primary and "if (logger != null)" not in primary
    for content in result["files"].values():
        javalang.parse.parse(content)


def test_null_object_refactor_preserves_collaborator_arguments(tmp_path):
    source = tmp_path / "OrderService.java"
    source.write_text("""public class OrderService {
    private Logger logger;
    public OrderService() { this.logger = null; }
    public void first(String input) { if (this.logger != null) { this.logger.log(input); } }
    public void second(String input) { if (this.logger != null) { this.logger.log(input); } }
}
""")
    evidence = tmp_path / "inspection.json"
    evidence.write_text(json.dumps(inspect_java_file(source)))
    result = extract_null_object_from_inspection(source, evidence)
    assert result["status"] == "TRANSFORMED"
    assert "void log(String input);" in result["files"]["Logger.java"]
    assert "void log(String input)" in result["files"]["NullLogger.java"]
    assert "this.logger.log(input);" in result["files"]["OrderService.java"]
