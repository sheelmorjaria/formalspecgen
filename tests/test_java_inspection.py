from types import SimpleNamespace
from unittest.mock import patch

from pipeline import cli
from pipeline.java_inspection import (
    _callable_lines, _line, _mask_non_code, _matching_brace,
    _runtime_type_condition, inspect_java_file,
)


def _write(tmp_path, source, name="Legacy.java"):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return path


def test_inspection_detects_type_switch_long_method_and_overinjection(tmp_path):
    body = "\n".join("        int value%d = %d;" % (number, number)
                     for number in range(61))
    source = """public class Legacy {
    private Object type;
    public Legacy(A a, B b, C c, D d, E e) { }
    public int dispatch(Object item) {
        if (item instanceof A) { return 1; }
        else if (item instanceof B) { return 2; }
        return 0;
    }
    public void large() {
%s
    }
}
""" % body
    result = inspect_java_file(_write(tmp_path, source))
    assert result["status"] == "INSPECTED"
    assert result["parser_mode"] == "javalang_ast_0.13.0"
    assert {finding["code"] for finding in result["findings"]} == {
        "type-switch", "constructor-overinjection", "long-method"}
    assert not result["formal_defect_proved"]
    assert not result["automated_refactor_applied"]


def test_inspection_detects_god_class_at_exact_threshold(tmp_path):
    fields = "\n".join(f"    private int f{index};" for index in range(10))
    methods = "\n".join(f"    public void m{index}() {{ }}" for index in range(15))
    result = inspect_java_file(_write(
        tmp_path, f"public class Legacy {{\n{fields}\n{methods}\n}}"))
    assert result["metrics"] == {"fields": 10, "methods": 15}
    assert result["findings"][0]["code"] == "god-class"
    assert result["findings"][0]["suggested_pattern"] == "Facade"


def test_comments_literals_generics_and_clean_class_are_handled(tmp_path):
    source = '''public class Legacy {
    // if (x instanceof A) { }
    private String text = "else if (x instanceof B) {";
    public Legacy(java.util.Map<String, Integer> values, int x) { }
    public void run() { char brace = '}'; /* if (x.type == 1) */ }
}
'''
    result = inspect_java_file(_write(tmp_path, source))
    assert result["status"] == "INSPECTED"
    assert result["findings"] == []
    assert result["metrics"] == {"fields": 1, "methods": 2}


def test_ast_detects_getclass_and_discriminator_member_switches(tmp_path):
    source = '''public class Legacy {
    public int run(Object value, Item item) {
        if (value.getClass() == String.class) { return 1; }
        if (item.type == 2) { return 2; }
        return 0;
    }
}
'''
    result = inspect_java_file(_write(tmp_path, source))
    assert [finding["code"] for finding in result["findings"]] == ["type-switch"]


def test_lexical_span_defensive_boundaries():
    masked = _mask_non_code('class A { String x = "a\\\"b"; char c = \'\\\'\'; }')
    assert '"' not in masked and "String x" in masked and masked.count("{") == 1
    for invalid in ["/* unfinished", '"unfinished']:
        try:
            _mask_non_code(invalid)
        except ValueError as exc:
            assert "unterminated" in str(exc)
        else:
            raise AssertionError("unterminated lexical state was accepted")
    assert _matching_brace("{", 0) == 0
    assert not _runtime_type_condition("not-an-ast-node")
    assert _callable_lines("no brace", SimpleNamespace(body=[], position=SimpleNamespace(line=1))) == 0
    assert _callable_lines("", SimpleNamespace(body=None, position=None)) == 0
    assert _line(SimpleNamespace(position=None)) == 1


def test_inspection_fails_closed_on_input_and_syntax_boundaries(tmp_path):
    assert inspect_java_file(tmp_path / "missing.java")["code"] == "source_unavailable"
    assert inspect_java_file(_write(tmp_path, "public class Legacy {}", "Legacy.txt"))["code"] == \
        "unsupported_language"
    for source in ["public class Legacy {", "public class Legacy { } }",
                   'public class Legacy { String x = "bad\n; }',
                   "public class Legacy { /* bad"]:
        assert inspect_java_file(_write(tmp_path, source))["code"] == \
            "unsupported_java_syntax"
    assert inspect_java_file(_write(
        tmp_path, "class First {} class Second {}"))["code"] == "unsupported_class_shape"


def test_inspect_cli_writes_findings_and_returns_failure_status(tmp_path):
    source = _write(tmp_path, "public class Legacy {}")
    output = tmp_path / "inspection.json"
    args = cli.build_parser().parse_args(["inspect", str(source), "--json", str(output)])
    ui = SimpleNamespace(console=SimpleNamespace(print=lambda *_args, **_kwargs: None))
    assert cli.dispatch(args, ui, None, {}) == 0
    assert "STATIC_INSPECTION" in output.read_text(encoding="utf-8")
    with patch("pipeline.java_inspection.inspect_java_file",
               return_value={"status": "FAIL", "claim": "NO_PROOF"}):
        assert cli.command_inspect(args, ui) == 1
