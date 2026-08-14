import json

import javalang

from pipeline.deterministic_refactor import extract_state_from_inspection
from pipeline.java_inspection import inspect_java_file


SOURCE = '''public class Legacy {
    private int state;

    public int run() {
        if (state == 0) { return 1; }
        if (state == 1) { return 2; }
        return 0;
    }

    public int other() {
        if (state == 0) { return 3; }
        if (state == 1) { return 4; }
        return 0;
    }
}
'''


def test_state_profile_emits_parseable_handlers_and_primary(tmp_path):
    source = tmp_path / "Legacy.java"
    source.write_text(SOURCE, encoding="utf-8")
    evidence = tmp_path / "inspection.json"
    evidence.write_text(json.dumps(inspect_java_file(source)), encoding="utf-8")
    result = extract_state_from_inspection(source, evidence, "run")
    assert result["status"] == "TRANSFORMED"
    assert result["heap_topology_equivalence_proved"] is False
    assert sorted(result["files"]) == ["Legacy.java", "State.java", "StateHandler1.java",
                                       "StateHandler2.java"]
    assert "new StateHandler1().handle()" in result["files"]["Legacy.java"]
    for content in result["files"].values():
        javalang.parse.parse(content)


def test_state_profile_rejects_stale_or_complex_evidence(tmp_path):
    source = tmp_path / "Legacy.java"
    source.write_text(SOURCE.replace("return 1;", "state++; return 1;"), encoding="utf-8")
    evidence = tmp_path / "inspection.json"
    evidence.write_text(json.dumps(inspect_java_file(source)), encoding="utf-8")
    result = extract_state_from_inspection(source, evidence, "run")
    assert result["status"] == "FAIL"
    assert result["code"] == "unsupported_state_shape"
