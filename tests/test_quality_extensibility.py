import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from pipeline.spec_lint import lint_spec
from pipeline.scaffold_domain import (DomainSpec, load_spec, registration_lines,
                                      scaffold_domain, scaffold_sources)
from pipeline.domains.train_crossing_extract import (
    UnsupportedJmlSemantics, _guard_id, extract_train_crossing_model,
    recognizes_train_crossing,
)
from pipeline.domains.train_crossing import TrainRoadCrossingTlaModel
from pipeline.jml_ast import BinaryExpr, FieldAccess, IntegerLiteral
from test_scaffold_domain import SPEC
from test_train_crossing_domain import TRAIN_CROSSING_JML


def test_spec_lint_detects_vacuity_frames_arrays_and_aggregates():
    code = r"""public class Smells {
private int count;
//@ ensures \result == true || \result == false;
//@ ensures true;
//@ ensures count == count;
//@ ensures (\product int i; 0 <= i && i < a.length; a[i]) >= 0;
public boolean update(int[] a) { count++; a[0] = 1; return true; }
}"""
    warnings = lint_spec(code)
    names = {item["code"] for item in warnings}
    assert {"vacuous-boolean-postcondition", "vacuous-true-clause", "self-equality",
            "openjml-unsupported-aggregate", "missing-array-nonnull",
            "missing-array-frame", "missing-field-frame"} <= names
    assert len({(item["line"], item["code"], item["message"]) for item in warnings}) == len(warnings)


def test_spec_lint_missing_postcondition_and_balanced_body_fallback():
    code = "public class C { public int value() { if (true) { return 1; } }"
    warnings = lint_spec(code)
    assert "missing-postcondition" in {item["code"] for item in warnings}
    # Unterminated methods fail conservatively without crashing the linter.
    assert lint_spec("public class C { public int value() { return 1;")


@pytest.mark.parametrize("change", [
    {"domain_name": "lowerCase"},
    {"state_variables": [{"name": "Bad", "type": "int", "bound": [0, 1]}]},
    {"state_variables": [{"name": "enabled", "type": "bool", "bound": [0, 1]}]},
    {"state_variables": [{"name": "enabled", "type": "int", "bound": [1, 1]}]},
    {"operations": [{**SPEC["operations"][0], "name": "bad-name"}]},
    {"operations": [{**SPEC["operations"][0], "guards": ["same", "same"]}]},
    {"operations": [{**SPEC["operations"][0], "frame": []}]},
    {"operations": [{**SPEC["operations"][0], "ast_pattern": "  "}]},
    {"tlc_invariants": ["badInvariant"]},
])
def test_domain_schema_rejects_unsafe_or_incomplete_values(change):
    with pytest.raises(ValidationError):
        DomainSpec.model_validate({**SPEC, **change})


def test_domain_schema_rejects_duplicates_and_generates_fail_closed_sources():
    duplicated = {**SPEC, "operations": SPEC["operations"] * 2}
    with pytest.raises(ValidationError, match="unique"):
        DomainSpec.model_validate(duplicated)
    spec = DomainSpec.model_validate(SPEC)
    outputs = scaffold_sources(spec)
    assert len(outputs) == 4
    assert "raises UnsupportedJmlSemantics" not in outputs[next(k for k in outputs if k.endswith("_extract.py"))]
    assert "raise UnsupportedJmlSemantics" in outputs[next(k for k in outputs if k.endswith("_render.py"))]
    assert registration_lines(spec)["plugin"].strip() == "LIGHT_SWITCH_PLUGIN,"


def test_load_spec_extensions_and_scaffold_force_no_register(tmp_path):
    bad = tmp_path / "domain.txt"
    bad.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="must use"):
        load_spec(bad)
    spec_file = tmp_path / "domain.json"
    spec_file.write_text(json.dumps(SPEC), encoding="utf-8")
    outputs = scaffold_domain(spec_file, project_root=tmp_path, register=False)
    assert len(outputs) == 4
    # Force makes regeneration explicit and does not require a registry when registration is off.
    assert len(scaffold_domain(spec_file, project_root=tmp_path, force=True, register=False)) == 4
    with pytest.raises(FileNotFoundError, match="registry"):
        scaffold_domain(spec_file, project_root=tmp_path, force=True, register=True)


def test_train_crossing_recognition_abstraction_and_complete_api_guards():
    assert recognizes_train_crossing(TRAIN_CROSSING_JML)
    assert not recognizes_train_crossing("class Crossing {}")
    with pytest.raises(UnsupportedJmlSemantics, match="atomic_operations"):
        extract_train_crossing_model(TRAIN_CROSSING_JML, "", "lock_protocol")
    missing = TRAIN_CROSSING_JML.replace("public void carLeaves() {}", "")
    with pytest.raises(UnsupportedJmlSemantics, match="all seven"):
        extract_train_crossing_model(missing, "")


def test_train_crossing_adapter_rejects_effect_and_reports_frame_mismatch():
    wrong_effect = TRAIN_CROSSING_JML.replace(
        "//@ ensures train_pos == 1;", "//@ ensures train_pos == 2;", 1)
    with pytest.raises(UnsupportedJmlSemantics, match="trainApproaches"):
        extract_train_crossing_model(wrong_effect, "")
    wrong_frame = TRAIN_CROSSING_JML.replace(
        "//@ assignable train_pos;", "//@ assignable gate_state;", 1)
    # The typed domain model independently rejects an adapter with a mismatched frame.
    with pytest.raises(ValidationError, match="invalid semantic mapping"):
        extract_train_crossing_model(wrong_frame, "")

    reversed_guard = BinaryExpr(kind="eq", left=IntegerLiteral(value=0),
                                right=FieldAccess(receiver="this", field="train_pos"))
    assert _guard_id(reversed_guard) == "train_is_away"
    assert _guard_id(IntegerLiteral(value=0)) is None
    field_to_field = BinaryExpr(
        kind="eq", left=FieldAccess(receiver="this", field="train_pos"),
        right=FieldAccess(receiver="this", field="gate_state"))
    assert _guard_id(field_to_field) is None


def test_train_crossing_model_rejects_operation_and_transition_order_drift():
    model, _ = extract_train_crossing_model(TRAIN_CROSSING_JML, "")
    payload = model.model_dump()
    with pytest.raises(ValidationError, match="operations are incomplete"):
        TrainRoadCrossingTlaModel(**{
            **payload, "operations": list(reversed(payload["operations"]))})
    with pytest.raises(ValidationError, match="transition evidence"):
        TrainRoadCrossingTlaModel(**{
            **payload, "transitions": list(reversed(payload["transitions"]))})
