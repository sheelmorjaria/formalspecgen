import pytest

from pipeline.domain_v2 import (
    BinaryExpr, BooleanExpr, FieldExpr, IntegerExpr, NotExpr, OldExpr,
)
from pipeline.domain_v2_promotion import ReviewedDomainSpecV2
from pipeline.v2_jml_serializer import render_class
from pipeline.v2_lock_serializer import (
    UnsupportedLockSerialization, _field_names, _rust_expr,
    lock_discipline_gate, render_reviewed_rust_mutex_file, render_rust_mutex,
)


def reviewed_lock_domain():
    return ReviewedDomainSpecV2.model_validate({
        "schema_version": 2, "review_status": "reviewed",
        "domain_name": "LockedCounter", "module_name": "locked_counter", "actors": 2,
        "state_variables": [
            {"kind": "int", "name": "lock_state", "bound": [0, 2], "initial": 0},
            {"kind": "int", "name": "value", "bound": [0, 2], "initial": 0}],
        "concurrency": {"mode": "lock_protocol", "lock_variable": "lock_state",
            "lock_states": ["UNLOCKED", "LOCKED_A", "LOCKED_B"],
            "unlocked_value": 0, "actor_lock_values": [1, 2],
            "linearization_points": {"Increment": "effect_commit"}},
        "operations": [{"name": "Increment", "return_type": "void",
            "failure_semantics": "unavailable", "guards": [{"id": "below", "expression": {
                "kind": "lt", "left": {"kind": "field", "name": "value"},
                "right": {"kind": "integer", "value": 2}}}],
            "effects": [{"id": "increment", "target": "value", "value": {
                "kind": "add", "left": {"kind": "field", "name": "value"},
                "right": {"kind": "integer", "value": 1}}}], "frame": ["value"]}],
        "tlc_invariants": [{"id": "ValueBounded", "expression": {
            "kind": "lte", "left": {"kind": "field", "name": "value"},
            "right": {"kind": "integer", "value": 2}}}],
        "accepted_candidate_sha256": "a" * 64,
        "accepted_evidence_sha256": "b" * 64,
    })


def test_rust_mutex_serializer_compiles_shape_and_preserves_simultaneous_rhs():
    code = render_rust_mutex(reviewed_lock_domain())
    assert "pub fn increment(&self) -> Result<(), LockError>" in code
    assert "let pre_value = state.value;" in code
    assert "state.value = pre_value + 1;" in code
    assert "return Err(LockError::Unavailable);" in code
    assert "unsafe" not in code and ".unwrap(" not in code and ".expect(" not in code


def test_exact_lock_discipline_gate_accepts_canonical_java_and_rust_only():
    reviewed = reviewed_lock_domain()
    java = render_class(reviewed)
    rust = render_rust_mutex(reviewed)
    for language, source in (("java", java), ("rust", rust)):
        result = lock_discipline_gate(reviewed, source, language)
        assert result["status"] == "VERIFIED"
        assert result["claim"] == "LOCK_DISCIPLINE_VERIFIED"
        assert result["lock_discipline_proved"]
        assert not result["source_model_refinement_proved"]
        assert not result["concurrent_linearizability_proved"]
        assert lock_discipline_gate(reviewed, source + "\n", language)[
            "code"] == "noncanonical_lock_surface"


def test_lock_discipline_gate_rejects_missing_protocol_and_unsupported_language():
    reviewed = reviewed_lock_domain()
    atomic = reviewed.model_copy(update={"concurrency": None})
    assert lock_discipline_gate(atomic, "", "rust")["code"] == "missing_lock_protocol"
    assert lock_discipline_gate(reviewed, "", "c")["code"] == "unsupported_language"


def test_lock_expression_lowering_covers_typed_recursive_nodes():
    field = FieldExpr(name="ready")
    old = OldExpr(expression=field)
    negated = NotExpr(expression=BooleanExpr(value=False))
    assert _rust_expr(BooleanExpr(value=True), {}) == "true"
    assert _rust_expr(old, {"ready": "pre_ready"}) == "pre_ready"
    assert _rust_expr(negated, {}) == "!(false)"
    implication = BinaryExpr(kind="implies", left=field,
                             right=BooleanExpr(value=True))
    assert "||" in _rust_expr(implication, {})
    assert _field_names(old) == {"ready"}
    assert _field_names(negated) == set()
    assert _field_names(IntegerExpr(value=1)) == set()
    with pytest.raises(UnsupportedLockSerialization, match="unsupported lock expression"):
        _rust_expr(object(), {})


def test_rust_mutex_file_loader_and_incomplete_boundaries(tmp_path):
    reviewed = reviewed_lock_domain()
    path = tmp_path / "reviewed.json"
    path.write_text(reviewed.model_dump_json(), encoding="utf-8")
    loaded, code = render_reviewed_rust_mutex_file(path)
    assert loaded.domain_name == "LockedCounter"
    assert code == render_rust_mutex(reviewed)

    incomplete = reviewed.model_copy(update={
        "concurrency": reviewed.concurrency.model_copy(
            update={"linearization_points": None})})
    with pytest.raises(UnsupportedLockSerialization, match="complete lock protocol"):
        render_rust_mutex(incomplete)
    lock_only = reviewed.model_copy(update={
        "state_variables": [reviewed.state_variables[0]]})
    with pytest.raises(UnsupportedLockSerialization, match="concrete protected state"):
        render_rust_mutex(lock_only)
