import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline.domain_v2_promotion import ReviewedDomainSpecV2
from pipeline.v2_cpp_serializer import UnsupportedCppBoundary, _effect_expr, _expr, render_cpp
from pipeline.verify_cpp import verify_cpp


def reviewed_cpp():
    return ReviewedDomainSpecV2.model_validate({
        "schema_version": 2, "review_status": "reviewed", "domain_name": "DoorLatch",
        "module_name": "door_latch", "actors": 1, "state_variables": [
            {"kind": "int", "name": "door_state", "bound": [0, 1], "initial": 1},
            {"kind": "bool", "name": "locked", "initial": False}],
        "operations": [{"name": "LockDoor", "return_type": "void",
            "failure_semantics": "unavailable", "guards": [{"id": "closed", "expression": {
                "kind": "eq", "left": {"kind": "field", "name": "door_state"},
                "right": {"kind": "integer", "value": 1}}}],
            "effects": [{"id": "lock", "target": "locked", "value": {
                "kind": "boolean", "value": True}}], "frame": ["locked"]}],
        "tlc_invariants": [{"id": "safe", "expression": {"kind": "implies",
            "left": {"kind": "field", "name": "locked"},
            "right": {"kind": "eq", "left": {"kind": "field", "name": "door_state"},
                      "right": {"kind": "integer", "value": 1}}}}],
        "accepted_candidate_sha256": "a" * 64, "accepted_evidence_sha256": "b" * 64})


def test_cpp_serializer_is_deterministic_and_cpp17_shaped(tmp_path):
    code = render_cpp(reviewed_cpp())
    assert code == render_cpp(reviewed_cpp())
    assert "#include <cassert>" in code
    assert "class DoorLatch" in code
    assert "private:" in code and "int door_state;" in code and "bool locked;" in code
    assert "DoorLatch()" in code and "!(locked) ||" in code
    assert "void lock_door()" in code and "assert((door_state == 1))" in code
    source = tmp_path / "DoorLatch.cpp"
    source.write_text(code, encoding="utf-8")
    import shutil, subprocess
    if shutil.which("g++"):
        result = subprocess.run(["g++", "-std=c++17", "-fsyntax-only", str(source)],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr


def test_esbmc_adapter_mints_only_bounded_claim_and_fails_closed(tmp_path):
    source = tmp_path / "safe.cpp"
    source.write_text("int main() { return 0; }", encoding="utf-8")
    with patch("pipeline.verify_cpp.subprocess.run") as run:
        run.return_value = type("Result", (), {
            "returncode": 0, "stdout": "VERIFICATION SUCCESSFUL", "stderr": ""})()
        result = verify_cpp(source)
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "BOUNDED_CPP_PROOF"
    command = run.call_args.args[0]
    assert "--unwind" in command and "--z3" in command

    with patch("pipeline.verify_cpp.subprocess.run", side_effect=FileNotFoundError):
        assert verify_cpp(source)["status"] == "TOOL_MISSING"
    with patch("pipeline.verify_cpp.subprocess.run", side_effect=subprocess.TimeoutExpired("esbmc", 1)):
        assert verify_cpp(source)["status"] == "TIMEOUT"
    with patch("pipeline.verify_cpp.subprocess.run") as run:
        run.return_value = type("Result", (), {
            "returncode": 1, "stdout": "Verification failed", "stderr": "counterexample"})()
        assert verify_cpp(source)["claim"] == "NO_PROOF"


def test_cpp_expression_lowering_and_rejection_edges(tmp_path):
    from pipeline.domain_v2 import BinaryExpr, BooleanExpr, FieldExpr, IntegerExpr, NotExpr, OldExpr
    field = FieldExpr(name="x")
    assert _expr(field) == "x"
    assert _expr(OldExpr(expression=field)) == "this->x"
    assert _expr(BooleanExpr(value=True)) == "true"
    assert _expr(NotExpr(expression=BooleanExpr(value=False))) == "!(false)"
    assert "||" in _expr(BinaryExpr(kind="implies", left=field,
                                     right=IntegerExpr(value=1)))
    assert "&&" in _expr(BinaryExpr(kind="and", left=BooleanExpr(value=True),
                                    right=BooleanExpr(value=False)))
    assert _effect_expr(OldExpr(expression=field), {"x": "pre_x"}) == "pre_x"
    with pytest.raises(UnsupportedCppBoundary):
        _expr(object())
    with pytest.raises(UnsupportedCppBoundary):
        import pipeline.v2_cpp_serializer as cpp
        old_ops = cpp._OPS.pop("and")
        try:
            _expr(BinaryExpr(kind="and", left=BooleanExpr(value=True),
                             right=BooleanExpr(value=False)))
        finally:
            cpp._OPS["and"] = old_ops
    with pytest.raises(UnsupportedCppBoundary):
        _effect_expr(field, {})
    from pipeline.domain_v2 import BinaryExpr
    assert _effect_expr(NotExpr(expression=BooleanExpr(value=True)), {}) == "!(true)"
    assert "||" in _effect_expr(BinaryExpr(kind="implies", left=BooleanExpr(value=False),
                                            right=BooleanExpr(value=True)), {})
    assert _effect_expr(BinaryExpr(kind="add", left=IntegerExpr(value=1),
                                   right=IntegerExpr(value=2)), {}) == "(1 + 2)"
    with pytest.raises(UnsupportedCppBoundary):
        _effect_expr(object(), {})
    with pytest.raises(UnsupportedCppBoundary):
        old_ops = cpp._OPS.pop("and")
        try:
            _effect_expr(BinaryExpr(kind="and", left=BooleanExpr(value=True),
                                    right=BooleanExpr(value=False)), {})
        finally:
            cpp._OPS["and"] = old_ops

    import json
    from pathlib import Path
    path = tmp_path / "reviewed.json"
    path.write_text(json.dumps(reviewed_cpp().model_dump()), encoding="utf-8")
    from pipeline.v2_cpp_serializer import render_reviewed_v2_cpp_file
    assert render_reviewed_v2_cpp_file(path)[0].domain_name == "DoorLatch"


def test_cpp_serializer_rejects_async_concurrency_and_exceptions():
    async_domain = reviewed_cpp().model_copy(update={"execution_model": "async_message_passing"})
    with pytest.raises(UnsupportedCppBoundary, match="Tokio"):
        render_cpp(async_domain)
    lock_domain = reviewed_cpp().model_copy(update={"concurrency": {
        "mode": "lock_protocol", "lock_variable": "lock", "lock_states": ["FREE", "HELD"]}})
    with pytest.raises(UnsupportedCppBoundary, match="mutex"):
        render_cpp(lock_domain)
    exception = reviewed_cpp().operations[0].model_copy(update={"failure_semantics": "exception"})
    exception_domain = reviewed_cpp().model_copy(update={"operations": [exception]})
    with pytest.raises(UnsupportedCppBoundary, match="exception"):
        render_cpp(exception_domain)

    boolean_op = reviewed_cpp().operations[0].model_copy(update={
        "name": "TryLock", "return_type": "boolean", "failure_semantics": "false_and_stutter"})
    boolean_domain = reviewed_cpp().model_copy(update={"operations": [boolean_op]})
    code = render_cpp(boolean_domain)
    assert "bool try_lock()" in code and "return false;" in code and "return true;" in code
