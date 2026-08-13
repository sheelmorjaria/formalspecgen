import subprocess
from unittest.mock import patch

import pytest

from pipeline.domain_v2 import DomainSpecV2
from pipeline.domain_v2_promotion import ReviewedDomainSpecV2
from pipeline.v2_async_serializer import (
    async_static_gate, check_tokio_scaffold, render_tokio_scaffold,
)
from pipeline.v2_prusti_serializer import render_struct
from pipeline.v2_jml_serializer import render_class
from pipeline.v2_acsl_serializer import render_translation_unit


def async_value(reviewed=True):
    return {"schema_version": 2, "review_status": "reviewed" if reviewed else "unreviewed",
        "domain_name": "AsyncCounter", "module_name": "async_counter", "actors": 2,
        "execution_model": "async_message_passing", "concurrency": None,
        "state_variables": [{"kind": "int", "name": "value", "bound": [0, 2],
                             "initial": 0}],
        "operations": [{"name": "Increment", "return_type": "void",
            "failure_semantics": "unavailable", "guards": [],
            "effects": [{"id": "inc", "target": "value", "value": {"kind": "add",
                "left": {"kind": "field", "name": "value"},
                "right": {"kind": "integer", "value": 1}}}], "frame": ["value"]}],
        "tlc_invariants": [{"id": "Bound", "expression": {"kind": "lte",
            "left": {"kind": "field", "name": "value"},
            "right": {"kind": "integer", "value": 2}}}],
        **({"accepted_candidate_sha256": "a" * 64,
            "accepted_evidence_sha256": "b" * 64} if reviewed else {})}


def test_schema_accepts_async_metadata_and_rejects_unsound_combinations():
    parsed = DomainSpecV2.model_validate(async_value(False))
    assert parsed.execution_model == "async_message_passing"
    one = async_value(False); one["actors"] = 1
    with pytest.raises(ValueError, match="at least two actors"):
        DomainSpecV2.model_validate(one)
    mixed = async_value(False); mixed["concurrency"] = {
        "mode": "lock_protocol", "lock_variable": "value",
        "lock_states": ["FREE", "A", "B"]}
    with pytest.raises(ValueError, match="cannot also claim"):
        DomainSpecV2.model_validate(mixed)


def test_tokio_serializer_is_panic_free_and_gate_downgrades_claims():
    reviewed = ReviewedDomainSpecV2.model_validate(async_value())
    code = render_tokio_scaffold(reviewed)
    assert code == render_struct(reviewed)
    assert "tokio::sync::mpsc" in code and "pub async fn send_increment" in code
    assert "NonZeroUsize" in code
    assert "unwrap(" not in code and "expect(" not in code and "panic!(" not in code
    result = async_static_gate(reviewed, code, native_checked=True)
    assert result["claims"] == ["BOUNDED_ARCHITECTURE_EVIDENCE", "STATIC_CHECK"]
    assert not result["source_refinement_proved"]
    assert not result["async_linearizability_proved"]
    assert not result["distributed_delivery_proved"]
    assert async_static_gate(reviewed, code, native_checked=False)["code"] == "native_not_checked"
    assert async_static_gate(reviewed, code + "\n", native_checked=True)["code"] == \
        "noncanonical_async_surface"
    atomic = reviewed.model_copy(update={"execution_model": None})
    assert async_static_gate(atomic, "", native_checked=True)["code"] == \
        "missing_async_execution_model"
    with pytest.raises(ValueError, match="requires async"):
        render_tokio_scaffold(atomic)
    with pytest.raises(ValueError, match="restricted to the Rust Tokio"):
        render_class(reviewed)
    with pytest.raises(ValueError, match="restricted to the Rust Tokio"):
        render_translation_unit(reviewed)


def test_real_offline_cargo_accepts_tokio_scaffold_and_failures_are_reported():
    code = render_tokio_scaffold(ReviewedDomainSpecV2.model_validate(async_value()))
    assert check_tokio_scaffold(code)["status"] == "TOKIO_CHECKED"
    with patch("pipeline.v2_async_serializer.subprocess.run", side_effect=FileNotFoundError):
        assert check_tokio_scaffold(code)["status"] == "TOOL_MISSING"
    with patch("pipeline.v2_async_serializer.subprocess.run",
               side_effect=subprocess.TimeoutExpired("cargo", 1)):
        assert check_tokio_scaffold(code)["status"] == "TIMEOUT"
    with patch("pipeline.v2_async_serializer.subprocess.run",
               return_value=subprocess.CompletedProcess([], 1, "", "bad")):
        assert check_tokio_scaffold(code)["status"] == "TOKIO_CHECK_FAILED"
