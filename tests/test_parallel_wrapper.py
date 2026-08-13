import pytest
import subprocess
from unittest.mock import patch

from pipeline.parallel_wrapper import (
    check_rayon_syntax, parallel_partition_gate, render_rayon_wrapper,
)


KERNEL = """use prusti_contracts::*;

#[ensures(result == value + 1)]
pub fn process_chunk(value: i32) -> i32 {
    value + 1
}
"""


def test_rayon_wrapper_preserves_kernel_and_uses_immutable_partition():
    wrapped = render_rayon_wrapper(KERNEL, "process_chunk")
    assert KERNEL.rstrip() in wrapped
    assert "use rayon::prelude::*;" in wrapped
    assert "pub fn process_parallel(data: &[i32]) -> Vec<i32>" in wrapped
    assert "data.par_iter().map(|value| process_chunk(*value)).collect()" in wrapped
    assert "unsafe" not in wrapped and "unwrap(" not in wrapped and "expect(" not in wrapped
    result = parallel_partition_gate(
        KERNEL, wrapped, "process_chunk", kernel_deductive_proof=True,
        wrapper_compiled=True)
    assert result["claim"] == "PARALLEL_PARTITION_VERIFIED"
    assert result["partition_safety_proved"]
    assert not result["parallel_scheduler_proved"]
    assert not result["parallel_functional_equivalence_proved"]


def test_parallel_gate_fails_closed_on_proof_source_and_kernel_boundaries():
    wrapped = render_rayon_wrapper(KERNEL, "process_chunk")
    assert parallel_partition_gate(
        KERNEL, wrapped, "process_chunk", kernel_deductive_proof=False,
        wrapper_compiled=True)["code"] == \
        "kernel_not_proved"
    assert parallel_partition_gate(
        KERNEL, wrapped, "process_chunk", kernel_deductive_proof=True,
        wrapper_compiled=False)["code"] == "wrapper_not_compiled"
    assert parallel_partition_gate(
        KERNEL, wrapped + "\n", "process_chunk", kernel_deductive_proof=True,
        wrapper_compiled=True)["code"] == \
        "noncanonical_parallel_wrapper"
    assert parallel_partition_gate(
        "pub static COUNT: i32 = 0;\npub fn process_chunk(value: i32) -> i32 { value }\n",
        "", "process_chunk", kernel_deductive_proof=True,
        wrapper_compiled=True)["code"] == \
        "unsupported_kernel_boundary"
    for code, name in ((KERNEL, "bad-name"), ("pub fn other(value: i32) -> i32 { value }", "x")):
        with pytest.raises(ValueError):
            render_rayon_wrapper(code, name)


def test_real_offline_cargo_accepts_generated_rayon_wrapper():
    result = check_rayon_syntax(render_rayon_wrapper(KERNEL, "process_chunk"))
    assert result["status"] == "RAYON_CHECKED", result


def test_rayon_native_check_reports_tool_timeout_and_compile_failure():
    wrapped = render_rayon_wrapper(KERNEL, "process_chunk")
    with patch("pipeline.parallel_wrapper.subprocess.run", side_effect=FileNotFoundError):
        assert check_rayon_syntax(wrapped)["status"] == "TOOL_MISSING"
    with patch("pipeline.parallel_wrapper.subprocess.run",
               side_effect=subprocess.TimeoutExpired("cargo", 1)):
        assert check_rayon_syntax(wrapped)["status"] == "TIMEOUT"
    failed = subprocess.CompletedProcess([], 1, stdout="", stderr="type error")
    with patch("pipeline.parallel_wrapper.subprocess.run", return_value=failed):
        result = check_rayon_syntax(wrapped)
    assert result["status"] == "RAYON_CHECK_FAILED"
    assert result["output"] == "type error"
