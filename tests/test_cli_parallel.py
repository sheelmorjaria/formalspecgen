import io
import json
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from pipeline import cli


KERNEL = """use prusti_contracts::*;
#[ensures(result == value + 1)]
pub fn process_chunk(value: i32) -> i32 { value + 1 }
"""


def args(tmp_path, suffix="rs"):
    source = tmp_path / f"kernel.{suffix}"; source.write_text(KERNEL)
    return SimpleNamespace(stub=str(source), provider="ollama", assurance_level="critical",
        method_proof_only=False, model=None, out=None, max_attempts=1, resample_budget=0,
        feedback_budget=0, accept_pass=[], clarifications=None,
        abstraction="atomic_operations", v2_reviewed_domain=None,
        v2_validation_evidence=None, json=str(tmp_path / "verdict.json"),
        parallel_wrapper="rayon", parallel_kernel="process_chunk",
        parallel_out=str(tmp_path / "parallel.rs"))


def ui():
    return cli.TerminalUI(Console(file=io.StringIO(), force_terminal=False), lambda _: "")


def test_implement_rayon_wraps_only_successfully_proved_kernel(tmp_path):
    result = {"final_status": "VERIFIED", "claim": "DEDUCTIVE_PROOF",
              "implementation_code": KERNEL}
    values = args(tmp_path)
    with patch.object(cli, "run_implementation_loop", return_value=result), patch(
            "pipeline.parallel_wrapper.check_rayon_syntax",
            return_value={"status": "RAYON_CHECKED", "exit_code": 0}):
        assert cli.command_implement(values, ui()) == 0
    verdict = json.loads((tmp_path / "verdict.json").read_text())
    assert verdict["final_status"] == "PARALLEL_PARTITION_VERIFIED"
    assert verdict["partition_safety_proved"]
    assert not verdict["parallel_scheduler_proved"]
    assert "par_iter()" in (tmp_path / "parallel.rs").read_text()


def test_implement_rayon_fails_closed_without_kernel_proof_or_on_non_rust(tmp_path):
    values = args(tmp_path)
    with patch.object(cli, "run_implementation_loop", return_value={
            "final_status": "STATIC_CHECKED", "claim": "STATIC_CHECK",
            "implementation_code": KERNEL}), patch(
                "pipeline.parallel_wrapper.check_rayon_syntax",
                return_value={"status": "RAYON_CHECKED", "exit_code": 0}):
        assert cli.command_implement(values, ui()) == 1
    assert not (tmp_path / "parallel.rs").exists()
    java = args(tmp_path, "java")
    with patch.object(cli, "run_implementation_loop", return_value={
            "final_status": "VERIFIED", "claim": "DEDUCTIVE_PROOF"}):
        assert cli.command_implement(java, ui()) == 1


def test_implement_rayon_rejects_unsupported_kernel_shape_and_compile_failure(tmp_path):
    values = args(tmp_path)
    with patch.object(cli, "run_implementation_loop", return_value={
            "final_status": "VERIFIED", "claim": "DEDUCTIVE_PROOF",
            "implementation_code": "pub fn other(value: i32) -> i32 { value }"}):
        assert cli.command_implement(values, ui()) == 1
    with patch.object(cli, "run_implementation_loop", return_value={
            "final_status": "VERIFIED", "claim": "DEDUCTIVE_PROOF",
            "implementation_code": KERNEL}), patch(
                "pipeline.parallel_wrapper.check_rayon_syntax",
                return_value={"status": "RAYON_CHECK_FAILED", "exit_code": 1}):
        assert cli.command_implement(values, ui()) == 1


def test_parser_registers_rayon_wrapper_options():
    parsed = cli.build_parser().parse_args([
        "implement", "kernel.rs", "--parallel-wrapper", "rayon",
        "--parallel-kernel", "map_one", "--parallel-out", "parallel.rs"])
    assert parsed.parallel_wrapper == "rayon"
    assert parsed.parallel_kernel == "map_one"
