"""Machine presentation and publication tests, without providers or verifiers."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from rich.console import Console

from pipeline import cli
from pipeline import cli_output
from pipeline.workflow_contracts import WorkflowContext


def invoke(argv, root):
    parser = cli.build_parser()
    return cli.dispatch(parser.parse_args(argv), cli.TerminalUI(), cli.SessionStore(root), {})


def response(capsys, code):
    captured = capsys.readouterr()
    value = json.loads(captured.out)
    assert value["schema"] == cli_output.CLI_RESULT_SCHEMA
    assert value["exit_code"] == code
    assert value["operation_satisfied"] == (code == 0)
    assert len(captured.out.splitlines()) == 1
    return value, captured.err


def test_inspection_stdout_uses_actual_result_without_write_effect(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "Counter.java"
    source.write_text("public class Counter { private int value; }")
    with patch.object(WorkflowContext, "for_cli", wraps=WorkflowContext.for_cli) as contexts:
        assert invoke(["inspect", str(source), "--json", "-"], tmp_path) == 0
        assert "workspace_write_new" not in contexts.call_args.args[0]
    value, _ = response(capsys, 0)
    result = value["result"]
    assert result["status"] == "INSPECTED"
    assert result["workflow_result"]["request"]["result_export"] is None
    assert not (tmp_path / "-").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["Counter.java"]


def test_negative_verification_stdout_never_requests_export_authority(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "x.c").write_text("int x;")
    with patch.object(cli, "execute_isolated_verification") as backend:
        assert invoke(["verify", "x.c", "--mode", "check", "--json", "-"], tmp_path) == 1
        backend.assert_not_called()
    value, diagnostic = response(capsys, 1)
    assert value["result"]["claim"] == "NO_PROOF"
    assert value["result"]["workflow_result"]["request"]["result_export"] is None
    assert diagnostic
    assert not (tmp_path / "-").exists()


@pytest.mark.parametrize("command", ["security-inspect", "verify-lockfree", "doctor"])
def test_legacy_json_stdout_uses_shared_envelope(tmp_path, capsys, command):
    if command == "security-inspect":
        args = [command, str(tmp_path / "absent"), "--json", "-"]
        assert invoke(args, tmp_path) == 1
        value, diagnostic = response(capsys, 1)
        assert value["result"]["code"] == "input_unavailable"
        assert diagnostic
    elif command == "verify-lockfree":
        with patch("pipeline.lockfree.verify_lockfree", return_value={
                "status": "LOCK_FREE_VERIFICATION_FAILED", "claim": "NO_PROOF"}):
            assert invoke([command, "x.c", "--json", "-"], tmp_path) == 1
        assert response(capsys, 1)[0]["result"]["claim"] == "NO_PROOF"
    else:
        with patch("pipeline.doctor.inspect_environment", return_value={"capabilities": []}), \
             patch("pipeline.doctor.required_failures", return_value=[]):
            assert invoke([command, "--json"], tmp_path) == 0
        assert response(capsys, 0)[0]["result"]["capabilities"] == []


@pytest.mark.parametrize("command", ["apply-refactor", "analyze-codebase", "generate-traceability-matrix"])
def test_controlled_workflows_negative_stdout(tmp_path, monkeypatch, capsys, command):
    monkeypatch.chdir(tmp_path)
    if command == "apply-refactor":
        args = [command, "absent.java", "--pattern", "extract-method", "--method", "f", "--out", "candidate.java"]
    elif command == "analyze-codebase":
        args = [command, "absent", "--out-dir", "analysis", "--project-root", "project"]
    else:
        args = [command, "absent.yaml", "src", "--reqs", "reqs.txt", "--out", "matrix.md"]
    code = invoke(args + ["--json", "-"], tmp_path)
    assert code != 0
    value, _ = response(capsys, code)
    if value["result"] is not None:
        assert value["result"]["claim"] == "NO_PROOF"
    else:
        assert value["error"]["code"] == "CLI_RESULT_UNAVAILABLE"
    assert not (tmp_path / "-").exists()


def test_analysis_positive_stdout_retains_published_references(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "src"
    source.mkdir()
    (source / "Counter.java").write_text(
        "public class Counter { private int value; public void inc() { if (value < 3) value++; } }")
    assert invoke(["analyze-codebase", "src", "--out-dir", "analysis", "--project-root", "project", "--json", "-"], tmp_path) == 0
    value, _ = response(capsys, 0)
    assert Path(value["result"]["architecture"]).is_file()
    assert not (tmp_path / "-").exists()


@pytest.mark.parametrize("command", ["compose", "reverify"])
def test_composition_early_failure_has_machine_error(tmp_path, capsys, command):
    argv = [command, str(tmp_path / "missing.json"), "--json", "-"]
    if command == "reverify":
        argv += ["--changed-module", "x"]
    assert invoke(argv, tmp_path) == 2
    value, diagnostic = response(capsys, 2)
    assert value["result"] is None
    assert value["error"]["code"] == "CLI_RESULT_UNAVAILABLE"
    assert "unreadable" in diagnostic


def test_signing_requires_real_export_before_dispatch(tmp_path, capsys):
    with patch("pipeline.workflow_services.run_refactor_verification") as service, \
         patch("pipeline.domain_v2_promotion.sign_artifact") as signer:
        assert invoke(["verify-refactor", "A.java", "B.java", "--signing-key", "human", "--json", "-"], tmp_path) == 2
        service.assert_not_called()
        signer.assert_not_called()
    assert "not stdout" in response(capsys, 2)[1]


@pytest.mark.parametrize("status", ["NO_FINDINGS", "FAIL"])
def test_file_export_collision_fails_without_replacement(tmp_path, capsys, status):
    destination = tmp_path / "result.json"
    destination.write_bytes(b"preserved")
    with patch("pipeline.security_poc.inspect_security", return_value={
            "status": status, "request_satisfied": status == "NO_FINDINGS"}):
        assert invoke(["security-inspect", "source", "--json", str(destination)], tmp_path) == 1
    assert destination.read_bytes() == b"preserved"
    assert "refusing to replace" in capsys.readouterr().err


@pytest.mark.parametrize("alias", ["input", "symlink", "hardlink"])
def test_export_cannot_overwrite_input_alias(tmp_path, alias):
    original = tmp_path / "source.java"
    original.write_bytes(b"class S {}")
    destination = original
    if alias != "input":
        destination = tmp_path / "result.json"
        if alias == "symlink":
            destination.symlink_to(original)
        else:
            os.link(original, destination)
    with pytest.raises(cli_output.CLIOutputError):
        cli._write_json({"status": "FAIL"}, str(destination), Console(file=io.StringIO()))
    assert original.read_bytes() == b"class S {}"


def test_export_race_is_no_replace(tmp_path):
    destination = tmp_path / "result.json"
    real_link = os.link
    def race(source, target):
        Path(target).write_bytes(b"other writer")
        return real_link(source, target)
    with patch("pipeline.mcp_artifacts.os.link", side_effect=race), pytest.raises(cli_output.CLIOutputError):
        cli._write_json({"claim": "NO_PROOF"}, str(destination), Console(file=io.StringIO()))
    assert destination.read_bytes() == b"other writer"


def test_fresh_export_keeps_semantic_shape_and_long_unicode(tmp_path):
    payload = {"claim": "NO_PROOF", "text": "[red]λ[/red]" * 1000}
    destination = tmp_path / "nested" / "result.json"
    cli._write_json(payload, str(destination), Console(file=io.StringIO(), width=20))
    assert json.loads(destination.read_text()) == payload


def test_machine_diagnostics_include_python_and_child_output(tmp_path, capfd):
    def run():
        print("python diagnostic")
        subprocess.run([sys.executable, "-c", "print('child diagnostic')"], check=True)
        cli._write_json({"claim": "NO_PROOF", "text": "[red]λ[/red]" * 1000}, "-", Console())
        return 0
    assert cli_output.run_machine_command("fixture", run) == 0
    captured = capfd.readouterr()
    assert json.loads(captured.out)["result"]["text"] == "[red]λ[/red]" * 1000
    assert "python diagnostic" in captured.err and "child diagnostic" in captured.err


@pytest.mark.parametrize("failure", ["exception", "duplicate", "missing", "invalid", "contradiction"])
def test_machine_failure_never_reports_success(capsys, failure):
    def run():
        if failure == "exception":
            raise ValueError("bad input")
        if failure == "missing":
            return 0
        if failure == "contradiction":
            cli._write_json({"request_satisfied": False}, "-", Console())
            return 0
        cli._write_json({"x": float("nan") if failure == "invalid" else 1}, "-", Console())
        if failure == "duplicate":
            cli._write_json({"x": 2}, "-", Console())
        return 0
    assert cli_output.run_machine_command("fixture", run) == 1
    assert response(capsys, 1)[0]["error"]


def test_actual_cli_process_stdout_is_single_json(tmp_path):
    source = tmp_path / "Counter.java"
    source.write_text("public class Counter { private int value; }")
    result = subprocess.run([
        sys.executable, "-m", "pipeline.cli", "inspect", str(source), "--json", "-"],
        capture_output=True, text=True, cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["result"]["status"] == "INSPECTED"
    assert not (tmp_path / "-").exists()


@pytest.mark.parametrize("command,backend,status", [
    ("compose", "verify_composition", "COMPOSITION_VERIFIED"),
    ("reverify", "reverify_composition", "REVERIFIED"),
])
def test_composition_machine_result_is_not_a_file(tmp_path, monkeypatch, capsys, command, backend, status):
    monkeypatch.chdir(tmp_path)
    artifact = tmp_path / "composition.json"
    artifact.write_text("{}")
    argv = [command, str(artifact), "--json", "-"]
    if command == "reverify":
        argv += ["--changed-module", "module"]
    payload = {"status": status, "claim": "NO_PROOF"}
    with patch("pipeline.composition_render." + backend, return_value=payload):
        assert invoke(argv, tmp_path) == 0
    assert response(capsys, 0)[0]["result"] == payload
    assert not (tmp_path / "-").exists()


def test_traceability_positive_stdout_keeps_default_sidecar(tmp_path, monkeypatch, capsys):
    from test_traceability import DOMAIN_YAML, REQUIREMENTS, SOURCE
    monkeypatch.chdir(tmp_path)
    (tmp_path / "domain.yaml").write_text(DOMAIN_YAML)
    (tmp_path / "requirements.req").write_text(REQUIREMENTS)
    (tmp_path / "Counter.java").write_text(SOURCE)
    assert invoke(["generate-traceability-matrix", "domain.yaml", "Counter.java",
                   "--reqs", "requirements.req", "--out", "matrix.md", "--json", "-"], tmp_path) == 0
    value, _ = response(capsys, 0)
    assert value["result"]["claim"] == "NO_PROOF"
    assert (tmp_path / "matrix.md").is_file()
    assert (tmp_path / "matrix.json").is_file()
    assert not (tmp_path / "-").exists()


def test_file_export_size_bound_is_unsuccessful(tmp_path, monkeypatch):
    monkeypatch.setattr(cli_output, "MAX_JSON_EXPORT_BYTES", 8)
    target = tmp_path / "result.json"
    with pytest.raises(cli_output.CLIOutputError, match="exceed"):
        cli._write_json({"text": "large result"}, str(target), Console(file=io.StringIO()))
    assert not target.exists()


def malformed_result(kind):
    if kind == "invalid-key":
        return {("not", "a JSON key"): "value"}
    if kind == "cycle":
        result = {}
        result["self"] = result
        return result
    result = {}
    # CPython's C JSON encoder can have a different nesting limit from the
    # Python encoder used for indented exports (notably on Python 3.12).
    for _ in range(max(10000, sys.getrecursionlimit() + 100)):
        result = {"nested": result}
    return result


@pytest.mark.parametrize("kind", ["invalid-key", "cycle", "depth"])
def test_malformed_machine_result_has_one_failure_envelope(capsys, kind):
    payload = malformed_result(kind)

    def run():
        cli._write_json(payload, "-", Console())
        return 0

    assert cli_output.run_machine_command("fixture", run) == 1
    envelope, _ = response(capsys, 1)
    assert envelope["result"] is None
    assert envelope["error"]["code"] == "CLI_RESULT_INVALID"
    # A failed serialization must not poison the next command's context.
    def next_run():
        cli._write_json({"claim": "NO_PROOF"}, "-", Console())
        return 0
    assert cli_output.run_machine_command("fixture", next_run) == 0
    assert response(capsys, 0)[0]["result"] == {"claim": "NO_PROOF"}


@pytest.mark.parametrize("kind", ["invalid-key", "cycle", "depth"])
def test_malformed_file_result_fails_before_publication(tmp_path, kind):
    target = tmp_path / "result.json"
    with patch("pipeline.cli_output.publish_new_artifacts") as publisher:
        with pytest.raises(cli_output.CLIOutputError, match="publication failed"):
            cli._write_json(malformed_result(kind), str(target), Console(file=io.StringIO()))
        publisher.assert_not_called()
    assert not target.exists()
