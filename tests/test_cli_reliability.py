"""Routing and outcome regressions; no provider or backend is executed."""
import argparse
import io
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from rich.console import Console
from prompt_toolkit.document import Document
from prompt_toolkit.completion import CompleteEvent

from pipeline import cli
from pipeline.parity_inventory import inventory_cli
from pipeline.security_poc import inspect_security
from pipeline.security_assessment import run_semgrep


def ui():
    return cli.TerminalUI(Console(file=io.StringIO()), lambda _: "")


@pytest.mark.parametrize("prefix", ["", "/", "formalspecgen "])
def test_all_registered_commands_route_without_drafting(prefix):
    parser = cli.build_parser()
    expected = next(a.choices for a in parser._actions
                    if isinstance(a, argparse._SubParsersAction))
    assert cli.repl_commands(parser) == set(expected)
    for name in expected:
        assert cli._repl_argv(prefix + name + " --help", parser) == [name, "--help"]


def test_registered_plugin_routes_and_appears_in_inventory():
    plugin = cli.CommandPlugin(
        abi_id=cli.CLI_COMMAND_PLUGIN_ABI, plugin_id="test.commands",
        declarations=(cli.CommandDeclaration(
            capability_name="sample", command_name="sample-command",
            handler_id="test:sample", handler=lambda _: 0),))
    parser = cli.build_parser((plugin,))
    args = parser.parse_args(cli._repl_argv("/sample-command", parser))
    assert args.command == "sample-command"
    assert "sample-command" in inventory_cli((plugin,))["repl"]["command_routes"]
    with pytest.raises(ValueError):
        cli._repl_argv("/sample-command", cli.build_parser())


@pytest.mark.parametrize("line", ["/not-a-command", "formalspecgen typo", "typo --flag",
                                  "Design a counter", "", "/", "formalspecgen",
                                  '/verify "unclosed'])
def test_invalid_repl_input_is_rejected(line):
    with pytest.raises(ValueError):
        cli._repl_argv(line, cli.build_parser())


def test_repl_survives_bad_input_without_dispatch_and_generates_help(tmp_path):
    lines = iter(['/verify "unclosed', "/not-a-command", "bare prose", "/help", "/quit"])
    terminal = ui()
    store = cli.SessionStore(tmp_path)
    with patch.object(cli, "PromptSession") as session, patch.object(cli, "dispatch") as dispatch:
        session.return_value.prompt.side_effect = lambda _: next(lines)
        assert cli.repl(cli.build_parser(), terminal, store, {}) == 0
        dispatch.assert_not_called()
        completer = session.call_args.kwargs["completer"]
        assert "/analyze-codebase" in completer.words
        assert [item.text for item in completer.get_completions(
            Document("/analyze-"), CompleteEvent())] == ["/analyze-codebase"]
        assert "validate-architecture" in terminal.console.file.getvalue()


def test_security_missing_input_exits_unsuccessfully(tmp_path):
    destination = tmp_path / "result.json"
    with patch("pipeline.security_poc.verify") as verify, patch("pipeline.security_poc.run_semgrep") as sast:
        assert cli.command_security_inspect(SimpleNamespace(
            source=str(tmp_path / "absent.java"), json=str(destination)), ui()) == 1
        verify.assert_not_called()
        sast.assert_not_called()
    assert json.loads(destination.read_text())["request_satisfied"] is False


@pytest.mark.parametrize("code,output", [(1, "type error"), (124, "timeout"),
    (125, "sandbox unavailable PossiblyNegativeIndex"), (127, "tool missing"),
    (19, "unknown failure"), (0, "Not implemented for static checking")])
def test_verifier_failure_is_not_completed_inspection(tmp_path, code, output):
    source = tmp_path / "S.java"
    source.write_text("class S {}")
    with patch("pipeline.security_poc.verify", return_value=(code, output)), \
         patch("pipeline.security_poc.run_semgrep", return_value={"status": "CLEAN"}):
        result = inspect_security(source)
    assert result["status"] == "SECURITY_INSPECTION_INCOMPLETE"
    assert result["claim"] == "NO_PROOF"
    assert not result["request_satisfied"]
    assert not result["findings"]
    assert result["files_checked"][0]["formal_output"] == output


@pytest.mark.parametrize("status", ["TOOL_MISSING", "TIMEOUT", "INVALID_OUTPUT", "ERROR"])
def test_sast_failure_retains_findings_but_prevents_completion(tmp_path, status):
    source = tmp_path / "S.java"
    source.write_text("class S {}")
    with patch("pipeline.security_poc.verify", return_value=(6, "PossiblyNegativeIndex")), \
         patch("pipeline.security_poc.run_semgrep", return_value={"status": status}):
        result = inspect_security(source)
    assert result["status"] == "SECURITY_INSPECTION_INCOMPLETE"
    assert result["findings"][0]["cwe"] == "CWE-125"
    assert result["files_checked"][0]["sast"]["status"] == status


def test_directory_failure_does_not_erase_other_file_findings(tmp_path):
    for name in ("A.java", "B.java"):
        (tmp_path / name).write_text("class " + name[:-5] + " {}")
    with patch("pipeline.security_poc.verify", side_effect=[
            (6, "PossiblyNegativeIndex"), (127, "tool missing")]), \
         patch("pipeline.security_poc.run_semgrep", return_value={"status": "CLEAN"}):
        result = inspect_security(tmp_path)
    assert not result["request_satisfied"]
    assert len(result["files_checked"]) == 2
    assert result["findings"][0]["file"] == str(tmp_path / "A.java")
    assert result["files_checked"][1]["formal_status"] == "TOOL_MISSING"


@pytest.mark.parametrize("code,output,status", [(0, "", "NO_FINDINGS"),
    (6, "PossiblyNegativeIndex", "VULNERABILITIES_FOUND")])
def test_completed_scan_with_or_without_findings_exits_zero(tmp_path, code, output, status):
    source = tmp_path / "S.java"
    source.write_text("class S {}")
    destination = tmp_path / "result.json"
    with patch("pipeline.security_poc.verify", return_value=(code, output)), \
         patch("pipeline.security_poc.run_semgrep", return_value={"status": "CLEAN"}):
        assert cli.command_security_inspect(SimpleNamespace(
            source=str(source), json=str(destination)), ui()) == 0
    assert json.loads(destination.read_text())["status"] == status


@pytest.mark.parametrize("payload,code,status", [
    ('', 0, "INVALID_OUTPUT"), ('{}', 0, "INVALID_OUTPUT"),
    ('{"results":[]}', 1, "ERROR"),
    ('{"results":[]}', 2, "ERROR"),
    ('{"results":[],"errors":[{"message":"parse failed"}]}', 0, "ERROR"),
    ('[]', 0, "INVALID_OUTPUT"), ('{"results":[null]}', 0, "INVALID_OUTPUT"),
    ('{"results":null}', 0, "INVALID_OUTPUT"),
])
def test_scanner_failure_cannot_become_clean(tmp_path, payload, code, status):
    with patch("pipeline.security_assessment.subprocess.run", return_value=SimpleNamespace(
            stdout=payload, stderr="", returncode=code)):
        assert run_semgrep(tmp_path / "S.java")["status"] == status


def test_help_explains_preflight_and_rejected_strategy():
    parser = cli.build_parser()
    commands = next(a.choices for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    assert "NO_PROOF" in commands["verify-bisimulation"].format_help()
    assert "always rejected" in commands["optimize-algorithm"].format_help()
