import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pipeline import ci
from pipeline.schemas import VC


def test_changed_java_filters_diff_and_existing_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in ("A.java", "B.jml", "note.txt"):
        Path(name).write_text("x", encoding="utf-8")
    completed = SimpleNamespace(returncode=0, stdout="A.java\nB.jml\nnote.txt\nGone.java\n", stderr="")
    with patch.object(ci.subprocess, "run", return_value=completed) as run:
        assert ci.changed_java("main") == [Path("A.java"), Path("B.jml")]
    assert run.call_args.args[0][-1] == "main...HEAD"

    with patch.object(ci.subprocess, "run", return_value=SimpleNamespace(
            returncode=1, stdout="", stderr="bad revision")):
        with pytest.raises(RuntimeError, match="bad revision"):
            ci.changed_java("missing")


def test_check_files_check_mode_emits_diagnostics_and_lints(tmp_path, capsys):
    source = tmp_path / "Bad.java"
    source.write_text("public class Bad {}", encoding="utf-8")
    vc = VC(str(source), 0, "error", detail="bad%line\nnext")
    warning = {"line": 2, "message": "missing frame", "advice": "add assignable"}
    with (patch.object(ci, "verify", return_value=(1, "failure")),
          patch.object(ci, "parse_check", return_value=[vc]),
          patch.object(ci, "lint_spec", return_value=[warning]),
          patch.object(ci, "explain_vc", return_value={"advice": "repair\rcontract"})):
        result = ci.check_files([source])
    assert result["status"] == "FAILED" and result["checked"] == 1
    output = capsys.readouterr().out
    assert "line=1" in output and "%25" in output and "%0A" in output and "%0D" in output
    assert "::warning" in output


def test_check_files_esc_rejects_dropped_obligations_and_accepts_clean(tmp_path):
    source = tmp_path / "Safe.java"
    source.write_text("public class Safe {}", encoding="utf-8")
    with (patch.object(ci, "verify", return_value=(0, "Not yet supported feature")),
          patch.object(ci, "has_dropped_vc", return_value=True),
          patch.object(ci, "parse_vcs", return_value=[]),
          patch.object(ci, "lint_spec", return_value=[])):
        result = ci.check_files([source], "esc")
    assert result["files"][0]["status"] == "VACUOUS_VERIFIED"
    assert result["status"] == "FAILED"

    with (patch.object(ci, "verify", return_value=(0, "proved")),
          patch.object(ci, "has_dropped_vc", return_value=False),
          patch.object(ci, "parse_vcs", return_value=[]),
          patch.object(ci, "lint_spec", return_value=[])):
        assert ci.check_files([source], "esc")["status"] == "VERIFIED"


def test_main_writes_report_and_sets_process_status(tmp_path):
    report = tmp_path / "report.json"
    with (patch("sys.argv", ["ci", "--report", str(report), "A.java"]),
          patch.object(ci, "check_files", return_value={
              "status": "VERIFIED", "checked": 1, "mode": "check", "files": []})):
        with pytest.raises(SystemExit) as exit_info:
            ci.main()
    assert exit_info.value.code == 0
    assert json.loads(report.read_text(encoding="utf-8"))["status"] == "VERIFIED"

    with (patch("sys.argv", ["ci", "--report", str(report)]),
          patch.object(ci, "changed_java", return_value=[]) as changed,
          patch.object(ci, "check_files", return_value={
              "status": "FAILED", "checked": 0, "mode": "check", "files": []})):
        with pytest.raises(SystemExit) as exit_info:
            ci.main()
    assert exit_info.value.code == 1 and changed.called
