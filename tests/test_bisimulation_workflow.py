# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import mcp_server
from pipeline import bisimulation, cli, bounded_inputs
from pipeline.bisimulation_workflow import BISIMULATION_BUDGET, BisimulationWorkflowRequest, run_bisimulation_workflow
from pipeline.workflow_contracts import WorkflowContext
from pipeline.mcp_policy import authorize_mcp_invocation


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "Legacy.java").write_text("class Legacy { public int go(int x) { return x; } }\r\n")
    (tmp_path / "Modern.java").write_text("class Idle { public int go(int x) { return x; } }\n")
    (tmp_path / "mapping.json").write_text('{"0": "Idle"}')
    return tmp_path


def request(export=None, candidate="Modern.java"):
    return BisimulationWorkflowRequest("Legacy.java", candidate, "mapping.json", export)


def normalized(result):
    return json.loads(json.dumps({k: v for k, v in result.items()
        if k not in {"workflow_result", "mcp_admission", "result_export"}}))


@pytest.mark.parametrize("directory", [False, True])
def test_cli_mcp_normalization_and_identity(inputs, directory, capsys):
    candidate = "Modern.java"
    if directory:
        root = inputs / "candidate"
        root.mkdir()
        (root / "Main.java").write_bytes((inputs / candidate).read_bytes())
        (root / "Helper.java").write_text("class Helper {}")
        candidate = "candidate"
    assert cli.dispatch(cli.build_parser().parse_args(["verify-bisimulation", "Legacy.java", candidate,
                        "mapping.json", "--json", "-"]), cli.TerminalUI(), None, {}) == 0
    local = json.loads(capsys.readouterr().out)["result"]
    with patch("subprocess.run", side_effect=AssertionError("no execution")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no provider")):
        remote = mcp_server.verify_bisimulation("Legacy.java", candidate, "mapping.json")
    assert normalized(local) == normalized(remote)
    assert remote["request_satisfied"] and remote["claim"] == "NO_PROOF"
    assert not remote["behavior_equivalence_proved"] and not remote["heap_topology_equivalence_proved"]
    assert remote["workflow_result"]["request"] == local["workflow_result"]["request"] == request(candidate=candidate).as_dict()
    for entry in remote["input_manifest"]:
        data = Path(entry["path"]).read_bytes()
        assert entry["size"] == len(data) and entry["sha256"] == hashlib.sha256(data).hexdigest()
    assert remote["input_manifest_sha256"] == hashlib.sha256(json.dumps(
        remote["input_manifest"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert remote["mcp_admission"]["granted_effects"] == ["workspace_read"]


@pytest.mark.parametrize("case,status", [("mapping", "BISIMULATION_MAPPING_INVALID"),
    ("duplicate", "BISIMULATION_INPUT_INVALID"), ("malformed", "BISIMULATION_INPUT_INVALID"),
    ("missing", "BISIMULATION_INPUT_INVALID"), ("unresolved", "BISIMULATION_STATE_UNRESOLVED"),
    ("surface", "BISIMULATION_SURFACE_MISMATCH"), ("encoding", "BISIMULATION_INPUT_INVALID")])
def test_negative_outcomes_export_without_claims(inputs, monkeypatch, case, status):
    if case in {"mapping", "duplicate", "malformed", "unresolved"}:
        (inputs / "mapping.json").write_text({"mapping": "{}", "duplicate": '{"0":"Idle","0":"Idle"}',
            "malformed": "not json", "unresolved": '{"0":"Missing"}'}[case])
    elif case == "missing":
        (inputs / "Modern.java").unlink()
    elif case == "surface":
        (inputs / "Modern.java").write_text("class Idle {}")
    else:
        (inputs / "Modern.java").write_bytes(b"\xff")
    custom = inputs / "custom-output"
    monkeypatch.setenv("FORMALSPECGEN_MCP_OUTPUT_ROOT", str(custom))
    result = mcp_server.verify_bisimulation("Legacy.java", "Modern.java", "mapping.json", "negative.json")
    assert result["status"] == status and not result["request_satisfied"]
    assert result["claim"] == "NO_PROOF" and not result["behavior_equivalence_proved"]
    exported = json.loads((custom / "negative.json").read_text())
    assert normalized(exported) == normalized(result)
    receipt = result["result_export"]["artifacts"]["negative.json"]
    assert receipt["path"] == str(custom / "negative.json")
    assert receipt["sha256"] == hashlib.sha256((custom / "negative.json").read_bytes()).hexdigest()


@pytest.mark.parametrize("target", ["Legacy.java", "Modern.java", "mapping.json", "candidate/result.json", "existing.json"])
def test_cli_publication_never_replaces_inputs(inputs, target, capsys):
    (inputs / "candidate").mkdir()
    (inputs / "candidate/Modern.java").write_bytes((inputs / "Modern.java").read_bytes())
    (inputs / "existing.json").write_text("keep")
    before = {str(p): p.read_bytes() for p in inputs.rglob("*") if p.is_file()}
    assert cli.dispatch(cli.build_parser().parse_args(["verify-bisimulation", "Legacy.java", "candidate",
                        "mapping.json", "--json", target]), cli.TerminalUI(), None, {}) == 1
    capsys.readouterr()
    assert before == {str(p): p.read_bytes() for p in inputs.rglob("*") if p.is_file()}


def test_cli_negative_export_and_publication_failure(inputs, capsys):
    (inputs / "mapping.json").write_text("{}")
    assert cli.dispatch(cli.build_parser().parse_args(["verify-bisimulation", "Legacy.java", "Modern.java",
                        "mapping.json", "--json", "negative.json"]), cli.TerminalUI(), None, {}) == 1
    capsys.readouterr()
    assert json.loads((inputs / "negative.json").read_text())["status"] == "BISIMULATION_MAPPING_INVALID"
    with patch("pipeline.bisimulation_workflow.publish_new_artifacts", side_effect=OSError("storage failure")):
        result = mcp_server.verify_bisimulation("Legacy.java", "Modern.java", "mapping.json", "out.json")
    assert result["status"] == "RESULT_EXPORT_FAILED" and not result["request_satisfied"]
    assert result["claim"] == "NO_PROOF" and result["input_manifest"]


@pytest.mark.parametrize("kind", ["bytes", "files", "entries", "depth", "denied", "symlink", "fifo", "empty"])
def test_limits_and_unsafe_inputs_stop_before_matching(inputs, kind):
    limits = dict(BISIMULATION_BUDGET)
    candidate = "Modern.java"
    if kind in {"bytes", "files", "depth"}:
        limits[{"bytes": "max_input_bytes", "files": "max_input_files", "depth": "max_path_depth"}[kind]] = 0
    if kind in {"entries", "empty"}:
        candidate = "candidate"
        (inputs / candidate).mkdir()
        if kind == "entries":
            (inputs / candidate / "irrelevant.txt").write_text("")
            limits["max_traversal_entries"] = 0
    if kind == "denied":
        candidate = "../outside.java"
    if kind == "symlink":
        (inputs / "Modern.java").unlink()
        (inputs / "Modern.java").symlink_to(inputs / "Legacy.java")
    if kind == "fifo":
        (inputs / "Modern.java").unlink()
        os.mkfifo(inputs / "Modern.java")
    req = request("failed.json", candidate)
    context = WorkflowContext.for_cli(req.required_effects(), resource_budget=limits)
    with patch("pipeline.bisimulation.check_bisimulation_sources") as check:
        result = run_bisimulation_workflow(req, context, output_root=inputs / "output", export_key="failed.json")
        check.assert_not_called()
    assert not result["request_satisfied"] and result["result_export"]["status"] == "COMMITTED"


def test_aggregate_capture_is_bounded_and_exact_limit_works(inputs):
    total = sum(p.stat().st_size for p in inputs.iterdir())
    req = request()
    exact = WorkflowContext.for_cli(req.required_effects(), resource_budget={**BISIMULATION_BUDGET, "max_input_bytes": total})
    assert run_bisimulation_workflow(req, exact)["request_satisfied"]
    observed = []
    original = bounded_inputs.os.fdopen
    class Reader:
        def __init__(self, *args): self.handle = original(*args)
        def __enter__(self): return self
        def __exit__(self, *args): self.handle.close()
        def fileno(self): return self.handle.fileno()
        def read(self, n):
            assert n >= 0
            value = self.handle.read(n)
            observed.append(len(value))
            return value
    context = WorkflowContext.for_cli(req.required_effects(), resource_budget={**BISIMULATION_BUDGET, "max_input_bytes": total - 2})
    with patch("pipeline.bounded_inputs.os.fdopen", Reader), patch("pipeline.bisimulation.check_bisimulation_sources") as check:
        result = run_bisimulation_workflow(req, context)
    assert result["code"] == "INPUT_LIMIT_EXCEEDED" and sum(observed) == total - 1
    check.assert_not_called()


def test_captured_bytes_not_reopened_and_filenames_are_bound(inputs):
    original = (inputs / "Legacy.java").read_bytes()
    check = bisimulation.check_bisimulation_sources
    def changed(baseline, candidate, mapping):
        (inputs / "Legacy.java").write_text("changed after capture")
        assert baseline == original.decode().replace("\r\n", "\n").replace("\r", "\n")
        return check(baseline, candidate, mapping)
    with patch("pipeline.bisimulation.check_bisimulation_sources", side_effect=changed):
        result = mcp_server.verify_bisimulation("Legacy.java", "Modern.java", "mapping.json")
    assert result["baseline_sha256"] == hashlib.sha256(original).hexdigest()
    assert result["request_satisfied"]
    (inputs / "Legacy.java").write_bytes(original)
    candidate = inputs / "candidate"
    candidate.mkdir()
    (candidate / "One.java").write_bytes((inputs / "Modern.java").read_bytes())
    first = mcp_server.verify_bisimulation("Legacy.java", "candidate", "mapping.json")
    (candidate / "One.java").rename(candidate / "Two.java")
    second = mcp_server.verify_bisimulation("Legacy.java", "candidate", "mapping.json")
    assert first["refactored_sha256"] == second["refactored_sha256"]
    assert first["input_manifest_sha256"] != second["input_manifest_sha256"]


def test_admission_denial_no_read_or_export(inputs):
    denied = authorize_mcp_invocation("verify_bisimulation", mode="preflight", language="text",
        backend="builtin-mapping-preflight", effects=("external_execution",))
    with patch("mcp_server.authorize_mcp_invocation", return_value=denied), \
         patch("pipeline.bisimulation_workflow.run_bisimulation_workflow") as service:
        assert not mcp_server.verify_bisimulation("Legacy.java", "Modern.java", "mapping.json", "out.json")["request_satisfied"]
        service.assert_not_called()
    for values in (("", "x", "m"), ("b", None, "m"), ("b", "x", "m", "")):
        with pytest.raises(ValueError):
            BisimulationWorkflowRequest(*values)


@pytest.mark.parametrize("effects", [(), ("workspace_read",)])
def test_missing_effect_stops_before_capture_and_publication(inputs, effects):
    req = request("denied.json")
    context = WorkflowContext.for_cli(effects, resource_budget=BISIMULATION_BUDGET)
    with patch("pipeline.bisimulation_workflow._capture_inputs") as capture, \
         patch("pipeline.bisimulation_workflow.publish_new_artifacts") as publish:
        result = run_bisimulation_workflow(req, context, output_root=inputs, export_key="denied.json")
    assert not result["request_satisfied"] and result["claim"] == "NO_PROOF"
    capture.assert_not_called()
    publish.assert_not_called()


def test_collaborators_share_aggregate_file_allowance(inputs):
    candidate = inputs / "candidate"
    candidate.mkdir()
    for name in ("One.java", "Two.java"):
        (candidate / name).write_text("class Idle {}")
    req = request(candidate="candidate")
    context = WorkflowContext.for_cli(req.required_effects(),
        resource_budget={**BISIMULATION_BUDGET, "max_input_files": 3})
    with patch("pipeline.bisimulation.check_bisimulation_sources") as check:
        result = run_bisimulation_workflow(req, context)
    assert result["code"] == "INPUT_LIMIT_EXCEEDED" and not result["request_satisfied"]
    check.assert_not_called()


@pytest.mark.parametrize("fragment", ["public int go(int x)", "public static void go()", "public T[] f(\nX x)",
    "public int unclosed(", "public static int f(public int g())", "// public int f()", "class S {}"])
def test_public_matcher_preserves_lexical_scope(fragment):
    text = fragment * 50
    assert bisimulation.public_surface(text) == sorted(bisimulation._PUBLIC_METHOD.findall(text))


def test_source_newline_normalization_preserves_raw_byte_identity(inputs):
    baseline = b"class Legacy { public int go(\r\nint x\r) { return x; } }"
    (inputs / "Legacy.java").write_bytes(baseline)
    (inputs / "Modern.java").write_bytes(b"class Idle { public int go(\nint x\n) { return x; } }")
    result = mcp_server.verify_bisimulation("Legacy.java", "Modern.java", "mapping.json")
    assert result["request_satisfied"]
    assert result["baseline_sha256"] == hashlib.sha256(baseline).hexdigest()


def test_real_bisimulation_transport():
    if os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") != "1":
        pytest.skip("requires real MCP transport")
    import anyio
    from scripts.mcp_acceptance_adapters import _bisimulation_observation
    observed = anyio.run(_bisimulation_observation)
    assert len(observed["semantic_results"]) == 16
    assert len(observed["cli_comparisons"]) == 14
    assert len(observed["artifact_validations"]) == 13
