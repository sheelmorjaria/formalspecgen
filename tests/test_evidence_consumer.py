"""Read-only evidence boundaries. Fixtures are synthetic ledgers, not proofs."""
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline import cli
from pipeline.evidence_consumer import EvidenceWorkflowRequest, inspect_evidence
from pipeline.lifecycle import EvidenceClaim, PipelineState, RunLedger
from pipeline.workflow_contracts import WorkflowContext
import mcp_server


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ledger = RunLedger(tmp_path / "run")
    ledger.record(PipelineState.PROOF, "VERIFIED", claim=EvidenceClaim.DEDUCTIVE_PROOF,
                  evidence={"output": "synthetic fixture only"})
    return ledger.commit({"final_status": "VERIFIED", "claim": "DEDUCTIVE_PROOF",
                          "claim_limits": {"fixture": True}})


def inspect(path, **budget):
    return inspect_evidence(EvidenceWorkflowRequest(str(path)), WorkflowContext.for_cli(
        ("workspace_read",), workspace_root=path.parent, resource_budget=budget))


@pytest.mark.parametrize("operation", ["validate", "explain"])
def test_cli_mcp_semantic_equivalence_and_readonly(bundle, capsys, operation):
    before = {p: p.read_bytes() for p in bundle.parent.rglob("*") if p.is_file()}
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    with patch("subprocess.run", side_effect=AssertionError("no execution")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no provider")):
        remote = mcp_server.inspect_evidence(str(bundle), operation, digest)
        args = cli.build_parser().parse_args(["evidence", operation, str(bundle),
                                             "--expected-sha256", digest, "--json"])
        assert cli.dispatch(args, cli.TerminalUI(), None, {}) == 0
    local = json.loads(capsys.readouterr().out)["result"]
    assert {k: v for k, v in remote.items() if k != "mcp_admission"} == local
    assert local["request_satisfied"] and local["claim"] == "NO_PROOF"
    assert local["integrity"]["status"] == "VALID"
    assert local["manifest_binding"]["status"] == "MATCH"
    for key in ("authenticity", "applicability", "assurance"):
        assert local[key]["status"] == "NOT_ASSESSED"
    if operation == "explain":
        assert local["explanation"]["recorded_claim"] == "DEDUCTIVE_PROOF"
    assert before == {p: p.read_bytes() for p in bundle.parent.rglob("*") if p.is_file()}


def test_tampered_missing_and_digest_mismatch_are_distinct(bundle):
    mismatch = mcp_server.inspect_evidence(str(bundle), expected_sha256="0" * 64)
    assert mismatch["code"] == "MANIFEST_DIGEST_MISMATCH"
    artifact = bundle.parent / "001-proof.json"
    artifact.write_text("tampered")
    tampered = inspect(bundle)
    assert tampered["status"] == "EVIDENCE_INVALID"
    assert tampered["integrity"]["status"] == "INVALID"
    artifact.unlink()
    assert inspect(bundle)["status"] == "EVIDENCE_INCOMPLETE"


def test_explain_multistage_preserves_baseline_and_failed_candidate(tmp_path, monkeypatch, capsys):
    from pipeline.multistage_evidence import publish_multistage_evidence
    monkeypatch.chdir(tmp_path)
    baseline = {"stage": "baseline", "language": "java", "status": "VERIFIED", "claim": "DEDUCTIVE_PROOF",
                "execution_stages": [
                    {"status": "COMPLETED", "tool": "openjml-check", "exit_code": 0, "policy_compliance": "ENFORCED"},
                    {"status": "COMPLETED", "tool": "openjml-esc", "exit_code": 0, "policy_compliance": "ENFORCED"}]}
    candidate = {"stage": "candidate", "language": "java", "status": "FAIL", "claim": "NO_PROOF",
                 "execution_stages": [{"status": "TIMEOUT", "tool": "openjml-esc", "exit_code": 0,
                    "policy_compliance": "NOT_ENFORCED", "timed_out": True, "output_truncated": True}]}
    receipt = publish_multistage_evidence(tmp_path / "run", workflow="verify-refactor", status="FAIL",
        claim="NO_PROOF", request={"fixture": True}, admission=None, inputs={},
        stages=[baseline, candidate], semantic_bindings={}, claim_limits={"synthetic_fixture": True})
    path = receipt["manifest_path"]
    before = {p: p.read_bytes() for p in (tmp_path / "run").rglob("*") if p.is_file()}
    with patch("subprocess.run", side_effect=AssertionError("no execution")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no provider")):
        remote = mcp_server.inspect_evidence(path, "explain")
        args = cli.build_parser().parse_args(["evidence", "explain", path, "--json"])
        assert cli.dispatch(args, cli.TerminalUI(), None, {}) == 0
    local = json.loads(capsys.readouterr().out)["result"]
    assert local == {k: v for k, v in remote.items() if k != "mcp_admission"}
    explanation = local["explanation"]
    assert explanation["recorded_status"] == "FAIL" and explanation["recorded_claim"] == "NO_PROOF"
    execution = explanation["recorded_execution"]
    assert execution["status"] == "RECORDED" and execution["issues"] == []
    assert [s["recorded"]["status"] for s in execution["stages"]] == ["VERIFIED", "FAIL"]
    assert len(execution["stages"][0]["observations"]) == 2
    assert execution["stages"][1]["observations"][0]["recorded"] == candidate["execution_stages"][0]
    assert execution["stages"][1]["observations"][0]["pointer"] == "/execution_stages/1/execution_stages/0"
    assert local["claim"] == "NO_PROOF" and local["request_satisfied"]  # explanation, not verification
    assert local["authenticity"]["status"] == local["assurance"]["status"] == "NOT_ASSESSED"
    assert before == {p: p.read_bytes() for p in (tmp_path / "run").rglob("*") if p.is_file()}


@pytest.mark.parametrize("terminal,status,stages,issues", [
    ({}, "NOT_RECORDED", 0, 0),
    ({"execution_stages": []}, "UNSUPPORTED_LAYOUT", 0, 0),
    ({"claim_policy_version": "verification-policy-v1", "execution_stages": []}, "RECORDED", 0, 0),
    ({"claim_policy_version": "verification-policy-v1", "execution_stages": [{"exit_code": 0}]}, "RECORDED", 1, 0),
    ({"claim_policy_version": "verification-policy-v1", "execution_stages": {}}, "PARTIAL", 0, 1),
    ({"schema": "formalspecgen-multistage-evidence-v1", "execution_stages": [None, {"stage": "baseline"},
        {"stage": "candidate", "execution_stages": [None, {"exit_code": 0}]}]}, "PARTIAL", 2, 3),
])
def test_explain_stage_shapes_are_explicit(tmp_path, monkeypatch, terminal, status, stages, issues):
    monkeypatch.chdir(tmp_path)
    ledger = RunLedger(tmp_path / "run")
    ledger.record(PipelineState.PROOF, "FAIL", claim=EvidenceClaim.NO_PROOF)
    manifest = ledger.commit({"claim": "NO_PROOF", "final_status": "FAIL", **terminal})
    result = mcp_server.inspect_evidence(str(manifest), "explain")
    execution = result["explanation"]["recorded_execution"]
    assert execution["status"] == status and len(execution["stages"]) == stages
    assert len(execution["issues"]) == issues
    assert result["integrity"]["valid"] and result["claim"] == "NO_PROOF"
    if status == "RECORDED" and stages:
        assert execution["stages"][0]["recorded"] == {"exit_code": 0}  # no inferred successful status


@pytest.mark.parametrize("name", ["../outside.json", "/etc/passwd", "manifest.json", "", ".", "a/b.json", "a\\b.json"])
def test_inventory_paths_rejected_before_artifact_capture(bundle, name):
    manifest = json.loads(bundle.read_bytes())
    manifest["artifacts"][0]["path"] = name
    bundle.write_text(json.dumps(manifest))
    result = inspect(bundle)
    assert result["code"] == "INVALID_INVENTORY"
    assert not result["request_satisfied"]


@pytest.mark.parametrize("target", ["manifest.json", "run.json"])
def test_symlink_inputs_rejected(bundle, tmp_path, target):
    path = bundle.parent / target
    outside = tmp_path / "outside"
    path.rename(outside)
    path.symlink_to(outside)
    assert not inspect(bundle)["request_satisfied"]


def test_symlink_directory_and_out_of_scope_paths_denied(bundle, tmp_path):
    (tmp_path / "link").symlink_to(bundle.parent, target_is_directory=True)
    result = mcp_server.inspect_evidence("link/manifest.json")
    assert not result["request_satisfied"]
    assert mcp_server.inspect_evidence("../elsewhere/manifest.json")["code"] == "PATH_OUTSIDE_WORKSPACE"
    denied = inspect_evidence(EvidenceWorkflowRequest(str(bundle)), WorkflowContext.for_cli(
        (), workspace_root=tmp_path))
    assert not denied["request_satisfied"]


@pytest.mark.parametrize("budget", [{"max_input_bytes": 0}, {"max_input_bytes": 8},
                                   {"max_input_files": 2}, {"max_path_depth": 0}])
def test_limits_fail_closed(bundle, budget):
    assert inspect(bundle, **budget)["code"] == "INPUT_LIMIT_EXCEEDED"


def test_exact_aggregate_limit_and_overflow_probe(bundle):
    total = sum(p.stat().st_size for p in bundle.parent.iterdir() if p.is_file())
    assert inspect(bundle, max_input_bytes=total)["request_satisfied"]
    assert inspect(bundle, max_input_bytes=total - 1)["code"] == "INPUT_LIMIT_EXCEEDED"
    original = os.fdopen
    reads = []
    class Reader:
        def __init__(self, fd, mode): self.handle = original(fd, mode)
        def __enter__(self): return self
        def __exit__(self, *args): self.handle.close()
        def fileno(self): return self.handle.fileno()
        def read(self, count):
            reads.append(count)
            return self.handle.read(count)
    with patch("pipeline.evidence_consumer.os.fdopen", side_effect=Reader):
        assert inspect(bundle, max_input_bytes=8)["code"] == "INPUT_LIMIT_EXCEEDED"
    assert reads == [9]


def test_capture_once_survives_late_workspace_mutation(bundle):
    original = RunLedger.validate_captured
    def mutate(manifest, read):
        (bundle.parent / "run.json").write_text("changed later")
        bundle.write_text("changed later")
        return original(manifest, read)
    with patch.object(RunLedger, "validate_captured", side_effect=mutate):
        result = inspect(bundle)
    assert result["request_satisfied"]
    assert result["manifest_sha256"] != hashlib.sha256(bundle.read_bytes()).hexdigest()


def test_nonregular_input_does_not_block(bundle):
    artifact = bundle.parent / "run.json"
    artifact.unlink()
    os.mkfifo(artifact)
    assert inspect(bundle)["code"] == "INVALID_INPUT"


@pytest.mark.parametrize("content", ["not json", "[]", "{}", '{"schema":"other"}'])
def test_malformed_manifest(bundle, content):
    bundle.write_text(content)
    assert not inspect(bundle)["request_satisfied"]


def test_request_and_readonly_profile(bundle):
    from pipeline.mcp_policy import authorize_mcp_invocation
    assert mcp_server.inspect_evidence(str(bundle), operation="sign")["code"] == "INVALID_REQUEST"
    assert mcp_server.inspect_evidence(str(bundle), expected_sha256="bad")["code"] == "INVALID_REQUEST"
    admission = authorize_mcp_invocation("inspect_evidence", mode="validate", language="evidence",
        backend="builtin-ledger", effects=("workspace_read", "external_execution"))
    assert not admission.admitted
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["evidence", "validate", str(bundle), "--json", "file.json"])


@pytest.mark.parametrize("operation,output", [("validate", ["--json", "-"]),
                                              ("explain", ["--json"]),
                                              ("validate", [])])
def test_request_and_argument_delivery(bundle, capsys, operation, output):
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    with patch("pipeline.evidence_consumer.inspect_evidence", wraps=inspect_evidence) as service:
        args = cli.build_parser().parse_args([
            "evidence", operation, str(bundle), "--expected-sha256", digest, *output])
        assert cli.dispatch(args, cli.TerminalUI(), None, {}) == 0
    request, context = service.call_args.args
    assert request == EvidenceWorkflowRequest(bundle.name, operation, digest)
    assert context.workspace_root == bundle.parent
    assert request.required_effects() == ("workspace_read",)
    assert context.required_effects == ("workspace_read",)
    if output:
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["result"]["request"] == {
            **request.as_dict(), "manifest": str(bundle)}
    assert not (Path.cwd() / "-").exists()


def test_evidence_completion_requires_runner_results():
    from pipeline.parity_inventory import load_parity_plan, reconcile_parity_plan
    root = Path(__file__).resolve().parents[1]
    plan = load_parity_plan(root / "mcpdocs/mcp_parity_plan.json")
    entry = next(item for item in plan["commands"] if item["cli_command"] == "evidence")
    contract = entry["completion_contract"]
    assert set(contract["required_variants"]) == {
        variant for case in contract["acceptance_cases"] for variant in case["variants"]}
    for case in contract["acceptance_cases"]:
        assert case["test"].split("::", 1)[1] in globals()
        # A declaration saying 'passed' must never establish completion.
        case["result"] = "passed"
    manifest = reconcile_parity_plan(plan, handlers={
        name: value for name, value in vars(mcp_server).items() if callable(value)})
    record = next(item for item in manifest["command_mappings"] if item["cli_command"] == "evidence")
    assert not record["workflow_completion"]["complete"]
    assert "runner_acceptance_evidence_missing" in record["workflow_completion"]["blockers"]


@pytest.fixture
def comparison_bundle(bundle):
    ledger = RunLedger(Path.cwd() / "comparison")
    ledger.record(PipelineState.PROOF, "REJECTED", claim=EvidenceClaim.NO_PROOF,
                  evidence={"fixture": "candidate failure"})
    ledger.record(PipelineState.REVIEW_AND_MEASURE, "PENDING", claim=EvidenceClaim.NO_PROOF)
    return ledger.commit({"final_status": "REJECTED", "claim": "NO_PROOF",
                          "claim_limits": {"fixture": True}, "optional": None})


def diff_request(baseline, comparison):
    return EvidenceWorkflowRequest(str(baseline), "diff",
        hashlib.sha256(baseline.read_bytes()).hexdigest(), str(comparison),
        hashlib.sha256(comparison.read_bytes()).hexdigest())


def test_diff_cli_mcp_equivalence_and_recorded_changes(bundle, comparison_bundle, capsys):
    request = diff_request(bundle, comparison_bundle)
    before = {path: path.read_bytes() for path in Path.cwd().rglob("*") if path.is_file()}
    remote = mcp_server.inspect_evidence(**{k: v for k, v in request.as_dict().items() if k != "schema"})
    args = cli.build_parser().parse_args([
        "evidence", "diff", str(bundle), "--comparison-manifest", str(comparison_bundle),
        "--expected-sha256", request.expected_sha256,
        "--comparison-expected-sha256", request.comparison_expected_sha256, "--json", "-"])
    assert cli.dispatch(args, cli.TerminalUI(), None, {}) == 0
    local = json.loads(capsys.readouterr().out)["result"]
    assert local == {key: value for key, value in remote.items() if key != "mcp_admission"}
    assert local["status"] == "EVIDENCE_COMPARED" and local["request_satisfied"]
    assert local["claim"] == "NO_PROOF"
    assert local["baseline"]["recorded_terminal"]["claim"] == "DEDUCTIVE_PROOF"
    changes = {entry["field"]: entry for entry in local["differences"]["recorded_terminal_changes"]}
    assert changes["claim"]["comparison"] == "NO_PROOF"
    assert changes["optional"]["baseline_present"] is False
    assert changes["optional"]["comparison_present"] is True
    assert [entry["path"] for entry in local["differences"]["artifacts_added"]] == ["002-review_and_measure.json"]
    assert local["differences"]["artifacts_removed"] == []
    assert {entry["path"] for entry in local["differences"]["artifacts_modified"]} == {"run.json", "001-proof.json"}
    for dimension in ("authenticity", "applicability", "assurance"):
        assert local[dimension]["status"] == "NOT_ASSESSED"
    assert before == {path: path.read_bytes() for path in Path.cwd().rglob("*") if path.is_file()}


def test_diff_identical_and_reverse(bundle, comparison_bundle):
    same = mcp_server.inspect_evidence(str(bundle), "diff", comparison_manifest=str(bundle))
    assert same["differences"]["manifest_bytes_equal"]
    assert same["differences"]["recorded_terminal_changes"] == []
    assert same["differences"]["artifacts_unchanged"] == ["001-proof.json", "run.json"]
    reverse = mcp_server.inspect_evidence(str(comparison_bundle), "diff", comparison_manifest=str(bundle))
    assert [entry["path"] for entry in reverse["differences"]["artifacts_removed"]] == ["002-review_and_measure.json"]


def test_diff_retains_json_type_changes(bundle, comparison_bundle):
    for path, flag in ((bundle, True), (comparison_bundle, 1)):
        value = json.loads(path.read_bytes())
        value["terminal"]["flag"] = flag
        path.write_text(json.dumps(value))
    result = mcp_server.inspect_evidence(str(bundle), "diff", comparison_manifest=str(comparison_bundle))
    change = next(item for item in result["differences"]["recorded_terminal_changes"] if item["field"] == "flag")
    assert change["baseline"] is True
    assert type(change["comparison"]) is int


def test_diff_nonfinite_manifest_rejected(bundle, comparison_bundle):
    value = json.loads(comparison_bundle.read_bytes())
    value["terminal"]["invalid_number"] = float("nan")
    comparison_bundle.write_text(json.dumps(value))
    result = mcp_server.inspect_evidence(str(bundle), "diff", comparison_manifest=str(comparison_bundle))
    assert result["baseline"]["request_satisfied"]
    assert result["code"] == "COMPARISON_EVIDENCE_REJECTED"
    assert result["comparison"]["code"] == "INVALID_INPUT"
    json.dumps(result, allow_nan=False)


@pytest.mark.parametrize("failed_side", ["baseline", "comparison"])
def test_diff_relative_negative_requests_match_cli(bundle, comparison_bundle, capsys, failed_side):
    (bundle if failed_side == "baseline" else comparison_bundle).write_text("bad")
    left = str(bundle.relative_to(Path.cwd()))
    right = str(comparison_bundle.relative_to(Path.cwd()))
    remote = mcp_server.inspect_evidence(left, "diff", comparison_manifest=right)
    args = cli.build_parser().parse_args(["evidence", "diff", left, "--comparison-manifest", right, "--json"])
    assert cli.dispatch(args, cli.TerminalUI(), None, {}) == 1
    assert json.loads(capsys.readouterr().out)["result"] == {
        key: value for key, value in remote.items() if key != "mcp_admission"}


@pytest.mark.parametrize("kind", ["bytes", "files"])
def test_diff_aggregate_limits_preserve_baseline(bundle, comparison_bundle, kind):
    request = diff_request(bundle, comparison_bundle)
    paths = [p for root in (bundle.parent, comparison_bundle.parent) for p in root.iterdir() if p.is_file()]
    exact = {"max_input_bytes": sum(path.stat().st_size for path in paths), "max_input_files": len(paths)}
    context = WorkflowContext.for_cli(("workspace_read",), workspace_root=Path.cwd(), resource_budget=exact)
    assert inspect_evidence(request, context)["request_satisfied"]
    budget = dict(exact)
    budget["max_input_bytes" if kind == "bytes" else "max_input_files"] -= 1
    context = WorkflowContext.for_cli(("workspace_read",), workspace_root=Path.cwd(), resource_budget=budget)
    result = inspect_evidence(request, context)
    assert not result["request_satisfied"] and "differences" not in result
    assert result["baseline"]["request_satisfied"]
    assert result["baseline"]["recorded_terminal"]["claim"] == "DEDUCTIVE_PROOF"
    assert result["comparison"]["code"] == "INPUT_LIMIT_EXCEEDED"


@pytest.mark.parametrize("failure", ["tampered", "missing", "digest", "denied", "link"])
def test_diff_rejects_second_input_without_losing_baseline(bundle, comparison_bundle, failure):
    comparison = str(comparison_bundle)
    expected = None
    if failure == "tampered":
        (comparison_bundle.parent / "run.json").write_text("bad")
    elif failure == "missing":
        comparison_bundle.unlink()
    elif failure == "digest":
        expected = "0" * 64
    elif failure == "denied":
        comparison = "../outside.json"
    elif failure == "link":
        comparison = "link.json"
        Path(comparison).symlink_to(comparison_bundle)
    result = mcp_server.inspect_evidence(str(bundle), "diff", comparison_manifest=comparison,
                                        comparison_expected_sha256=expected)
    assert result["status"] == "EVIDENCE_COMPARISON_REJECTED"
    assert not result["request_satisfied"] and result["claim"] == "NO_PROOF"
    assert result["baseline"]["request_satisfied"]
    assert not result["comparison"]["request_satisfied"]
    assert "differences" not in result


def test_diff_invalid_baseline_stops_before_second_capture(bundle, comparison_bundle):
    from pipeline.evidence_consumer import _inspect_one
    bundle.write_text("bad")
    with patch("pipeline.evidence_consumer._inspect_one", wraps=_inspect_one) as capture:
        result = mcp_server.inspect_evidence(str(bundle), "diff", comparison_manifest=str(comparison_bundle))
    assert capture.call_count == 1
    assert result["code"] == "BASELINE_EVIDENCE_REJECTED"
    assert result["comparison"]["status"] == "NOT_CHECKED"


def test_diff_uses_captured_bytes_after_late_mutation(bundle, comparison_bundle):
    from pipeline.evidence_consumer import _inspect_one
    request = diff_request(bundle, comparison_bundle)
    def mutate(request, context, budget):
        result = _inspect_one(request, context, budget)
        Path(request.manifest).write_text("changed after capture")
        return result
    with patch("pipeline.evidence_consumer._inspect_one", side_effect=mutate):
        result = inspect_evidence(request, WorkflowContext.for_cli(("workspace_read",), workspace_root=Path.cwd()))
    assert result["request_satisfied"]
    assert result["baseline"]["manifest_sha256"] == request.expected_sha256
    assert result["comparison"]["manifest_sha256"] == request.comparison_expected_sha256


@pytest.mark.parametrize("kwargs", [
    {"operation": "diff"}, {"comparison_manifest": "second.json"},
    {"comparison_expected_sha256": "0" * 64},
    {"operation": "diff", "comparison_manifest": "second.json", "comparison_expected_sha256": "bad"}])
def test_diff_rejects_inconsistent_options(bundle, kwargs):
    assert mcp_server.inspect_evidence(str(bundle), **kwargs)["code"] == "INVALID_REQUEST"


@pytest.fixture
def source_receipt(tmp_path, monkeypatch):
    """Use the real receipt publisher with synthetic observations, no backend."""
    from types import SimpleNamespace
    from pipeline.workflow_contracts import VerificationWorkflowRequest
    from pipeline.mcp_policy import authorize_mcp_invocation
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "Counter.java"
    source.write_bytes(b"class Counter {}\r\n")
    request = VerificationWorkflowRequest(str(source))
    admission = authorize_mcp_invocation("verify_code", mode="esc", language="java", backend="openjml",
                                        effects=("workspace_read", "external_execution", "evidence_publication"))
    context = WorkflowContext.for_mcp(admission, ("workspace_read", "external_execution", "evidence_publication"))
    observation = SimpleNamespace(as_dict=lambda: {
        "snapshot_files": [{"path": source.name, "sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "size": source.stat().st_size}],
        "command": [], "policy_compliance": "FIXTURE_ONLY", "fixture": True})
    detailed = SimpleNamespace(observations=(observation,), observation=observation, output="synthetic fixture", exit_code=1)
    receipt = mcp_server._publish_verification_evidence(source, "esc", detailed,
        {"status": "FAIL", "claim": "NO_PROOF", "request_satisfied": False}, admission, context, request)
    return Path(receipt["manifest_path"]), source


@pytest.mark.parametrize("operation,changed", [("validate", False), ("explain", False), ("validate", True)])
def test_source_binding_cli_mcp_and_claim_scope(source_receipt, capsys, operation, changed):
    manifest, source = source_receipt
    if changed:
        source.write_text("class Changed {}")
    with patch("subprocess.run", side_effect=AssertionError("no execution")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no provider")):
        remote = mcp_server.inspect_evidence(str(manifest), operation, source=str(source))
        args = cli.build_parser().parse_args(["evidence", operation, str(manifest), "--source", str(source), "--json"])
        assert cli.dispatch(args, cli.TerminalUI(), None, {}) == int(changed)
    local = json.loads(capsys.readouterr().out)["result"]
    assert local == {key: value for key, value in remote.items() if key != "mcp_admission"}
    assert local["request_satisfied"] is not changed
    assert local["claim"] == "NO_PROOF"
    assert local["recorded_terminal"]["final_status"] == "FAIL"
    assert local["integrity"]["valid"]
    assert local["applicability"]["status"] == ("SOURCE_CHANGED" if changed else "SOURCE_MATCH_ONLY")
    assert local["applicability"]["full_applicability_established"] is False
    assert local["source_binding"]["captured"]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert local["authenticity"]["status"] == local["assurance"]["status"] == "NOT_ASSESSED"


@pytest.mark.parametrize("failure", ["missing", "link", "directory-link", "fifo", "outside", "bytes", "files"])
def test_source_capture_boundaries_preserve_integrity(source_receipt, failure):
    manifest, source = source_receipt
    budget = {}
    if failure == "missing":
        source.unlink()
    elif failure == "link":
        actual = source.with_suffix(".actual")
        source.rename(actual)
        source.symlink_to(actual)
    elif failure == "directory-link":
        Path("linked").symlink_to(source.parent, target_is_directory=True)
        source = Path("linked") / source.name
    elif failure == "fifo":
        source.unlink()
        os.mkfifo(source)
    elif failure == "outside":
        source = Path("../outside.java")
    elif failure == "bytes":
        budget = {"max_input_bytes": sum(p.stat().st_size for p in manifest.parent.iterdir() if p.is_file()) + source.stat().st_size - 1}
    elif failure == "files":
        budget = {"max_input_files": len([p for p in manifest.parent.iterdir() if p.is_file()])}
    result = inspect_evidence(EvidenceWorkflowRequest(str(manifest), source=str(source)),
        WorkflowContext.for_cli(("workspace_read",), workspace_root=Path.cwd(), resource_budget=budget))
    assert result["status"] == "EVIDENCE_SOURCE_CHECK_REJECTED"
    assert not result["request_satisfied"] and result["integrity"]["valid"]
    assert result["recorded_terminal"]["final_status"] == "FAIL"
    assert result["applicability"]["status"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("kind", ["unrecognized", "digest", "proof-record", "snapshot", "malformed-path"])
def test_source_binding_rejects_unsupported_or_conflicting_records(source_receipt, kind):
    from pipeline.evidence_consumer import _capture
    manifest, source = source_receipt
    value = json.loads(manifest.read_bytes())
    if kind == "unrecognized":
        value["terminal"]["workflow_request"]["workflow"] = "verify-refactor"
    elif kind == "digest":
        value["terminal"]["source_sha256"] = "0" * 64
    else:
        proof_path = manifest.parent / "001-proof.json"
        proof = json.loads(proof_path.read_bytes())
        if kind == "proof-record":
            proof["details"] = []
        else:
            stages = value["terminal"]["execution_stages"]
            stages[0]["snapshot_files"][0]["path" if kind == "malformed-path" else "sha256"] = [] if kind == "malformed-path" else "0" * 64
            proof["evidence"]["execution_stages"] = stages
        encoded = json.dumps(proof).encode()
        proof_path.write_bytes(encoded)
        value["artifacts"][-1].update(sha256=hashlib.sha256(encoded).hexdigest(), size=len(encoded))
    manifest.write_text(json.dumps(value))
    with patch("pipeline.evidence_consumer._capture", wraps=_capture) as capture:
        result = mcp_server.inspect_evidence(str(manifest), source=str(source))
    assert result["integrity"]["valid"] and not result["request_satisfied"]
    assert result["code"] in {"UNSUPPORTED_SOURCE_BINDING", "INCONSISTENT_SOURCE_BINDING"}
    assert source.name not in [call.args[0] for call in capture.call_args_list]


def test_source_capture_exact_budget_and_late_mutation(source_receipt):
    from pipeline.evidence_consumer import _capture
    manifest, source = source_receipt
    original = source.read_bytes()
    files = [p for p in manifest.parent.iterdir() if p.is_file()] + [source]
    budget = {"max_input_bytes": sum(p.stat().st_size for p in files), "max_input_files": len(files)}
    def mutate(name, directory_fd, context, budget):
        value = _capture(name, directory_fd, context, budget)
        if name == source.name:
            source.write_text("changed after capture")
        return value
    with patch("pipeline.evidence_consumer._capture", side_effect=mutate):
        result = inspect_evidence(EvidenceWorkflowRequest(str(manifest), source=str(source)),
            WorkflowContext.for_cli(("workspace_read",), workspace_root=Path.cwd(), resource_budget=budget))
    assert result["request_satisfied"]
    assert result["source_binding"]["captured"]["sha256"] == hashlib.sha256(original).hexdigest()


def test_source_options_and_invalid_evidence_stop_before_source(bundle):
    assert mcp_server.inspect_evidence(str(bundle), source="")["code"] == "INVALID_REQUEST"
    assert mcp_server.inspect_evidence(str(bundle), "diff", comparison_manifest=str(bundle), source="source.java")["code"] == "INVALID_REQUEST"
    bundle.write_text("invalid")
    result = mcp_server.inspect_evidence(str(bundle), source="source.java")
    assert result["status"] == "EVIDENCE_INVALID" and result["code"] == "INVALID_INPUT"
    assert "source_binding" not in result


@pytest.mark.skipif(not any(os.environ.get(name) == "1" for name in (
    "FORMALSPECGEN_REQUIRE_EVIDENCE_TRANSPORT", "FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE")),
                    reason="explicit evidence MCP stdio acceptance")
def test_real_mcp_evidence_discovery_and_calls():
    from scripts.mcp_acceptance_adapters import collect_transport_observation
    observation = collect_transport_observation("evidence")
    assert observation["transport"] == "mcp-stdio-subprocess"
    assert len(observation["semantic_results"]) == 42
    assert len(observation["cli_comparisons"]) == 38
    assert len(observation["validated_inputs"]) == 12
    assert len(observation["validated_sources"]) == 3
    assert observation["workspace_unchanged"] is True
    from scripts.mcp_acceptance_adapters import _sha256
    assert observation["result_sha256"] == _sha256(observation["semantic_results"])
    from pipeline.parity_inventory import load_parity_plan
    plan = load_parity_plan(Path(__file__).resolve().parents[1] / "mcpdocs/mcp_parity_plan.json")
    entry = next(item for item in plan["commands"] if item["cli_command"] == "evidence")
    transport = next(case for case in entry["completion_contract"]["acceptance_cases"]
                     if case["kind"] == "mcp_transport")
    assert set(transport["variants"]) == set(observation["variants"])
    assert set(observation["variants"]) == {
        "validate", "explain", "digest-match", "digest-mismatch", "tampered",
        "missing-artifact", "missing-manifest", "malformed", "denied-path",
        "symlink-manifest", "symlink-artifact", "byte-limit", "file-limit",
        "inventory-path", "invalid-operation", "invalid-digest",
        "diff-changed", "diff-identical", "diff-reverse", "diff-digest-mismatch",
        "diff-tampered", "diff-missing", "diff-denied", "diff-baseline-invalid",
        "diff-aggregate-bytes", "diff-aggregate-files", "diff-invalid-options",
        "source-match", "source-explain", "source-changed", "source-unsupported", "source-conflict",
        "source-missing", "source-denied", "source-link", "source-byte-limit", "source-file-limit",
        "source-invalid-options", "source-invalid-receipt",
        "explain-multistage", "explain-partial-stages", "explain-unknown-stages"}
