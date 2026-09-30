"""Surface inspection fixtures are not proofs or authenticated requirements."""
import hashlib
import json
import os
from unittest.mock import patch

import pytest

import mcp_server
from pipeline import cli
from pipeline.contract_inspection import ContractInspectionRequest, inspect_contract
from pipeline.workflow_contracts import WorkflowContext


SOURCE = """public class Account {
    //@ requires true;
    //@ ensures \\result >= 0;
    public int balance() { return 1; }
}
"""


@pytest.fixture
def sources(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for directory, content in (("before", SOURCE), ("after", SOURCE.replace("return 1", "return 2"))):
        path = tmp_path / directory / "Account.java"
        path.parent.mkdir()
        path.write_text(content)
    return tmp_path


@pytest.mark.parametrize("operation", ["extract", "diff"])
@pytest.mark.parametrize("suffix", [".java", ".jml"])
def test_interfaces_and_scope(sources, capsys, operation, suffix):
    source = sources / "before/Account.java"
    source = source.rename(source.with_suffix(suffix))
    candidate = "after/Account.java" if operation == "diff" else None
    before = {p: p.read_bytes() for p in sources.rglob("*") if p.is_file()}
    args = ["contract", operation, str(source), "--json", "-"]
    if candidate:
        args += ["--candidate", candidate]
    with patch("subprocess.run", side_effect=AssertionError("no execution")), \
         patch("subprocess.Popen", side_effect=AssertionError("no execution")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no provider")):
        remote = mcp_server.inspect_contract(str(source), operation, candidate)
        assert cli.dispatch(cli.build_parser().parse_args(args), cli.TerminalUI(), None, {}) == 0
    local = json.loads(capsys.readouterr().out)["result"]
    assert local == {k: v for k, v in remote.items() if k != "mcp_admission"}
    assert remote["mcp_admission"]["granted_effects"] == ["workspace_read"]
    assert local["claim"] == "NO_PROOF" and local["review_status"] == "NOT_ASSESSED"
    assert not local["semantic_equivalence_proved"] and not local["behavior_equivalence_proved"]
    for item in local["inputs"].values():
        content = (sources / item["path"]).read_bytes()
        assert item["sha256"] == hashlib.sha256(content).hexdigest() and item["size"] == len(content)
    assert local["contract_statements_present"]["source"]
    if candidate:
        assert local["comparison"]["surface_equal"] and not local["comparison"]["differences"]
        assert local["inputs"]["source"]["sha256"] != local["inputs"]["candidate"]["sha256"]
    assert before == {p: p.read_bytes() for p in sources.rglob("*") if p.is_file()}


@pytest.mark.parametrize("change", ["clause", "assumption", "context", "api"])
def test_surface_mutations_are_reported_not_proved(sources, change):
    candidate = {"clause": SOURCE.replace(">= 0", ">= 1"),
                 "assumption": SOURCE.replace("return 1;", "\n//@ assume true;\nreturn 1;"),
                 "context": "import java.util.List;\n" + SOURCE,
                 "api": SOURCE.replace("balance()", "balance(int extra)")}[change]
    (sources / "after/Account.java").write_text(candidate)
    result = mcp_server.inspect_contract("before/Account.java", "diff", "after/Account.java")
    assert result["request_satisfied"] and result["status"] == "CONTRACT_COMPARED"
    assert not result["comparison"]["surface_equal"] and result["comparison"]["differences"]
    assert result["claim"] == "NO_PROOF" and not result["semantic_equivalence_proved"]


@pytest.mark.parametrize("arguments", [
    {"source": "a.rs"}, {"source": ""}, {"source": []},
    {"source": "x.java", "operation": "sign"}, {"source": "x.java", "operation": "diff"},
    {"source": "x.java", "candidate": "y.java"},
    {"source": "x.java", "operation": "diff", "candidate": "y.cpp"}])
def test_invalid_requests_stop_before_dispatch(arguments):
    with patch("pipeline.contract_inspection.inspect_contract", side_effect=AssertionError("no dispatch")), \
         patch("mcp_server.authorize_mcp_invocation", side_effect=AssertionError("no admission")):
        result = mcp_server.inspect_contract(**arguments)
    assert result["code"] == "INVALID_REQUEST" and not result["request_satisfied"]
    with pytest.raises(ValueError):
        ContractInspectionRequest(**arguments)


@pytest.mark.parametrize("kind", ["missing", "symlink", "outside", "encoding", "syntax", "bytes", "files"])
def test_candidate_failures_preserve_baseline(sources, kind):
    candidate = sources / "after/Account.java"
    limits = {}
    if kind == "missing":
        candidate.unlink()
    elif kind == "symlink":
        candidate.unlink()
        candidate.symlink_to(sources / "before/Account.java")
    elif kind == "outside":
        candidate = "../outside.java"
    elif kind == "encoding":
        candidate.write_bytes(b"\xff")
    elif kind == "syntax":
        candidate.write_text("public class {")
    elif kind == "bytes":
        limits = {"max_input_bytes": len(SOURCE.encode())}
    else:
        limits = {"max_input_files": 1}
    result = inspect_contract(ContractInspectionRequest("before/Account.java", "diff", str(candidate)),
        WorkflowContext.for_cli(("workspace_read",), resource_budget=limits))
    assert not result["request_satisfied"] and result["claim"] == "NO_PROOF"
    assert result["inputs"]["source"]["sha256"] == hashlib.sha256(SOURCE.encode()).hexdigest()
    assert result["surfaces"]["source"] and "comparison" not in result


def test_once_capture_and_exact_budget(sources):
    from pipeline.contract_inspection import capture
    def changed(name, *args):
        content = capture(name, *args)
        (sources / "before/Account.java").write_text("public class {")
        return content
    with patch("pipeline.contract_inspection.capture", side_effect=changed) as reader:
        result = inspect_contract(ContractInspectionRequest("before/Account.java", "diff", "before/./Account.java"),
            WorkflowContext.for_cli(("workspace_read",), resource_budget={"max_input_files": 1,
                                                                      "max_input_bytes": len(SOURCE.encode())}))
    assert reader.call_count == 1 and result["request_satisfied"]
    assert result["comparison"]["surface_equal"]
    assert result["inputs"]["source"] == result["inputs"]["candidate"]


def test_permissions_no_contracts_and_output(sources):
    from pipeline.mcp_policy import MCPPolicyViolation, authorize_mcp_invocation
    with patch("pipeline.contract_inspection.capture", side_effect=AssertionError("no capture")):
        with pytest.raises(MCPPolicyViolation):
            inspect_contract(ContractInspectionRequest("before/Account.java"), WorkflowContext.for_cli(()))
    denied = authorize_mcp_invocation("inspect_contract", mode="extract", language="java",
        backend="builtin-contract-surface", effects=("workspace_read", "external_execution"))
    assert not denied.admitted
    with patch("mcp_server.authorize_mcp_invocation", return_value=denied), \
         patch("pipeline.contract_inspection.inspect_contract") as service:
        assert not mcp_server.inspect_contract("before/Account.java")["request_satisfied"]
        service.assert_not_called()
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["contract", "extract", "before/Account.java", "--json", "result.json"])
    (sources / "before/Account.java").write_text("public class Account {}")
    result = mcp_server.inspect_contract("before/Account.java")
    assert result["request_satisfied"] and not result["contract_statements_present"]["source"]
    assert result["review_status"] == "NOT_ASSESSED"


def test_real_contract_transport():
    if not any(os.environ.get(key) == "1" for key in (
            "FORMALSPECGEN_REQUIRE_CONTRACT_TRANSPORT", "FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE")):
        pytest.skip("explicit contract transport acceptance")
    from scripts.mcp_acceptance_adapters import collect_transport_observation
    result = collect_transport_observation("contract")
    assert result["workspace_unchanged"] and len(result["cli_comparisons"]) == 12
