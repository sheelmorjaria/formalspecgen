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

INVENTORY_SOURCE = r"""public class Account {
    //@ invariant true;
    public Account() {}
    //@ requires true;
    //@ ensures \result >= 0;
    //@ assignable \nothing;
    //@ signals (Exception e) true;
    public int balance() { return 1; }
    protected void reset() {}
    //@ requires false;
    private void helper() {}
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
    for role, inventory in local["clause_inventory"].items():
        assert inventory["input_pointer"] == f"/inputs/{role}"
        assert inventory["member_count"] == 1 and inventory["members_without_explicit_clauses"] == 0
        assert inventory["members"][0]["keywords"] == {"requires": 1, "ensures": 1}
    if candidate:
        assert local["comparison"]["surface_equal"] and not local["comparison"]["differences"]
        assert local["comparison"]["review_changes"] == []
        assert local["inputs"]["source"]["sha256"] != local["inputs"]["candidate"]["sha256"]
    assert before == {p: p.read_bytes() for p in sources.rglob("*") if p.is_file()}


@pytest.mark.parametrize("change", ["clause", "assumption", "context", "api", "modifier", "annotation", "private-assumption"])
def test_surface_mutations_are_reported_not_proved(sources, change):
    candidate = {"clause": SOURCE.replace(">= 0", ">= 1"),
                 "assumption": SOURCE.replace("return 1;", "\n//@ assume true;\nreturn 1;"),
                 "context": "import java.util.List;\n" + SOURCE,
                 "api": SOURCE.replace("balance()", "balance(int extra)"),
                 "modifier": SOURCE.replace("public int balance", "/*@ pure @*/ public int balance"),
                 "annotation": SOURCE.replace("public int balance", "@Deprecated\npublic int balance"),
                 "private-assumption": SOURCE.replace("public int balance", "private int helper() {\n//@ assume true;\nreturn 0; }\npublic int balance")}[change]
    (sources / "after/Account.java").write_text(candidate)
    result = mcp_server.inspect_contract("before/Account.java", "diff", "after/Account.java")
    assert result["request_satisfied"] and result["status"] == "CONTRACT_COMPARED"
    assert not result["comparison"]["surface_equal"] and result["comparison"]["differences"]
    assert result["claim"] == "NO_PROOF" and not result["semantic_equivalence_proved"]
    changes = result["comparison"]["review_changes"]
    category = {"clause": "CONTRACT_CLAUSES", "assumption": "PROOF_TRUST",
                "context": "SEMANTIC_CONTEXT", "api": "PUBLIC_API",
                "modifier": "SEMANTIC_MODIFIERS", "annotation": "JAVA_ANNOTATIONS",
                "private-assumption": "PROOF_TRUST"}[change]
    assert category in {item["category"] for item in changes}
    _assert_review_references(result)
    assert changes == mcp_server.inspect_contract("before/Account.java", "diff", "after/Account.java")["comparison"]["review_changes"]


def _resolve(document, pointer):
    for token in pointer[1:].split("/"):
        document = document[token.replace("~1", "/").replace("~0", "~")]
    return document


def _assert_review_references(result):
    for change in result["comparison"]["review_changes"]:
        for role in ("source", "candidate"):
            reference = change[role]
            assert _resolve(result, reference["input_pointer"]) == result["inputs"][role]
            if reference["present"]:
                assert _resolve(result, reference["surface_pointer"]) == reference["value"]
            else:
                assert reference["surface_pointer"] is None and reference["value"] is None
        expected_kind = ("ADDED" if not change["source"]["present"] else
                         "REMOVED" if not change["candidate"]["present"] else "MODIFIED")
        assert change["kind"] == expected_kind
        assert (change["source"]["present"], change["source"]["value"]) != (change["candidate"]["present"], change["candidate"]["value"])


def test_review_change_structure_and_pointer_escaping():
    from pipeline.contract_inspection import _surface_review_changes
    # Synthetic parser objects exercise JSON pointer escaping and absence vs
    # null/empty values without inventing Java support for these field names.
    source = {"clauses": {"members": {"a~/b": ["requires x;", "ensures y;"],
                                     "removed": [], "null": None}},
              "future_surface": {"flag": "old"}}
    candidate = {"future_surface": {"flag": "new"},
                 "clauses": {"members": {"a~/b": ["ensures y;", "requires x;", "requires x;"],
                                         "added": [], "null": []}}}
    changes = _surface_review_changes(source, candidate)
    result = {"inputs": {"source": {"sha256": "before"}, "candidate": {"sha256": "after"}},
              "surfaces": {"source": source, "candidate": candidate},
              "comparison": {"review_changes": changes}}
    _assert_review_references(result)
    assert len(changes) == 5
    assert [item["kind"] for item in changes] == ["ADDED", "MODIFIED", "MODIFIED", "REMOVED", "MODIFIED"]
    assert changes[1]["source"]["surface_pointer"].endswith("/a~0~1b")
    assert changes[-1]["category"] == "OTHER_SURFACE"
    assert changes == _surface_review_changes(dict(reversed(list(source.items()))), candidate)
    assert _surface_review_changes(source, source) == []


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
    assert set(result["clause_inventory"]) == {"source"}


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
    assert result["comparison"]["review_changes"] == []
    assert result["inputs"]["source"] == result["inputs"]["candidate"]


def test_review_changes_bind_captured_not_current_sources(sources):
    from pipeline.contract_inspection import capture
    changed_source = SOURCE.replace(">= 0", ">= 1")
    (sources / "after/Account.java").write_text(changed_source)
    calls = 0

    def mutate_after_capture(*args):
        nonlocal calls
        content = capture(*args)
        calls += 1
        if calls == 2:
            for role in ("before", "after"):
                (sources / role / "Account.java").write_text("public class Replacement {}")
        return content

    with patch("pipeline.contract_inspection.capture", side_effect=mutate_after_capture):
        result = inspect_contract(ContractInspectionRequest("before/Account.java", "diff", "after/Account.java"),
                                  WorkflowContext.for_cli(("workspace_read",)))
    assert calls == 2 and result["request_satisfied"]
    assert result["inputs"]["source"]["sha256"] == hashlib.sha256(SOURCE.encode()).hexdigest()
    assert result["inputs"]["candidate"]["sha256"] == hashlib.sha256(changed_source.encode()).hexdigest()
    changes = result["comparison"]["review_changes"]
    assert len(changes) == 1 and changes[0]["category"] == "CONTRACT_CLAUSES"
    assert changes[0]["kind"] == "MODIFIED"
    _assert_review_references(result)
    assert result["clause_inventory"]["source"]["member_count"] == 1
    assert result["clause_inventory"]["candidate"]["member_count"] == 1


@pytest.mark.parametrize("content, members, empty", [
    (INVENTORY_SOURCE, 3, 2),
    ("public class Account {}", 0, 0),
    ("public class Account { public void reset() {} }", 1, 1),
    ("public class Account {\n//@ invariant true;\npublic void reset() {}\n}", 1, 1),
    ("public class Account {\n/*@ pure @*/ public int balance() { return 1; }\n}", 1, 1),
    ("public class Account { public int balance() {\n//@ assume true;\nreturn 1; } }", 1, 0),
    ("public class Account {\n//@ ensures true;\npublic void reset() {}\n}", 1, 0),
])
def test_explicit_clause_inventory_is_not_adequacy(sources, capsys, content, members, empty):
    path = sources / "before/Account.java"
    path.write_text(content)
    remote = mcp_server.inspect_contract("before/Account.java")
    args = cli.build_parser().parse_args(["contract", "extract", "before/Account.java", "--json", "-"])
    assert cli.dispatch(args, cli.TerminalUI(), None, {}) == 0
    local = json.loads(capsys.readouterr().out)["result"]
    assert local == {key: value for key, value in remote.items() if key != "mcp_admission"}
    assert local["request_satisfied"] and local["claim"] == "NO_PROOF"
    inventory = local["clause_inventory"]["source"]
    assert inventory["adequacy"] == inventory["effective_contracts"] == "NOT_ASSESSED"
    assert inventory["member_count"] == members
    assert inventory["members_without_explicit_clauses"] == empty
    assert _resolve(local, inventory["input_pointer"])["sha256"] == hashlib.sha256(content.encode()).hexdigest()
    for member in inventory["members"]:
        assert len(_resolve(local, member["clauses_pointer"])) == member["clause_count"]
        assert sum(member["keywords"].values()) == member["clause_count"]
        assert "helper" not in member["signature"]
    if content == INVENTORY_SOURCE:
        assert [member["kind"] for member in inventory["members"]] == ["method", "method", "constructor"]
        assert inventory["members"][1]["keywords"] == {"requires": 1, "ensures": 1, "assignable": 1, "signals": 1}


def test_inventory_preserves_prefixes_duplicates_and_unclassified_syntax():
    from pipeline.contract_inspection import _clause_inventory
    signature = "synthetic~/signature"
    clauses = ['public normal_behavior requires true', 'also requires true',
               'ensures "requires" != null', 'modifiable x', 'modifies y', 'normal_behavior']
    surface = {"methods": [signature], "constructors": [], "clauses": {"members": {signature: clauses}}}
    inventory = _clause_inventory(surface, "source")
    member = inventory["members"][0]
    assert member["keywords"] == {"requires": 2, "ensures": 1, "modifiable": 1, "modifies": 1, "other": 1}
    assert member["clause_count"] == 6
    assert _resolve({"surfaces": {"source": surface}}, member["clauses_pointer"]) == clauses


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
    assert result["workspace_unchanged"] and len(result["cli_comparisons"]) == 17
