import pytest

from pipeline.workspace_contracts import contract_context, index_workspace, retrieve_contracts


ACCOUNT = r"""public class Account {
  //@ requires amount > 0;
  //@ requires balance >= amount;
  //@ assignable balance;
  //@ ensures balance == \old(balance) - amount;
  public boolean withdraw(long amount) { return false; }
}"""


def test_index_and_rank_exact_workspace_contracts():
    entries = index_workspace({"src/Account.java": ACCOUNT, "Empty.java": "class Empty {}"})
    assert len(entries) == 1
    assert entries[0].owner == "Account" and entries[0].method == "withdraw"
    assert entries[0].clauses[0] == "requires amount > 0;"
    assert retrieve_contracts("Transfer using Account.withdraw", {"src/Account.java": ACCOUNT})[0]["source"] == "src/Account.java"
    assert retrieve_contracts("unrelated elevator", {"src/Account.java": ACCOUNT}) == []


def test_context_is_provenanced_and_bounded():
    prompt, entries = contract_context("Call Account withdraw", {"src/Account.java": ACCOUNT})
    assert entries and "read-only context" in prompt
    assert "src/Account.java :: public boolean withdraw(long amount) {" in prompt
    assert "establish applicable callee preconditions" in prompt
    assert contract_context("unrelated", {"src/Account.java": ACCOUNT}) == ("unrelated", [])
    with pytest.raises(ValueError, match="WORKSPACE_CONTEXT_TOO_LARGE"):
        index_workspace({f"{n}.java": ACCOUNT for n in range(81)})
    with pytest.raises(ValueError, match="WORKSPACE_CONTEXT_TOO_LARGE"):
        index_workspace({"Huge.java": "x" * 500_001})


def test_interface_and_fallback_owner_are_supported():
    code = """//@ ensures \\result >= 0;
protected int size();"""
    entry = index_workspace({"api/Collection.java": code})[0]
    assert entry.owner == "Collection" and entry.method == "size"
