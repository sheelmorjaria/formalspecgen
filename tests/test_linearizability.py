# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M26 (roadmap Feature 3): verify-linearizability.

Two halves: (1) a deterministic Java lock-correspondence gate — every lock
acquisition site in the source must map to the modeled lock variable, and a
mixed or unmodeled lock discipline fails closed; (2) the bounded
invocation-history exploration (the traverser's lock-protocol mode) proving
every bounded concurrent history serializes through the reviewed
effect_commit linearization points. The claim covers the model plus the lock
correspondence — not the Java memory model.
"""
from __future__ import annotations

import json

from pipeline.linearizability import (
    extract_lock_sites, verify_linearizability,
)

JAVA_SYNC = """public class ConcurrentBank {
    private int balance = 0;

    public void deposit(int amount) {
        synchronized (this) {
            balance = balance + amount;
        }
    }

    public boolean withdraw(int amount) {
        synchronized (this) {
            if (balance >= amount) {
                balance = balance - amount;
                return true;
            }
            return false;
        }
    }
}
"""

JAVA_REENTRANT = """import java.util.concurrent.locks.ReentrantLock;

public class ConcurrentBank {
    private final ReentrantLock account_lock = new ReentrantLock();
    private int balance = 0;

    public void deposit(int amount) {
        account_lock.lock();
        try {
            balance = balance + amount;
        } finally {
            account_lock.unlock();
        }
    }
}
"""

JAVA_FOREIGN_LOCK = JAVA_REENTRANT.replace("account_lock", "mutex")

JAVA_MIXED = """public class ConcurrentBank {
    private final Object guard = new Object();
    private int balance = 0;

    public void deposit(int amount) {
        synchronized (this) { balance = balance + amount; }
        synchronized (guard) { audit(); }
    }
    private void audit() { }
}
"""

DOMAIN_YAML = """schema_version: 2
review_status: unreviewed
domain_name: ConcurrentBankAccount
module_name: concurrent_bank_account
actors: 2
concurrency:
  mode: lock_protocol
  lock_variable: account_lock
  actor_lock_values: [1, 2]
  lock_states: [UNLOCKED, LOCKED_ACTOR_1, LOCKED_ACTOR_2]
  unlocked_value: 0
  linearization_points:
    Deposit: effect_commit
    Withdraw: effect_commit
state_variables:
  - kind: int
    name: account_lock
    bound: [0, 2]
    initial: 0
  - kind: int
    name: balance
    bound: [0, 10]
    initial: 0
operations:
  - name: Deposit
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: g1
        expression:
          kind: lte
          left: {kind: field, name: balance}
          right: {kind: integer, value: 9}
    effects:
      - id: e1
        target: balance
        value:
          kind: add
          left: {kind: field, name: balance}
          right: {kind: integer, value: 1}
    frame: [balance]
  - name: Withdraw
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: g2
        expression:
          kind: gte
          left: {kind: field, name: balance}
          right: {kind: integer, value: 1}
    effects:
      - id: e2
        target: balance
        value:
          kind: sub
          left: {kind: field, name: balance}
          right: {kind: integer, value: 1}
    frame: [balance]
tlc_invariants:
  - id: inv1
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: balance}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: balance}
        right: {kind: integer, value: 10}
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_extract_lock_sites_finds_synchronized_regions():
    """Milestone 1 (Test 1.1): synchronized blocks yield acquisition and
    release points."""
    sites = extract_lock_sites(JAVA_SYNC)
    sync = [site for site in sites if site["kind"] == "synchronized"]
    assert len(sync) == 2
    assert all(site["lock"] == "this" for site in sync)
    first = sync[0]
    assert first["acquire_line"] < first["release_line"]
    assert first["acquire_line"] == 5           # the deposit guard opens
    assert first["release_line"] == 7           # and closes three lines later


def test_extract_lock_sites_finds_reentrant_locks():
    sites = extract_lock_sites(JAVA_REENTRANT)
    explicit = [site for site in sites if site["kind"] == "explicit"]
    assert {site["lock"] for site in explicit} == {"account_lock"}
    assert {site["action"] for site in explicit} == {"lock", "unlock"}


def test_correspondence_rejects_unmodeled_locks(tmp_path):
    """Milestone 1 (Test 1.2): a ReentrantLock outside the model fails
    closed; synchronized-only sources and matching lock names correspond."""
    domain = _write(tmp_path, "bank.v2.yaml", DOMAIN_YAML)

    result = verify_linearizability(_write(tmp_path, "Foreign.java",
                                           JAVA_FOREIGN_LOCK), domain)
    assert result["status"] == "LINEARIZABILITY_FAILED"
    assert result["code"] == "LOCK_CORRESPONDENCE_FAILED"
    assert "mutex" in result["message"]

    mixed = verify_linearizability(_write(tmp_path, "Mixed.java",
                                          JAVA_MIXED), domain)
    assert mixed["code"] == "LOCK_CORRESPORDENCE_FAILED".replace("D", "D") \
        or mixed["code"] == "LOCK_CORRESPONDENCE_FAILED"
    assert "guard" in mixed["message"] or "receiver" in mixed["message"]

    # synchronized-only and name-matching ReentrantLock both correspond
    for name, source in (("Sync.java", JAVA_SYNC),
                         ("Reentrant.java", JAVA_REENTRANT)):
        result = verify_linearizability(_write(tmp_path, name, source), domain)
        assert result["status"] == "LINEARIZABILITY_PROVED", (name, result)


def test_verify_linearizability_proves_and_reports_scope(tmp_path):
    """Milestones 2+3: bounded history exploration passes and the claim is
    scoped to the model plus lock correspondence."""
    domain = _write(tmp_path, "bank.v2.yaml", DOMAIN_YAML)
    result = verify_linearizability(_write(tmp_path, "Bank.java", JAVA_SYNC),
                                   domain)
    assert result["status"] == "LINEARIZABILITY_PROVED"
    assert result["claim"] == "CONCURRENT_LINEARIZABILITY_PROVED"
    assert result["scope"] == "bounded_lock_history_plus_java_lock_correspondence"
    assert result["reachable_states"] > 0
    assert result["reachable_transitions"] > 0
    assert result["lock_sites_mapped"] == 2
    assert result["linearization_points"] == {"Deposit": "effect_commit",
                                              "Withdraw": "effect_commit"}
    assert result["java_memory_model_proved"] is False


def test_verify_linearizability_fails_closed_on_domain_shapes(tmp_path):
    domain = _write(tmp_path, "bank.v2.yaml", DOMAIN_YAML)
    # missing file / missing lock protocol / missing linearization point
    assert verify_linearizability(tmp_path / "nope.java", domain)["code"] == \
        "input_unavailable"
    atomic = _write(tmp_path, "atomic.v2.yaml",
                    DOMAIN_YAML.split("concurrency:")[0] +
                    "state_variables:" +
                    DOMAIN_YAML.split("state_variables:", 1)[1])
    result = verify_linearizability(_write(tmp_path, "Bank.java", JAVA_SYNC),
                                    atomic)
    assert result["code"] == "lock_protocol_required"

    # partial linearization-point coverage is refused by the DOMAIN SCHEMA
    # itself (the spec never loads) — surfaced here as domain_unreadable
    no_points = DOMAIN_YAML.replace("    Withdraw: effect_commit\n", "")
    result = verify_linearizability(
        _write(tmp_path, "Bank.java", JAVA_SYNC),
        _write(tmp_path, "nopoints.v2.yaml", no_points))
    assert result["code"] == "domain_unreadable"
    assert "linearization" in result["message"]


def test_cli_command_mints_the_claim(tmp_path, monkeypatch):
    """Milestone 3 (Test 3.1): verify-linearizability Bank.java mints the
    claim and writes evidence."""
    import argparse
    from pipeline.cli import command_verify_linearizability
    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "Bank.java", JAVA_SYNC)
    _write(tmp_path, "bank.v2.yaml", DOMAIN_YAML)
    ui = _SilentUI()
    args = argparse.Namespace(source="Bank.java", domain="bank.v2.yaml",
                              json_out="lin.json")
    assert command_verify_linearizability(args, ui) == 0
    payload = json.loads((tmp_path / "lin.json").read_text(encoding="utf-8"))
    assert payload["claim"] == "CONCURRENT_LINEARIZABILITY_PROVED"

    _write(tmp_path, "Foreign.java", JAVA_FOREIGN_LOCK)
    args = argparse.Namespace(source="Foreign.java", domain="bank.v2.yaml",
                              json_out="bad.json")
    assert command_verify_linearizability(args, ui) == 1
    failed = json.loads((tmp_path / "bad.json").read_text(encoding="utf-8"))
    assert failed["code"] == "LOCK_CORRESPONDENCE_FAILED"


class _SilentUI:
    class console:
        @staticmethod
        def print(*_a, **_k): pass


def test_reviewed_fallback_and_exploration_failure(tmp_path):
    """The reviewed-JSON loader path proves, and a traverser failure is
    surfaced as history_exploration_failed."""
    import json as _json
    import yaml as _yaml
    from unittest.mock import patch
    reviewed = _yaml.safe_load(DOMAIN_YAML)
    reviewed["review_status"] = "reviewed"
    reviewed["accepted_candidate_sha256"] = "0" * 64
    reviewed["accepted_evidence_sha256"] = "1" * 64
    domain = _write(tmp_path, "bank.json", _json.dumps(reviewed))
    result = verify_linearizability(_write(tmp_path, "Bank.java", JAVA_SYNC),
                                   domain)
    assert result["status"] == "LINEARIZABILITY_PROVED"   # reviewed JSON loads

    with patch("pipeline.domain_v2_model.validate_transitions_and_invariants",
               side_effect=ValueError("state space exceeds maximum")):
        failed = verify_linearizability(
            _write(tmp_path, "B2.java", JAVA_SYNC),
            _write(tmp_path, "bank.v2.yaml", DOMAIN_YAML))
    assert failed["code"] == "history_exploration_failed"
    assert "state space" in failed["message"]
