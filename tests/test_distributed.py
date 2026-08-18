# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M27 (roadmap Feature 6): verify-distributed — safety under an unreliable
network. DropMsg / DuplicateMsg / ReorderMsg are injected as synthetic
operations over the domain's declared message-slot fields, and the bounded
traverser must find the reviewed invariants holding across EVERY
fault-enabled interleaving. Over-approximating by construction: the faults
adversarially add behaviors, so safety under faults implies safety under any
subset. Liveness is never claimed — loss can always fire.
"""
from __future__ import annotations

import json

from pipeline.distributed import (
    inject_fault_actions, verify_distributed,
)

# Two-actor ping-pong over lossy slots: cmd_slot carries 0(empty)/1(message),
# ack_slot likewise; delivered counts completed round trips.
SAFE_DOMAIN = """schema_version: 2
review_status: unreviewed
domain_name: PingPong
module_name: ping_pong
actors: 2
execution_model: async_message_passing
state_variables:
  - kind: int
    name: cmd_slot
    bound: [0, 1]
    initial: 0
  - kind: int
    name: ack_slot
    bound: [0, 1]
    initial: 0
  - kind: int
    name: delivered
    bound: [0, 4]
    initial: 0
operations:
  - name: SendCmd
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: g1
        expression:
          kind: eq
          left: {kind: field, name: cmd_slot}
          right: {kind: integer, value: 0}
      - id: g1b
        expression:
          kind: eq
          left: {kind: field, name: ack_slot}
          right: {kind: integer, value: 0}
    effects:
      - id: e1
        target: cmd_slot
        value: {kind: integer, value: 1}
    frame: [cmd_slot]
  - name: RecvCmd
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: g2
        expression:
          kind: eq
          left: {kind: field, name: cmd_slot}
          right: {kind: integer, value: 1}
    effects:
      - id: e2
        target: cmd_slot
        value: {kind: integer, value: 0}
      - id: e2b
        target: ack_slot
        value: {kind: integer, value: 1}
    frame: [cmd_slot, ack_slot]
  - name: RecvAck
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: g3
        expression:
          kind: eq
          left: {kind: field, name: ack_slot}
          right: {kind: integer, value: 1}
      - id: g3b
        expression:
          kind: lt
          left: {kind: field, name: delivered}
          right: {kind: integer, value: 4}
    effects:
      - id: e3
        target: ack_slot
        value: {kind: integer, value: 0}
      - id: e3b
        target: delivered
        value:
          kind: add
          left: {kind: field, name: delivered}
          right: {kind: integer, value: 1}
    frame: [ack_slot, delivered]
tlc_invariants:
  - id: inv1
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: delivered}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: delivered}
        right: {kind: integer, value: 4}
"""

# Safety that DUPLICATION breaks: at most one message in flight. The
# DuplicateMsg fault copies a message into the other empty slot.
FRAGILE_DOMAIN = SAFE_DOMAIN.replace(
    """tlc_invariants:
  - id: inv1
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: delivered}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: delivered}
        right: {kind: integer, value: 4}""",
    """tlc_invariants:
  - id: inv1
    expression:
      kind: lte
      left:
        kind: add
        left: {kind: field, name: cmd_slot}
        right: {kind: field, name: ack_slot}
      right: {kind: integer, value: 1}""")


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_inject_drop_msg_removes_a_message(tmp_path):
    """Milestone 1 (Test 1.1): DropMsg resets an occupied slot to its empty
    sentinel — a message leaves the network set."""
    from pipeline.domain_v2_promotion import load_candidate
    spec = load_candidate(_write(tmp_path, "pp.v2.yaml", SAFE_DOMAIN))
    ops = inject_fault_actions(spec, faults=["message_loss"],
                               message_fields=["cmd_slot", "ack_slot"])
    drops = [op for op in ops if op.name.startswith("DropMsg")]
    assert {op.name for op in drops} == {"DropMsg_cmd_slot", "DropMsg_ack_slot"}
    drop = drops[0]
    # guard: the slot holds a message (cmd_slot == 1); effect: sentinel 0
    assert drop.guards[0].expression.model_dump(mode="json") == {
        "kind": "eq", "left": {"kind": "field", "name": "cmd_slot"},
        "right": {"kind": "integer", "value": 1}}
    assert drop.effects[0].target == "cmd_slot"
    assert drop.effects[0].value.model_dump(mode="json") == {
        "kind": "integer", "value": 0}


def test_duplicate_and_reorder_fault_shapes(tmp_path):
    from pipeline.domain_v2_promotion import load_candidate
    spec = load_candidate(_write(tmp_path, "pp.v2.yaml", SAFE_DOMAIN))
    ops = inject_fault_actions(spec,
                               faults=["duplication", "reordering"],
                               message_fields=["cmd_slot", "ack_slot"])
    names = {op.name for op in ops}
    assert "DuplicateMsg_cmd_slot_to_ack_slot" in names
    assert "ReorderMsg_cmd_slot_ack_slot" in names
    dup = next(op for op in ops if op.name.startswith("DuplicateMsg"))
    # enabled only when the source holds a message and the target is empty
    guards = {g.expression.model_dump(mode="json")["left"]["name"]:
              g.expression.model_dump(mode="json") for g in dup.guards}
    assert guards["cmd_slot"] == {
        "kind": "eq", "left": {"kind": "field", "name": "cmd_slot"},
        "right": {"kind": "integer", "value": 1}}
    assert guards["ack_slot"]["right"]["value"] == 0
    # a single declared field cannot model duplication: honestly refused
    assert inject_fault_actions(spec, faults=["duplication"],
                               message_fields=["cmd_slot"]) == []


def test_verify_distributed_proves_under_all_faults(tmp_path):
    """Milestone 2: the bounded traverser finds the invariants holding
    across every fault-enabled interleaving."""
    result = verify_distributed(
        _write(tmp_path, "pp.v2.yaml", SAFE_DOMAIN),
        faults=["message_loss", "duplication", "reordering"],
        message_fields=["cmd_slot", "ack_slot"])
    assert result["status"] == "DISTRIBUTED_SAFETY_PROVED"
    assert result["claim"] == "DISTRIBUTED_SAFETY_PROVED"
    assert result["fault_model"] == ["message_loss", "duplication",
                                     "reordering"]
    assert result["scope"] == "bounded_fault_injected_exploration"
    assert result["reachable_states"] > 0
    assert result["liveness_proved"] is False
    assert result["eventual_delivery_proved"] is False


def test_verify_distributed_finds_fault_violation(tmp_path):
    """The in-flight bound tolerates loss and reorder but DUPLICATION
    breaks it — the violation names the fault and the invariant."""
    result = verify_distributed(
        _write(tmp_path, "fragile.v2.yaml", FRAGILE_DOMAIN),
        faults=["message_loss", "duplication", "reordering"],
        message_fields=["cmd_slot", "ack_slot"])
    assert result["status"] == "DISTRIBUTED_SAFETY_FAILED"
    assert result["claim"] == "NO_PROOF"
    assert result["violated_invariant"] == "inv1"
    assert result["fault"] == "duplication"
    # loss-only stays safe: the bound survives message loss
    safe = verify_distributed(
        _write(tmp_path, "fragile.v2.yaml", FRAGILE_DOMAIN),
        faults=["message_loss"], message_fields=["cmd_slot", "ack_slot"])
    assert safe["status"] == "DISTRIBUTED_SAFETY_PROVED"


def test_verify_distributed_fails_closed_on_shapes(tmp_path):
    domain = _write(tmp_path, "pp.v2.yaml", SAFE_DOMAIN)
    assert verify_distributed(tmp_path / "nope.yaml",
                              faults=["message_loss"],
                              message_fields=["cmd_slot"])["code"] == \
        "input_unavailable"
    # non-async domains are outside the fault model
    atomic = _write(tmp_path, "atomic.v2.yaml",
                    SAFE_DOMAIN.replace("execution_model: async_message_passing\n", ""))
    result = verify_distributed(atomic, faults=["message_loss"],
                                message_fields=["cmd_slot"])
    assert result["code"] == "async_model_required"
    # unknown fault / unknown field names fail closed
    assert verify_distributed(domain, faults=["byzantine"],
                              message_fields=["cmd_slot"])["code"] == \
        "unknown_fault"
    assert verify_distributed(domain, faults=["message_loss"],
                              message_fields=["mystery"])["code"] == \
        "unknown_message_field"


def test_cli_command_mints_the_claim(tmp_path, monkeypatch):
    """Milestone 3 (Test 3.1): verify-distributed mints the claim with the
    fault model recorded."""
    import argparse
    from pipeline.cli import command_verify_distributed
    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "pp.v2.yaml", SAFE_DOMAIN)
    ui = _SilentUI()
    args = argparse.Namespace(domain="pp.v2.yaml",
                              faults="message_loss,duplication,reordering",
                              message_fields="cmd_slot,ack_slot",
                              json_out="d.json")
    assert command_verify_distributed(args, ui) == 0
    payload = json.loads((tmp_path / "d.json").read_text(encoding="utf-8"))
    assert payload["claim"] == "DISTRIBUTED_SAFETY_PROVED"
    assert payload["fault_model"][0] == "message_loss"

    _write(tmp_path, "fragile.v2.yaml", FRAGILE_DOMAIN)
    args = argparse.Namespace(domain="fragile.v2.yaml",
                              faults="message_loss,duplication,reordering",
                              message_fields="cmd_slot,ack_slot",
                              json_out="bad.json")
    assert command_verify_distributed(args, ui) == 1
    failed = json.loads((tmp_path / "bad.json").read_text(encoding="utf-8"))
    assert failed["status"] == "DISTRIBUTED_SAFETY_FAILED"


class _SilentUI:
    class console:
        @staticmethod
        def print(*_a, **_k): pass


def test_reviewed_fallback_loss_fault_and_exceeded_cap(tmp_path):
    """Reviewed-JSON loading, a DropMsg-classified violation, reorder
    classification, domain_unreadable, and the exploration cap."""
    import json as _json
    import yaml as _yaml
    from pipeline.distributed import _fault_of_operation

    assert _fault_of_operation("DropMsg_cmd_slot") == "message_loss"
    assert _fault_of_operation("ReorderMsg_a_b") == "reordering"
    assert _fault_of_operation("SendCmd") is None

    reviewed = _yaml.safe_load(SAFE_DOMAIN)
    reviewed["review_status"] = "reviewed"
    reviewed["accepted_candidate_sha256"] = "0" * 64
    reviewed["accepted_evidence_sha256"] = "1" * 64
    domain = _write(tmp_path, "pp.json", _json.dumps(reviewed))
    assert verify_distributed(domain, faults=["message_loss"],
                              message_fields=["cmd_slot"])["status"] == \
        "DISTRIBUTED_SAFETY_PROVED"                    # reviewed JSON loads

    garbage = _write(tmp_path, "bad.v2.yaml", "{{{ not yaml")
    result = verify_distributed(garbage, faults=["message_loss"],
                                message_fields=["cmd_slot"])
    assert result["code"] == "domain_unreadable"

    # a drop-induced violation classifies the fault as message_loss
    # an invariant only a DROP can break: some traffic must always be
    # countable; zeroing an occupied slot empties the network entirely
    drop_fragile = FRAGILE_DOMAIN.replace(
        """      kind: lte
      left:
        kind: add
        left: {kind: field, name: cmd_slot}
        right: {kind: field, name: ack_slot}
      right: {kind: integer, value: 1}""",
        """      kind: gte
      left:
        kind: add
        left:
          kind: add
          left: {kind: field, name: cmd_slot}
          right: {kind: field, name: ack_slot}
        right: {kind: field, name: delivered}
      right: {kind: integer, value: 1}""")
    result = verify_distributed(_write(tmp_path, "df.v2.yaml", drop_fragile),
                                faults=["message_loss"],
                                message_fields=["cmd_slot", "ack_slot"])
    assert result["status"] == "DISTRIBUTED_SAFETY_FAILED"
    assert result["fault"] == "message_loss"

    # exploding bounds refuse before exploration
    wide = _yaml.safe_load(SAFE_DOMAIN)
    wide["state_variables"][2]["bound"] = [0, 200001]
    capped = verify_distributed(_write(tmp_path, "wide.v2.yaml",
                                        _yaml.safe_dump(wide)),
                                faults=["message_loss"],
                                message_fields=["cmd_slot"])
    assert capped["code"] == "fault_model_state_space_exceeded"
