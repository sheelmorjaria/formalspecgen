# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Real-TLC end-to-end tests for the typed V2 domain lifecycle."""
import json
from pathlib import Path

import pytest

from pipeline.domain_v2_promotion import promote_domain
from pipeline.domain_v2_validation import validate_domain


pytestmark = pytest.mark.toolchain


ELEVATOR_V2_YAML = """
schema_version: 2
review_status: unreviewed
domain_name: ElevatorV2
module_name: elevator_v2
actors: 2
state_variables:
  - {kind: int, name: current_floor, bound: [0, 4], initial: 0}
  - {kind: int, name: door_state, bound: [0, 1], initial: 0}
  - {kind: int, name: moving_state, bound: [0, 2], initial: 0}
operations:
  - name: startMoveUp
    return_type: boolean
    failure_semantics: false_and_stutter
    guards:
      - id: moving_is_stopped
        expression: {kind: eq, left: {kind: field, name: moving_state}, right: {kind: integer, value: 0}}
      - id: doors_are_closed
        expression: {kind: eq, left: {kind: field, name: door_state}, right: {kind: integer, value: 0}}
      - id: below_top_floor
        expression: {kind: lt, left: {kind: field, name: current_floor}, right: {kind: integer, value: 4}}
    effects:
      - id: set_moving_up
        target: moving_state
        value: {kind: integer, value: 1}
    frame: [moving_state]
  - name: finishMove
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: moving_is_up
        expression: {kind: eq, left: {kind: field, name: moving_state}, right: {kind: integer, value: 1}}
    effects:
      - id: set_moving_stopped
        target: moving_state
        value: {kind: integer, value: 0}
    frame: [moving_state]
tlc_invariants:
  - id: DoorsClosedWhileMoving
    expression:
      kind: implies
      left: {kind: neq, left: {kind: field, name: moving_state}, right: {kind: integer, value: 0}}
      right: {kind: eq, left: {kind: field, name: door_state}, right: {kind: integer, value: 0}}
"""


VENDING_MACHINE_V2_YAML = """
schema_version: 2
review_status: unreviewed
domain_name: VendingMachineV2
module_name: vending_machine_v2
actors: 2
state_variables:
  - {kind: int, name: stock, bound: [0, 5], initial: 5}
  - {kind: int, name: credits, bound: [0, 10], initial: 0}
operations:
  - name: insertCoin
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: credits_not_full
        expression: {kind: lt, left: {kind: field, name: credits}, right: {kind: integer, value: 10}}
    effects:
      - id: add_credit
        target: credits
        value: {kind: add, left: {kind: field, name: credits}, right: {kind: integer, value: 1}}
    frame: [credits]
  - name: buyItem
    return_type: boolean
    failure_semantics: false_and_stutter
    guards:
      - id: has_enough_credits
        expression: {kind: gte, left: {kind: field, name: credits}, right: {kind: integer, value: 2}}
      - id: has_stock
        expression: {kind: gt, left: {kind: field, name: stock}, right: {kind: integer, value: 0}}
    effects:
      - id: decrement_stock
        target: stock
        value: {kind: sub, left: {kind: field, name: stock}, right: {kind: integer, value: 1}}
      - id: subtract_credits
        target: credits
        value: {kind: sub, left: {kind: field, name: credits}, right: {kind: integer, value: 2}}
    frame: [stock, credits]
tlc_invariants:
  - id: NonNegativeStock
    expression: {kind: gte, left: {kind: field, name: stock}, right: {kind: integer, value: 0}}
"""


def setup_candidate(root: Path, module_name: str, yaml_content: str) -> Path:
    candidates = root / "domains" / "candidates"
    candidates.mkdir(parents=True, exist_ok=True)
    candidate = candidates / f"{module_name}.v2.yaml"
    candidate.write_text(yaml_content, encoding="utf-8")
    return candidate


def validated_envelope(root: Path, module_name: str) -> dict:
    path = root / "domains" / "candidates" / f"{module_name}.v2.validation.json"
    assert path.exists(), "validation envelope was not published"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("module_name,yaml_content", [
    ("elevator_v2", ELEVATOR_V2_YAML),
    ("vending_machine_v2", VENDING_MACHINE_V2_YAML),
])
def test_v2_domain_validation_and_promotion_with_real_tlc(
        tmp_path, tlc_tool, module_name, yaml_content):
    setup_candidate(tmp_path, module_name, yaml_content)

    evidence = validate_domain(module_name, project_root=tmp_path, tlc_jar=tlc_tool)
    envelope = validated_envelope(tmp_path, module_name)
    assert envelope["evidence"]["validation_status"] == "VALIDATED"
    assert envelope["evidence"]["reachable_state_count"] >= 1
    assert envelope["evidence"]["reachable_transition_count"] >= 1
    assert envelope["evidence_sha256"]
    assert evidence.tools["tlc"].version.startswith("2.")

    candidate_hash = envelope["evidence"]["candidate_sha256"]
    reviewed = promote_domain(
        module_name, accept_candidate_sha256=candidate_hash, project_root=tmp_path)
    canonical = tmp_path / "domains" / "v2" / f"{module_name}.json"
    assert canonical.exists()
    canonical_value = json.loads(canonical.read_text(encoding="utf-8"))
    assert reviewed.review_status == canonical_value["review_status"] == "reviewed"
    assert canonical_value["accepted_candidate_sha256"] == candidate_hash


def test_v2_toctou_candidate_tampering_blocks_promotion(tmp_path, tlc_tool):
    module_name = "vending_machine_v2"
    candidate = setup_candidate(tmp_path, module_name, VENDING_MACHINE_V2_YAML)
    validate_domain(module_name, project_root=tmp_path, tlc_jar=tlc_tool)
    original_hash = validated_envelope(tmp_path, module_name)["evidence"]["candidate_sha256"]

    candidate.write_text(
        VENDING_MACHINE_V2_YAML.replace("initial: 5", "initial: 3"), encoding="utf-8")
    with pytest.raises(ValueError, match="candidate hash mismatch"):
        promote_domain(
            module_name, accept_candidate_sha256=original_hash, project_root=tmp_path)
    assert not (tmp_path / "domains" / "v2" / f"{module_name}.json").exists()


def test_v2_elevator_renders_per_actor_last_result(tmp_path, tlc_tool):
    module_name = "elevator_v2"
    setup_candidate(tmp_path, module_name, ELEVATOR_V2_YAML)
    validate_domain(module_name, project_root=tmp_path, tlc_jar=tlc_tool)
    from pipeline.domain_v2_promotion import load_candidate
    from pipeline.domain_v2_tla import render_v2_tla
    tla, cfg = render_v2_tla(load_candidate(
        tmp_path / "domains" / "candidates" / f"{module_name}.v2.yaml"))
    assert "startMoveUpFailure(actor)" in tla
    assert "callResult' = [callResult EXCEPT ![actor] = \"false\"]" in tla
    assert "Actors = {a1, a2}" in cfg
