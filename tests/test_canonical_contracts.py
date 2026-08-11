# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

import pytest

from pipeline.canonical_contracts import (
    CanonicalContractConflict, canonical_contract, canonical_traffic_light_contract,
)
from pipeline.domains.traffic_light_controller_extract import (
    extract_traffic_light_controller_model, recognizes_traffic_light_controller,
)


def test_canonical_traffic_contract_enters_reviewed_adapter():
    code, assumptions = canonical_traffic_light_contract(
        "Design a traffic-light controller. RED=0, YELLOW=1, GREEN=2. "
        "Only turn green while the opposing direction is red.")
    assert recognizes_traffic_light_controller(code)
    model, findings = extract_traffic_light_controller_model(
        code, "single-threaded", "atomic_operations")
    assert findings == []
    assert len(model.operations) == 6
    assert any("single-threaded" in item for item in assumptions)


def test_canonical_contract_rejects_wrong_domain_and_conflicts():
    with pytest.raises(CanonicalContractConflict, match="traffic-light requirement"):
        canonical_traffic_light_contract("Design a bounded counter")
    with pytest.raises(CanonicalContractConflict, match="opposing light"):
        canonical_traffic_light_contract(
            "Design a traffic light where green is allowed when the opposing light is yellow")
    with pytest.raises(CanonicalContractConflict, match="Boolean-result"):
        canonical_traffic_light_contract(
            "Design a traffic light where boolean true is returned by turnNsGreen")


def test_canonical_domain_aliases_and_review_state_are_actionable():
    domain, code, _assumptions = canonical_contract(
        "traffic_light", "Design a traffic light controller")
    assert domain == "traffic_light_controller"
    assert "turnNsGreen" in code
    elevator_domain, elevator_code, assumptions = canonical_contract(
        "elevator", "Design a five-floor elevator controller")
    assert elevator_domain == "elevator_controller"
    assert "arriveUp" in elevator_code and "closeDoors" in elevator_code
    assert any("single-threaded" in item for item in assumptions)
    with pytest.raises(CanonicalContractConflict, match="no reviewed canonical"):
        canonical_contract("unknown", "Design something")
