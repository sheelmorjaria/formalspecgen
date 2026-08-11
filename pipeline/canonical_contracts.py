# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Deterministic contracts for reviewed semantic domains."""
from __future__ import annotations

import re

from .domains.traffic_light_controller import ACTION_REFINEMENTS


class CanonicalContractConflict(ValueError):
    pass


_ALIASES = {
    "traffic_light": "traffic_light_controller",
    "traffic-light": "traffic_light_controller",
    "elevator": "elevator_controller",
}


def canonical_contract(domain: str, requirement: str) -> tuple[str, str, list[str]]:
    """Resolve a domain name and invoke only a reviewed deterministic serializer."""
    normalized = _ALIASES.get(domain.strip().lower(), domain.strip().lower())
    if normalized == "traffic_light_controller":
        code, assumptions = canonical_traffic_light_contract(requirement)
        return normalized, code, assumptions
    if normalized == "elevator_controller":
        code, assumptions = canonical_elevator_contract(requirement)
        return normalized, code, assumptions
    raise CanonicalContractConflict(
        f"no reviewed canonical contract serializer for domain {normalized!r}")


def canonical_traffic_light_contract(requirement: str) -> tuple[str, list[str]]:
    """Render the reviewed six-action JML surface after checking obvious conflicts."""
    lowered = re.sub(r"\s+", " ", requirement.lower())
    if "traffic light" not in lowered and "traffic-light" not in lowered:
        raise CanonicalContractConflict(
            "traffic_light_controller requires a traffic-light requirement")
    conflicts = []
    if re.search(r"(?:green|turn green).{0,50}(?:other|opposing).{0,30}(?:yellow|not green)", lowered):
        conflicts.append("reviewed green transitions require the opposing light to be RED")
    if re.search(r"\b(?:boolean|true|false)\b.{0,50}\bturn(?:ns|ew|north|east)", lowered):
        conflicts.append("reviewed transition operations are void, not Boolean-result APIs")
    if conflicts:
        raise CanonicalContractConflict("; ".join(conflicts))
    expected = {'turnNsGreen', 'turnNsYellow', 'turnNsRed',
                'turnEwGreen', 'turnEwYellow', 'turnEwRed'}
    if set(ACTION_REFINEMENTS) != expected:
        raise CanonicalContractConflict("reviewed traffic-light action table is incomplete")
    code = r'''public class TrafficLightController {
    private /*@ spec_public @*/ int ns_light;
    private /*@ spec_public @*/ int ew_light;

    //@ public invariant 0 <= ns_light && ns_light <= 2;
    //@ public invariant 0 <= ew_light && ew_light <= 2;
    //@ public invariant !(ns_light == 2 && ew_light == 2);

    //@ ensures ns_light == 0 && ew_light == 0;
    public TrafficLightController() {
        ns_light = 0;
        ew_light = 0;
    }

    //@ requires ew_light == 0;
    //@ assignable ns_light;
    //@ ensures ns_light == 2;
    public void turnNsGreen() {}

    //@ requires ns_light == 2;
    //@ assignable ns_light;
    //@ ensures ns_light == 1;
    public void turnNsYellow() {}

    //@ requires ns_light == 1;
    //@ assignable ns_light;
    //@ ensures ns_light == 0;
    public void turnNsRed() {}

    //@ requires ns_light == 0;
    //@ assignable ew_light;
    //@ ensures ew_light == 2;
    public void turnEwGreen() {}

    //@ requires ew_light == 2;
    //@ assignable ew_light;
    //@ ensures ew_light == 1;
    public void turnEwYellow() {}

    //@ requires ew_light == 1;
    //@ assignable ew_light;
    //@ ensures ew_light == 0;
    public void turnEwRed() {}
}
'''
    assumptions = [
        "Light encoding is RED=0, YELLOW=1, GREEN=2.",
        "A direction may enter GREEN only while the opposing direction is RED.",
        "The contract models single-threaded atomic method calls; concurrent linearizability is not proved.",
    ]
    return code, assumptions


def canonical_elevator_contract(requirement: str) -> tuple[str, list[str]]:
    """Render the reviewed five-floor, observable-motion elevator contract."""
    lowered = re.sub(r"\s+", " ", requirement.lower())
    if "elevator" not in lowered:
        raise CanonicalContractConflict("elevator_controller requires an elevator requirement")
    if re.search(r"\b(?:six|6)\s+floors?\b", lowered):
        raise CanonicalContractConflict("reviewed elevator has exactly five floors numbered 0..4")
    code = r'''public class ElevatorController {
    private /*@ spec_public @*/ int current_floor;
    private /*@ spec_public @*/ int door_state;
    private /*@ spec_public @*/ int moving_state;

    //@ public invariant 0 <= current_floor && current_floor <= 4;
    //@ public invariant 0 <= door_state && door_state <= 1;
    //@ public invariant 0 <= moving_state && moving_state <= 2;
    //@ public invariant moving_state != 0 ==> door_state == 0;

    //@ ensures current_floor == 0 && door_state == 0 && moving_state == 0;
    public ElevatorController() { current_floor = 0; door_state = 0; moving_state = 0; }

    //@ requires moving_state == 0;
    //@ requires door_state == 0;
    //@ requires current_floor < 4;
    //@ assignable moving_state;
    //@ ensures moving_state == 1;
    public void startMoveUp() {}

    //@ requires moving_state == 0;
    //@ requires door_state == 0;
    //@ requires current_floor > 0;
    //@ assignable moving_state;
    //@ ensures moving_state == 2;
    public void startMoveDown() {}

    //@ requires moving_state == 1;
    //@ assignable current_floor, moving_state;
    //@ ensures current_floor == \old(current_floor) + 1 && moving_state == 0;
    public void arriveUp() {}

    //@ requires moving_state == 2;
    //@ assignable current_floor, moving_state;
    //@ ensures current_floor == \old(current_floor) - 1 && moving_state == 0;
    public void arriveDown() {}

    //@ requires moving_state == 0;
    //@ requires door_state == 0;
    //@ assignable door_state;
    //@ ensures door_state == 1;
    public void openDoors() {}

    //@ requires door_state == 1;
    //@ assignable door_state;
    //@ ensures door_state == 0;
    public void closeDoors() {}
}
'''
    return code, [
        "Floors are exactly 0 through 4.",
        "Door states are CLOSED=0 and OPEN=1; motion states are STOPPED=0, UP=1, DOWN=2.",
        "Movement is observable through separate start and directional arrival actions.",
        "Operations are strict-guarded void actions under a single-threaded atomic-call assumption.",
    ]
