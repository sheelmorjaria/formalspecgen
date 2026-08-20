# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic TLA+ renderer for the reviewed bounded elevator."""
from ..extract_tla_ir import UnsupportedJmlSemantics
from .elevator_controller import ElevatorControllerTlaModel
from .elevator_controller_extract import extract_elevator_controller_model, recognizes_elevator_controller
from .router import DomainMaturity, DomainPlugin

def render_elevator_controller(model: ElevatorControllerTlaModel) -> tuple[str,str]:
    if model is None or {x.operation for x in model.operations}!={'startMoveUp','startMoveDown','arriveUp','arriveDown','openDoors','closeDoors'}:
        raise UnsupportedJmlSemantics('Incomplete elevator operation set')
    tla=r'''---- MODULE ElevatorController ----
EXTENDS Naturals
VARIABLES currentFloor, doorState, movingState
vars == <<currentFloor, doorState, movingState>>
Init == /\ currentFloor = 0 /\ doorState = 0 /\ movingState = 0
StartMoveUp == /\ movingState = 0 /\ doorState = 0 /\ currentFloor < 4 /\ movingState' = 1 /\ UNCHANGED <<currentFloor, doorState>>
StartMoveDown == /\ movingState = 0 /\ doorState = 0 /\ currentFloor > 0 /\ movingState' = 2 /\ UNCHANGED <<currentFloor, doorState>>
ArriveUp == /\ movingState = 1 /\ currentFloor' = currentFloor + 1 /\ movingState' = 0 /\ UNCHANGED doorState
ArriveDown == /\ movingState = 2 /\ currentFloor' = currentFloor - 1 /\ movingState' = 0 /\ UNCHANGED doorState
OpenDoors == /\ movingState = 0 /\ doorState = 0 /\ doorState' = 1 /\ UNCHANGED <<currentFloor, movingState>>
CloseDoors == /\ doorState = 1 /\ doorState' = 0 /\ UNCHANGED <<currentFloor, movingState>>
Next == \/ StartMoveUp \/ StartMoveDown \/ ArriveUp \/ ArriveDown \/ OpenDoors \/ CloseDoors
TypeOK == /\ currentFloor \in 0..4 /\ doorState \in 0..1 /\ movingState \in 0..2
DoorsClosedWhileMoving == movingState /= 0 => doorState = 0
Spec == Init /\ [][Next]_vars
====
'''
    cfg='SPECIFICATION Spec\nINVARIANT TypeOK\nINVARIANT DoorsClosedWhileMoving\nCHECK_DEADLOCK FALSE'
    return tla,cfg

ELEVATOR_CONTROLLER_PLUGIN=DomainPlugin('elevator_controller',recognizes_elevator_controller,
    extract_elevator_controller_model,render_elevator_controller,
    maturity=DomainMaturity.BOUNDED_EVIDENCE,
    evidence_ceiling="BOUNDED_ARCHITECTURE_EVIDENCE",
    maturity_note="Reviewed deterministic source-to-TLA adapter; source refinement remains unproved.")
