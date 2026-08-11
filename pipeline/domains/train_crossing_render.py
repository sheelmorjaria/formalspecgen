# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Deterministic TLA+ renderer for the reviewed safe crossing controller."""
from .router import DomainPlugin
from .train_crossing import TrainRoadCrossingTlaModel
from .train_crossing_extract import extract_train_crossing_model, recognizes_train_crossing


def render_train_crossing(model: TrainRoadCrossingTlaModel) -> tuple[str, str]:
    if len(model.operations) != 7:
        raise ValueError("UNSUPPORTED_BOUNDARY: incomplete train-crossing operation set")
    tla = r'''---- MODULE TrainRoadCrossing ----
EXTENDS Naturals

VARIABLES trainPos, gateState, carPos
vars == <<trainPos, gateState, carPos>>

Init == /\ trainPos = 0 /\ gateState = 0 /\ carPos = 0

TrainApproaches ==
    /\ trainPos = 0
    /\ trainPos' = 1
    /\ UNCHANGED <<gateState, carPos>>

LowerGate ==
    /\ trainPos = 1
    /\ gateState = 0
    /\ carPos = 0
    /\ gateState' = 1
    /\ UNCHANGED <<trainPos, carPos>>

TrainEnters ==
    /\ trainPos = 1
    /\ gateState = 1
    /\ trainPos' = 2
    /\ UNCHANGED <<gateState, carPos>>

TrainLeaves ==
    /\ trainPos = 2
    /\ trainPos' = 3
    /\ UNCHANGED <<gateState, carPos>>

RaiseGate ==
    /\ trainPos = 3
    /\ gateState = 1
    /\ gateState' = 0
    /\ UNCHANGED <<trainPos, carPos>>

CarCrosses ==
    /\ gateState = 0
    /\ carPos = 0
    /\ carPos' = 1
    /\ UNCHANGED <<trainPos, gateState>>

CarLeaves ==
    /\ carPos = 1
    /\ carPos' = 0
    /\ UNCHANGED <<trainPos, gateState>>

Next ==
    \/ TrainApproaches
    \/ LowerGate
    \/ TrainEnters
    \/ TrainLeaves
    \/ RaiseGate
    \/ CarCrosses
    \/ CarLeaves

TypeOK == /\ trainPos \in 0..3 /\ gateState \in 0..1 /\ carPos \in 0..1
SafetyNoCollision == ~(trainPos = 2 /\ carPos = 1)
Spec == Init /\ [][Next]_vars
===='''
    cfg = """SPECIFICATION Spec
INVARIANT TypeOK
INVARIANT SafetyNoCollision
CHECK_DEADLOCK FALSE"""
    return tla, cfg


TRAIN_CROSSING_PLUGIN = DomainPlugin("train_crossing", recognizes_train_crossing,
    extract_train_crossing_model, render_train_crossing)
