# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Strict semantic IR for the reviewed train-road crossing controller."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from ..transition_ir import MethodTransitionIR

Operation = Literal[
    "trainApproaches", "lowerGate", "trainEnters", "trainLeaves",
    "raiseGate", "carCrosses", "carLeaves",
]
GuardId = Literal[
    "train_is_away", "train_is_approaching", "train_is_crossing", "train_is_past",
    "gate_is_up", "gate_is_down", "car_is_waiting", "car_is_crossing",
    "crossing_is_clear",
]
EffectId = Literal[
    "move_train_approaching", "set_gate_down", "move_train_crossing",
    "move_train_past", "set_gate_up", "move_car_crossing", "move_car_waiting",
]
FrameId = Literal["train_pos", "gate_state", "car_pos"]


class TrainRoadCrossingOperationIR(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: Operation
    guard_ids: list[GuardId]
    effect_id: EffectId
    frame_ids: list[FrameId]


class TrainRoadCrossingTlaModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    domain: Literal["train_crossing"] = "train_crossing"
    operations: list[TrainRoadCrossingOperationIR]
    transitions: list[MethodTransitionIR]

    @model_validator(mode="after")
    def complete_api(self) -> "TrainRoadCrossingTlaModel":
        expected = ["trainApproaches", "lowerGate", "trainEnters", "trainLeaves",
                    "raiseGate", "carCrosses", "carLeaves"]
        if [item.operation for item in self.operations] != expected:
            raise ValueError("train-crossing operations are incomplete or out of order")
        if [item.name for item in self.transitions] != expected:
            raise ValueError("transition evidence does not correspond to operations")
        semantics = {
            "trainApproaches": ("move_train_approaching", ["train_pos"]),
            "lowerGate": ("set_gate_down", ["gate_state"]),
            "trainEnters": ("move_train_crossing", ["train_pos"]),
            "trainLeaves": ("move_train_past", ["train_pos"]),
            "raiseGate": ("set_gate_up", ["gate_state"]),
            "carCrosses": ("move_car_crossing", ["car_pos"]),
            "carLeaves": ("move_car_waiting", ["car_pos"]),
        }
        for operation in self.operations:
            effect, frame = semantics[operation.operation]
            if operation.effect_id != effect or operation.frame_ids != frame:
                raise ValueError(f"invalid semantic mapping for {operation.operation}")
        return self
