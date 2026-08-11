# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Reviewed strict IR for the bounded five-floor elevator controller."""
from typing import Literal
from pydantic import BaseModel, ConfigDict
from ..transition_ir import MethodTransitionIR

Operation = Literal['startMoveUp', 'startMoveDown', 'arriveUp', 'arriveDown',
                    'openDoors', 'closeDoors']
GuardId = Literal['moving_is_stopped', 'door_is_closed', 'door_is_open',
                  'below_top_floor', 'above_bottom_floor', 'moving_is_up',
                  'moving_is_down']
EffectId = Literal['set_moving_up', 'set_moving_down', 'arrive_up_and_stop',
                   'arrive_down_and_stop', 'open_doors', 'close_doors']
FrameId = Literal['current_floor', 'door_state', 'moving_state']

ABSTRACTION_MAPPING = {
    'this.current_floor': 'currentFloor',
    'this.door_state': 'doorState',
    'this.moving_state': 'movingState',
}
INITIAL_STATE = {'this.current_floor': 0, 'this.door_state': 0, 'this.moving_state': 0}
ACTION_REFINEMENTS = {
    'startMoveUp': {'action': 'StartMoveUp',
        'guards': [('this.moving_state', 'eq', 0), ('this.door_state', 'eq', 0),
                   ('this.current_floor', 'lt', 4)],
        'updates': [('this.moving_state', 'constant', 1)]},
    'startMoveDown': {'action': 'StartMoveDown',
        'guards': [('this.moving_state', 'eq', 0), ('this.door_state', 'eq', 0),
                   ('this.current_floor', 'gt', 0)],
        'updates': [('this.moving_state', 'constant', 2)]},
    'arriveUp': {'action': 'ArriveUp', 'guards': [('this.moving_state', 'eq', 1)],
        'updates': [('this.current_floor', 'add_old', 1),
                    ('this.moving_state', 'constant', 0)]},
    'arriveDown': {'action': 'ArriveDown', 'guards': [('this.moving_state', 'eq', 2)],
        'updates': [('this.current_floor', 'sub_old', 1),
                    ('this.moving_state', 'constant', 0)]},
    'openDoors': {'action': 'OpenDoors',
        'guards': [('this.moving_state', 'eq', 0), ('this.door_state', 'eq', 0)],
        'updates': [('this.door_state', 'constant', 1)]},
    'closeDoors': {'action': 'CloseDoors', 'guards': [('this.door_state', 'eq', 1)],
        'updates': [('this.door_state', 'constant', 0)]},
}

class ElevatorControllerOperationIR(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    operation: Operation
    guard_ids: list[GuardId]
    effect_id: EffectId
    frame_ids: list[FrameId]
    result_constrained: bool
    failure_preserves_frame: bool

class ElevatorControllerTlaModel(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    domain: Literal['elevator_controller'] = 'elevator_controller'
    operations: list[ElevatorControllerOperationIR]
    transitions: list[MethodTransitionIR]
    abstraction: Literal['atomic_operations'] = 'atomic_operations'
    execution_assumption: Literal['single_threaded'] = 'single_threaded'
