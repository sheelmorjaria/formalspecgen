"""Reviewed strict IR for the bounded traffic-light controller."""
from typing import Literal
from pydantic import BaseModel, ConfigDict
from ..transition_ir import MethodTransitionIR

Operation = Literal['turnNsGreen', 'turnNsYellow', 'turnNsRed', 'turnEwGreen', 'turnEwYellow', 'turnEwRed']
GuardId = Literal['ew_is_green', 'ew_is_red', 'ew_is_yellow', 'ns_is_green', 'ns_is_red', 'ns_is_yellow']
EffectId = Literal['set_ns_green', 'set_ns_yellow', 'set_ns_red', 'set_ew_green', 'set_ew_yellow', 'set_ew_red']
FrameId = Literal['ns_light', 'ew_light']

# This reviewed table is the single semantic source used by both deterministic
# TLA+ serialization and the refinement checker.
ABSTRACTION_MAPPING = {'this.ns_light': 'nsLight', 'this.ew_light': 'ewLight'}
INITIAL_STATE = {'this.ns_light': 0, 'this.ew_light': 0}
ACTION_REFINEMENTS = {
    'turnNsGreen': {'action': 'TurnNsGreen', 'guard': ('this.ew_light', 0),
                    'update': ('this.ns_light', 2)},
    'turnNsYellow': {'action': 'TurnNsYellow', 'guard': ('this.ns_light', 2),
                     'update': ('this.ns_light', 1)},
    'turnNsRed': {'action': 'TurnNsRed', 'guard': ('this.ns_light', 1),
                  'update': ('this.ns_light', 0)},
    'turnEwGreen': {'action': 'TurnEwGreen', 'guard': ('this.ns_light', 0),
                    'update': ('this.ew_light', 2)},
    'turnEwYellow': {'action': 'TurnEwYellow', 'guard': ('this.ew_light', 2),
                     'update': ('this.ew_light', 1)},
    'turnEwRed': {'action': 'TurnEwRed', 'guard': ('this.ew_light', 1),
                  'update': ('this.ew_light', 0)},
}

class TrafficLightControllerOperationIR(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: Operation
    guard_ids: list[GuardId]
    effect_id: EffectId
    frame_ids: list[FrameId]
    result_constrained: bool
    failure_preserves_frame: bool

class TrafficLightControllerTlaModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    domain: Literal['traffic_light_controller'] = 'traffic_light_controller'
    operations: list[TrafficLightControllerOperationIR]
    transitions: list[MethodTransitionIR]
    abstraction: Literal['atomic_operations'] = 'atomic_operations'
    execution_assumption: Literal['single_threaded'] = 'single_threaded'
