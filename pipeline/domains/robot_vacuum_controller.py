"""Generated strict IR for RobotVacuumController; edit only after review."""
from typing import Literal
from pydantic import BaseModel, ConfigDict
from ..transition_ir import MethodTransitionIR

Operation = Literal['startCleaning', 'stopCleaning', 'dock']
GuardId = Literal['battery_level_is_positive', 'vacuum_mode_is_cleaning', 'vacuum_mode_is_docked']
EffectId = Literal['set_vacuum_mode_cleaning', 'set_battery_level_decrease', 'set_battery_level_recharge']
FrameId = Literal['battery_level', 'vacuum_mode']

class RobotVacuumControllerOperationIR(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: Operation
    guard_ids: list[GuardId]
    effect_id: EffectId
    frame_ids: list[FrameId]
    result_constrained: bool
    failure_preserves_frame: bool

class RobotVacuumControllerTlaModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    domain: Literal['robot_vacuum_controller'] = 'robot_vacuum_controller'
    operations: list[RobotVacuumControllerOperationIR]
    transitions: list[MethodTransitionIR]
