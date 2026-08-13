"""Generated strict IR for SmartLock; edit only after review."""
from typing import Literal
from pydantic import BaseModel, ConfigDict
from ..transition_ir import MethodTransitionIR

Operation = Literal['CloseDoor', 'OpenDoor', 'LockDoor', 'UnlockDoor']
GuardId = Literal['door_is_closed', 'door_is_open', 'lock_is_locked', 'lock_is_unlocked']
EffectId = Literal['set_door_state_closed', 'set_door_state_open', 'set_lock_state_locked', 'set_lock_state_unlocked']
FrameId = Literal['door_state', 'lock_state']

class SmartLockOperationIR(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: Operation
    guard_ids: list[GuardId]
    effect_id: EffectId
    frame_ids: list[FrameId]
    result_constrained: bool
    failure_preserves_frame: bool

class SmartLockTlaModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    domain: Literal['smart_lock'] = 'smart_lock'
    operations: list[SmartLockOperationIR]
    transitions: list[MethodTransitionIR]
