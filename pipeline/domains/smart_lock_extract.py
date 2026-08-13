"""Generated recognizer and fail-closed adapter skeleton for SmartLock."""
import re
from ..extract_tla_ir import UnsupportedJmlSemantics
from .smart_lock import SmartLockTlaModel

REQUIRED_METHODS = ['closedoor', 'opendoor', 'lockdoor', 'unlockdoor']

def recognizes_smart_lock(code: str) -> bool:
    lowered = code.lower()
    return all(re.search(rf"\b{name}\s*\(", lowered) for name in REQUIRED_METHODS)

def extract_smart_lock_model(code: str, clarifications: str, abstraction: str | None):
    del code, clarifications, abstraction
    # Reviewed AST patterns declared by the domain specification:
    # - CloseDoor: door_state == 1
    # - OpenDoor: door_state == 0
    # - LockDoor: lock_state == 1
    # - UnlockDoor: lock_state == 0
    # TODO: parse methods with extract_method_transition_ir, structurally match every
    # effect/guard/frame, construct SmartLockOperationIR values, then return
    # (SmartLockTlaModel(...), findings).
    raise UnsupportedJmlSemantics(
        "smart_lock plugin is scaffolded but its AST adapter is not reviewed")
