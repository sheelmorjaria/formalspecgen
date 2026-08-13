"""Generated recognizer and fail-closed adapter skeleton for RobotVacuumController."""
import re
from ..extract_tla_ir import UnsupportedJmlSemantics
from .robot_vacuum_controller import RobotVacuumControllerTlaModel

REQUIRED_METHODS = ['startcleaning', 'stopcleaning', 'dock']

def recognizes_robot_vacuum_controller(code: str) -> bool:
    lowered = code.lower()
    return all(re.search(rf"\b{name}\s*\(", lowered) for name in REQUIRED_METHODS)

def extract_robot_vacuum_controller_model(code: str, clarifications: str, abstraction: str | None):
    del code, clarifications, abstraction
    # Reviewed AST patterns declared by the domain specification:
    # - startCleaning: vacuum_mode == 1 && battery_level > 0
    # - stopCleaning: vacuum_mode == 0 && battery_level >= 1
    # - dock: vacuum_mode == 0 && battery_level == 5
    # TODO: parse methods with extract_method_transition_ir, structurally match every
    # effect/guard/frame, construct RobotVacuumControllerOperationIR values, then return
    # (RobotVacuumControllerTlaModel(...), findings).
    raise UnsupportedJmlSemantics(
        "robot_vacuum_controller plugin is scaffolded but its AST adapter is not reviewed")
