"""Generated fail-closed renderer skeleton for RobotVacuumController."""
from ..extract_tla_ir import UnsupportedJmlSemantics
from .robot_vacuum_controller import RobotVacuumControllerTlaModel
from .robot_vacuum_controller_extract import extract_robot_vacuum_controller_model, recognizes_robot_vacuum_controller
from .router import DomainPlugin

STATE_VARIABLES = 'battery_level, vacuum_mode'
CFG_INVARIANTS = 'INVARIANT BatteryLevelBounds\nINVARIANT VacuumModeBounds\nINVARIANT NoCleaningWithDeadBattery'

def render_robot_vacuum_controller(model: RobotVacuumControllerTlaModel) -> tuple[str, str]:
    del model
    # TODO: implement reviewed complete-variable assignments, Init, Next, bounds,
    # invariants, Spec, and separate CFG serialization. Never interpolate AST strings.
    raise UnsupportedJmlSemantics(
        "robot_vacuum_controller plugin is scaffolded but its TLA+ renderer is not reviewed")

ROBOT_VACUUM_CONTROLLER_PLUGIN = DomainPlugin(
    'robot_vacuum_controller', recognizes_robot_vacuum_controller,
    extract_robot_vacuum_controller_model, render_robot_vacuum_controller)
