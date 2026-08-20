"""Deterministic TLA+ renderer for the reviewed traffic-light controller."""
from ..extract_tla_ir import UnsupportedJmlSemantics
from .traffic_light_controller import (
    ABSTRACTION_MAPPING, ACTION_REFINEMENTS, INITIAL_STATE,
    TrafficLightControllerTlaModel,
)
from .traffic_light_controller_extract import extract_traffic_light_controller_model, recognizes_traffic_light_controller
from .router import DomainMaturity, DomainPlugin

STATE_VARIABLES = 'ns_light, ew_light'
CFG_INVARIANTS = 'INVARIANT NoSimultaneousGreenLights'

def render_traffic_light_controller(model: TrafficLightControllerTlaModel) -> tuple[str, str]:
    expected = {'turnNsGreen', 'turnNsYellow', 'turnNsRed',
                'turnEwGreen', 'turnEwYellow', 'turnEwRed'}
    if model is None or {item.operation for item in model.operations} != expected:
        raise UnsupportedJmlSemantics('Incomplete traffic-light operation set')
    def variable(java_location: str) -> str:
        return ABSTRACTION_MAPPING[java_location]

    actions = []
    for method in ('turnNsGreen', 'turnNsYellow', 'turnNsRed',
                   'turnEwGreen', 'turnEwYellow', 'turnEwRed'):
        spec = ACTION_REFINEMENTS[method]
        guard_location, guard_value = spec['guard']
        update_location, update_value = spec['update']
        unchanged = next(value for key, value in ABSTRACTION_MAPPING.items()
                         if key != update_location)
        actions.append(
            f"{spec['action']} == /\\ {variable(guard_location)} = {guard_value} "
            f"/\\ {variable(update_location)}' = {update_value} /\\ UNCHANGED {unchanged}")
    action_definitions = '\n'.join(actions)
    next_actions = '\n'.join(
        f"    \\/ {ACTION_REFINEMENTS[name]['action']}" for name in
        ('turnNsGreen', 'turnNsYellow', 'turnNsRed',
         'turnEwGreen', 'turnEwYellow', 'turnEwRed'))
    init = ' /\\ '.join(
        f"{ABSTRACTION_MAPPING[location]} = {value}"
        for location, value in INITIAL_STATE.items())
    tla = rf'''---- MODULE TrafficLightController ----
EXTENDS Naturals

VARIABLES nsLight, ewLight
vars == <<nsLight, ewLight>>

Init == /\ {init}

{action_definitions}

Next ==
{next_actions}

TypeOK == /\ nsLight \in 0..2 /\ ewLight \in 0..2
NoSimultaneousGreenLights == ~(nsLight = 2 /\ ewLight = 2)
Spec == Init /\ [][Next]_vars
===='''
    cfg = '''SPECIFICATION Spec
INVARIANT TypeOK
INVARIANT NoSimultaneousGreenLights
CHECK_DEADLOCK FALSE'''
    return tla, cfg

TRAFFIC_LIGHT_CONTROLLER_PLUGIN = DomainPlugin(
    'traffic_light_controller', recognizes_traffic_light_controller,
    extract_traffic_light_controller_model, render_traffic_light_controller,
    maturity=DomainMaturity.BOUNDED_EVIDENCE,
    evidence_ceiling="BOUNDED_ARCHITECTURE_EVIDENCE",
    maturity_note="Reviewed deterministic source-to-TLA adapter; source refinement remains unproved.")
