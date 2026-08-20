"""Generated fail-closed renderer skeleton for SmartLock."""
from ..extract_tla_ir import UnsupportedJmlSemantics
from .smart_lock import SmartLockTlaModel
from .smart_lock_extract import extract_smart_lock_model, recognizes_smart_lock
from .router import DomainMaturity, DomainPlugin

STATE_VARIABLES = 'door_state, lock_state'
CFG_INVARIANTS = 'INVARIANT DoorOpenImpliesLockUnlocked'

def render_smart_lock(model: SmartLockTlaModel) -> tuple[str, str]:
    del model
    # TODO: implement reviewed complete-variable assignments, Init, Next, bounds,
    # invariants, Spec, and separate CFG serialization. Never interpolate AST strings.
    raise UnsupportedJmlSemantics(
        "smart_lock plugin is scaffolded but its TLA+ renderer is not reviewed")

SMART_LOCK_PLUGIN = DomainPlugin(
    'smart_lock', recognizes_smart_lock,
    extract_smart_lock_model, render_smart_lock,
    maturity=DomainMaturity.SCAFFOLD, evidence_ceiling="NO_PROOF",
    maturity_note="AST extractor and TLA renderer contain review-blocking TODOs.")
