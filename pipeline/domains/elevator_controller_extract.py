# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed JML AST adapter for the reviewed elevator controller."""
from __future__ import annotations
import re
from ..extract_tla_ir import UnsupportedJmlSemantics, extract_method_transition_ir
from ..jml_ast import BinaryExpr, FieldAccess, IntegerLiteral, OldValue
from .elevator_controller import ElevatorControllerOperationIR, ElevatorControllerTlaModel

ORDER = ['startMoveUp', 'startMoveDown', 'arriveUp', 'arriveDown', 'openDoors', 'closeDoors']
_METHOD = re.compile(r'(?P<contracts>(?:\s*//@[^\n]*\n)+)\s*public\s+void\s+'
    r'(?P<name>startMoveUp|startMoveDown|arriveUp|arriveDown|openDoors|closeDoors)'
    r'\s*\((?P<params>[^)]*)\)\s*\{', re.I)
FIELDS = {'current_floor', 'door_state', 'moving_state'}
EXPECTED = {
 'startMoveUp': (['moving_is_stopped','door_is_closed','below_top_floor'], 'set_moving_up', ['moving_state']),
 'startMoveDown': (['moving_is_stopped','door_is_closed','above_bottom_floor'], 'set_moving_down', ['moving_state']),
 'arriveUp': (['moving_is_up'], 'arrive_up_and_stop', ['current_floor','moving_state']),
 'arriveDown': (['moving_is_down'], 'arrive_down_and_stop', ['current_floor','moving_state']),
 'openDoors': (['moving_is_stopped','door_is_closed'], 'open_doors', ['door_state']),
 'closeDoors': (['door_is_open'], 'close_doors', ['door_state']),
}
GUARDS = {('moving_state','eq',0):'moving_is_stopped', ('door_state','eq',0):'door_is_closed',
 ('door_state','eq',1):'door_is_open', ('current_floor','lt',4):'below_top_floor',
 ('current_floor','gt',0):'above_bottom_floor', ('moving_state','eq',1):'moving_is_up',
 ('moving_state','eq',2):'moving_is_down'}

def recognizes_elevator_controller(code: str) -> bool:
    return {m.group('name').lower() for m in _METHOD.finditer(code)} == {x.lower() for x in ORDER}

def _guard(node):
    if not isinstance(node, BinaryExpr): return None
    if isinstance(node.left, FieldAccess) and isinstance(node.right, IntegerLiteral):
        return GUARDS.get((node.left.field,node.kind,node.right.value))
    return None

def _effect_shape(name, effects):
    def constant(effect, field, value):
        return effect.target.field == field and isinstance(effect.value,IntegerLiteral) and effect.value.value == value
    def delta(effect, kind):
        value=effect.value
        return (effect.target.field=='current_floor' and isinstance(value,BinaryExpr) and value.kind==kind and
          isinstance(value.left,OldValue) and isinstance(value.left.expression,FieldAccess) and
          value.left.expression.field=='current_floor' and isinstance(value.right,IntegerLiteral) and value.right.value==1)
    if name=='startMoveUp': return len(effects)==1 and constant(effects[0],'moving_state',1)
    if name=='startMoveDown': return len(effects)==1 and constant(effects[0],'moving_state',2)
    if name=='openDoors': return len(effects)==1 and constant(effects[0],'door_state',1)
    if name=='closeDoors': return len(effects)==1 and constant(effects[0],'door_state',0)
    kind='add' if name=='arriveUp' else 'sub'
    return len(effects)==2 and delta(effects[0],kind) and constant(effects[1],'moving_state',0)

def extract_elevator_controller_model(code: str, clarifications: str, abstraction: str | None):
    del clarifications
    if abstraction not in {None,'atomic_operations'}:
        raise UnsupportedJmlSemantics('Elevator controller supports only atomic_operations')
    constructor=re.search(r'(?P<c>(?:\s*//@[^\n]*\n)+)\s*public\s+ElevatorController\s*\(\s*\)',code)
    if not constructor or all(x not in re.sub(r'\s+','',constructor.group('c')) for x in [
      'current_floor==0&&door_state==0&&moving_state==0',
      'moving_state==0&&door_state==0&&current_floor==0']):
        raise UnsupportedJmlSemantics('Constructor must establish floor 0, closed doors, and stopped motion')
    matches={m.group('name').lower():m for m in _METHOD.finditer(code)}
    if set(matches)!={x.lower() for x in ORDER}:
        raise UnsupportedJmlSemantics('Elevator controller requires all six reviewed void operations')
    operations=[]; transitions=[]; findings=[]
    for name in ORDER:
        match=matches[name.lower()]
        transition=extract_method_transition_ir(name,'void',match.group('params'),match.group('contracts'),FIELDS,
          {'current_floor':'currentFloor','door_state':'doorState','moving_state':'movingState'})
        expected_guards,effect_id,expected_frame=EXPECTED[name]
        guards=[_guard(x) for x in transition.guards]
        frame=[x.field for x in transition.frame if x.receiver=='this']
        if guards!=expected_guards: findings.append({'code':'guard_mismatch','operation':name,'message':f'Expected exactly {expected_guards}, got {guards}'})
        if frame!=expected_frame: findings.append({'code':'frame_mismatch','operation':name,'message':f'Expected exactly {expected_frame}, got {frame}'})
        if not _effect_shape(name,transition.success_effects):
            raise UnsupportedJmlSemantics(f'No reviewed effect mapping for {name}')
        operations.append(ElevatorControllerOperationIR(operation=name,guard_ids=expected_guards if guards==expected_guards else [],
          effect_id=effect_id,frame_ids=expected_frame if frame==expected_frame else [],result_constrained=True,failure_preserves_frame=True))
        transitions.append(transition)
    return ElevatorControllerTlaModel(operations=operations,transitions=transitions),findings
