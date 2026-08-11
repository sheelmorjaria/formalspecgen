# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import unittest
from unittest.mock import patch
from pipeline.canonical_contracts import canonical_elevator_contract
from pipeline.domains.elevator_controller_extract import (
    UnsupportedJmlSemantics, extract_elevator_controller_model,
    recognizes_elevator_controller)
from pipeline.domains.elevator_controller_render import render_elevator_controller
from pipeline.canonical_contracts import CanonicalContractConflict
from pipeline.assurance import refinement_gate

class ElevatorControllerDomainTests(unittest.TestCase):
    def setUp(self):
        self.code, _ = canonical_elevator_contract(
            'Design an elevator system with 5 floors and doors closed while moving')

    def test_canonical_api_extracts_and_renders(self):
        self.assertTrue(recognizes_elevator_controller(self.code))
        model, findings = extract_elevator_controller_model(
            self.code, '', 'atomic_operations')
        self.assertEqual(findings, [])
        self.assertEqual(len(model.operations), 6)
        tla, cfg = render_elevator_controller(model)
        self.assertIn('ArriveUp ==', tla)
        self.assertIn('DoorsClosedWhileMoving', cfg)

    def test_refinement_gate_proves_six_reviewed_action_simulations(self):
        model, _ = extract_elevator_controller_model(
            self.code, '', 'atomic_operations')
        tla, _ = render_elevator_controller(model)
        evidence = {'status': 'VERIFIED', 'domain': 'elevator_controller',
                    'ir': model.model_dump(), 'tla': tla,
                    'provenance': {'execution_assumption': 'single_threaded',
                                   'ir_sha256': 'test-ir'}}
        result = refinement_gate(self.code, self.code, evidence, esc_verified=True)
        self.assertEqual(result['status'], 'VERIFIED')
        self.assertEqual(result['claim'], 'SOURCE_MODEL_REFINEMENT')
        self.assertEqual(len(result['obligations']), 7)
        self.assertFalse(result['concurrent_linearizability_proved'])

        drifted = dict(evidence, tla=tla.replace("doorState' = 1", "doorState' = 0"))
        failed = refinement_gate(self.code, self.code, drifted, esc_verified=True)
        self.assertEqual(failed['code'], 'refinement_obligation_failed')

        bad_ir = dict(evidence, ir={})
        self.assertEqual(refinement_gate(
            self.code, self.code, bad_ir, esc_verified=True)['code'],
            'architecture_ir_mismatch')

    def test_refinement_gate_internal_fail_closed_paths(self):
        model, _ = extract_elevator_controller_model(self.code, '', 'atomic_operations')
        tla, _ = render_elevator_controller(model)
        evidence = {'status': 'VERIFIED', 'domain': 'elevator_controller',
                    'ir': model.model_dump(), 'tla': tla,
                    'provenance': {'execution_assumption': 'single_threaded'}}
        with patch('pipeline.domains.elevator_controller_extract.extract_elevator_controller_model',
                   side_effect=UnsupportedJmlSemantics('bad AST')):
            self.assertEqual(refinement_gate(
                self.code, self.code, evidence, esc_verified=True)['code'],
                'unsupported_jml_semantics')
        with patch('pipeline.domains.elevator_controller_extract.extract_elevator_controller_model',
                   return_value=(model, [{'code': 'guard_mismatch'}])):
            self.assertEqual(refinement_gate(
                self.code, self.code, evidence, esc_verified=True)['code'],
                'contract_model_inconsistent')
        changed = model.model_copy(update={'operations': model.operations[:-1]})
        with patch('pipeline.domains.elevator_controller_extract.extract_elevator_controller_model',
                   side_effect=[(model, []), (changed, [])]):
            self.assertEqual(refinement_gate(
                self.code, self.code, evidence, esc_verified=True)['code'],
                'trusted_contract_changed')
        with patch('pipeline.domains.elevator_controller.ABSTRACTION_MAPPING',
                   {'this.current_floor': 'state', 'this.door_state': 'state',
                    'this.moving_state': 'motion'}):
            self.assertEqual(refinement_gate(
                self.code, self.code, evidence, esc_verified=True)['code'],
                'invalid_abstraction_mapping')
        duplicate = {key: dict(value) for key, value in
                     __import__('pipeline.domains.elevator_controller', fromlist=['ACTION_REFINEMENTS']).ACTION_REFINEMENTS.items()}
        duplicate['closeDoors']['action'] = duplicate['openDoors']['action']
        with patch('pipeline.domains.elevator_controller.ACTION_REFINEMENTS', duplicate):
            self.assertEqual(refinement_gate(
                self.code, self.code, evidence, esc_verified=True)['code'],
                'duplicate_tla_action')
        missing = {key: value for key, value in duplicate.items() if key != 'closeDoors'}
        with patch('pipeline.domains.elevator_controller.ACTION_REFINEMENTS', missing):
            self.assertEqual(refinement_gate(
                self.code, self.code, evidence, esc_verified=True)['code'],
                'operation_coverage_mismatch')

    def test_open_doors_guard_mutation_fails_consistency(self):
        weakened = self.code.replace(
            '    //@ requires moving_state == 0;\n    //@ requires door_state == 0;\n'
            '    //@ assignable door_state;\n    //@ ensures door_state == 1;',
            '    //@ requires door_state == 0;\n    //@ assignable door_state;\n'
            '    //@ ensures door_state == 1;')
        _model, findings = extract_elevator_controller_model(
            weakened, '', 'atomic_operations')
        self.assertTrue(any(item['code'] == 'guard_mismatch' and
                            item['operation'] == 'openDoors' for item in findings))

    def test_missing_operation_and_wrong_abstraction_fail_closed(self):
        incomplete = self.code.replace('public void closeDoors() {}',
                                       'public void closeDoor() {}')
        self.assertFalse(recognizes_elevator_controller(incomplete))
        with self.assertRaisesRegex(UnsupportedJmlSemantics, 'all six'):
            extract_elevator_controller_model(incomplete, '', None)
        with self.assertRaisesRegex(UnsupportedJmlSemantics, 'atomic_operations'):
            extract_elevator_controller_model(self.code, '', 'lock_protocol')

    def test_constructor_effect_and_renderer_boundaries_fail_closed(self):
        without_constructor = self.code.replace(
            '//@ ensures current_floor == 0 && door_state == 0 && moving_state == 0;',
            '//@ ensures current_floor == 1 && door_state == 0 && moving_state == 0;')
        with self.assertRaisesRegex(UnsupportedJmlSemantics, 'Constructor'):
            extract_elevator_controller_model(without_constructor, '', None)
        wrong_effect = self.code.replace(
            '//@ ensures moving_state == 1;\n    public void startMoveUp()',
            '//@ ensures moving_state == 2;\n    public void startMoveUp()')
        with self.assertRaisesRegex(UnsupportedJmlSemantics, 'startMoveUp'):
            extract_elevator_controller_model(wrong_effect, '', None)
        with self.assertRaisesRegex(UnsupportedJmlSemantics, 'Incomplete'):
            render_elevator_controller(None)

    def test_canonical_requirement_conflicts_fail_closed(self):
        from pipeline.canonical_contracts import canonical_elevator_contract
        with self.assertRaisesRegex(CanonicalContractConflict, 'elevator requirement'):
            canonical_elevator_contract('Design a counter')
        with self.assertRaisesRegex(CanonicalContractConflict, 'exactly five'):
            canonical_elevator_contract('Design an elevator with six floors')

if __name__ == '__main__':
    unittest.main()
