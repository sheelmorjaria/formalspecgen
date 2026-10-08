# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Verifier success requires bound inputs and recognized proof results."""
import hashlib
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from pipeline import lockfree, weak_memory


MPSC = '''#include <pthread.h>
#include <assert.h>
#define LANES 2
#define CAP 4
#define LANE_CAP 2
int head[LANES] = {0};
int tail[LANES] = {0};
void *p0(void *arg) { head[0] = 1; return 0; }
void *p1(void *arg) { head[1] = 1; return 0; }
int main(void) {
    pthread_t a,b;
    pthread_create(&a,0,p0,0);
    pthread_create(&b,0,p1,0);
    pthread_join(a,0);
    pthread_join(b,0);
    return 0;
}
'''


@pytest.mark.parametrize('output,exit_code,expected', [
    ('Observation Test Never 0 1', 0, 'WEAK_MEMORY_SAFETY_PROVED'),
    ('Observation Test Sometimes 1 1', 0, 'WEAK_MEMORY_COUNTEREXAMPLE'),
    ('Observation Test Always 1 0', 0, 'WEAK_MEMORY_COUNTEREXAMPLE'),
    ('Observation A Never 0 1\nObservation B Sometimes 1 1', 0, 'WEAK_MEMORY_COUNTEREXAMPLE'),
    ('no observations', 0, 'HERD7_RESULT_UNRECOGNIZED'),
    ('Observation Test Never 0 1', 1, 'HERD7_EXECUTION_FAILED'),
])
def test_herd7_requires_recognized_forbidden_outcome(tmp_path, monkeypatch, output, exit_code, expected):
    source = tmp_path / 'test.litmus'
    source.write_bytes(b'C Test\n')
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    monkeypatch.setattr(weak_memory.shutil, 'which', lambda _name: '/tools/herd7')
    run = Mock(return_value=subprocess.CompletedProcess([], exit_code, output, ''))
    monkeypatch.setattr(weak_memory.subprocess, 'run', run)
    result = weak_memory.herd7_model_check(source, 'x86_tso', expected_sha256=digest)
    assert result.get('code', result['status']) == expected
    assert result['litmus_sha256'] == digest
    assert result['output_sha256'] == hashlib.sha256(output.encode()).hexdigest()
    assert result['claim'] == ('WEAK_MEMORY_SAFETY_PROVED' if expected == 'WEAK_MEMORY_SAFETY_PROVED' else 'NO_PROOF')
    assert run.call_args.args[0] == ['/tools/herd7', str(source)]
    assert run.call_args.kwargs['check'] is False


def test_herd7_input_and_execution_boundaries(tmp_path, monkeypatch):
    source = tmp_path / 'test.litmus'
    source.write_text('C Test')
    run = Mock()
    monkeypatch.setattr(weak_memory.subprocess, 'run', run)
    assert weak_memory.herd7_model_check(tmp_path / 'missing', 'x86_tso')['code'] == 'input_unavailable'
    wrong = tmp_path / 'test.c'; wrong.write_text('')
    assert weak_memory.herd7_model_check(wrong, 'x86_tso')['code'] == 'UNSUPPORTED_BOUNDARY'
    assert weak_memory.herd7_model_check(source, 'unknown')['code'] == 'unknown_memory_model'
    assert weak_memory.herd7_model_check(source, 'x86_tso', expected_sha256='a' * 64)['code'] == 'LITMUS_HASH_MISMATCH'
    monkeypatch.setattr(weak_memory.shutil, 'which', lambda _name: None)
    assert weak_memory.herd7_model_check(source, 'x86_tso')['status'] == 'judge_pending'
    run.assert_not_called()
    monkeypatch.setattr(weak_memory.shutil, 'which', lambda _name: '/tools/herd7')
    for error in (OSError('cannot execute'), subprocess.TimeoutExpired('herd7', 60)):
        run.side_effect = error
        assert weak_memory.herd7_model_check(source, 'x86_tso')['code'] == 'HERD7_EXECUTION_FAILED'


@pytest.mark.parametrize('before,after,code', [
    ('#define CAP 4', '#define CAP 5', 'PARTITION_MISMATCH'),
    ('#define LANES 2', '', 'no_mpsc_structure'),
    ('pthread_create(&b,0,p1,0);', '', 'no_thread_harness'),
    ('pthread_join', 'unused_join', 'no_thread_harness'),
    ('head[0] = 1;', '', 'LINEARIZATION_POINT_MISSING'),
    ('head[0] = 1;', 'head[0] = 1; head[0] = 2;', 'LINEARIZATION_MULTIPLE_STORES'),
    ('head[1] = 1;', 'head[0] = 1;', 'LANE_OWNER_CONFLICT'),
    ('head[1] = 1;', 'head[2] = 1;', 'LANE_INDEX_OUT_OF_RANGE'),
    ('head[1] = 1;', 'head[1] = 1; tail[1] = 1;', 'PRODUCER_WRITES_TAIL'),
])
def test_mpsc_rejects_invalid_ownership_before_launch(tmp_path, monkeypatch, before, after, code):
    source = tmp_path / 'queue.c'; source.write_text(MPSC.replace(before, after))
    run = Mock()
    monkeypatch.setattr(lockfree.subprocess, 'run', run)
    result = lockfree.verify_mpsc(source)
    assert result['code'] == code and result['claim'] == 'NO_PROOF'
    run.assert_not_called()


def test_mpsc_injects_capacity_witness_and_limits_claim(tmp_path, monkeypatch):
    source = tmp_path / 'queue.c'; source.write_text(MPSC)
    monkeypatch.setattr(lockfree, 'ESBMC_AVAILABLE', True)

    def prove(command, **kwargs):
        harness = Path(command[1]).read_text()
        for goal in ('head[0] - tail[0] <= 2', 'head[1] - tail[1] <= 2',
                     'head[0] + head[1] - tail[0] - tail[1] <= 4', 'tail[0] <= head[0]'):
            assert goal in harness
        assert command[-2:] == ['--unwind', '5']
        assert kwargs['timeout'] == 300
        return subprocess.CompletedProcess(command, 0, 'VERIFICATION SUCCESSFUL', '')

    monkeypatch.setattr(lockfree.subprocess, 'run', prove)
    result = lockfree.verify_mpsc(source)
    assert result['claim'] == 'MPSC_BOUNDED_PARTITION_PROVED'
    assert result['lane_owners'] == {0: 'p0', 1: 'p1'}
    assert result['progress_proved'] is False
    assert source.read_text() == MPSC
    monkeypatch.setattr(lockfree, 'ESBMC_AVAILABLE', False)
    assert lockfree.verify_mpsc(source)['code'] == 'esbmc_unavailable'
    monkeypatch.setattr(lockfree, 'ESBMC_AVAILABLE', True)
    run = Mock(return_value=subprocess.CompletedProcess([], 1, '', 'counterexample'))
    monkeypatch.setattr(lockfree.subprocess, 'run', run)
    assert lockfree.verify_mpsc(source)['code'] == 'esbmc_verification_failed'
    for error in (OSError('missing'), subprocess.TimeoutExpired('esbmc', 300)):
        run.side_effect = error
        assert lockfree.verify_mpsc(source)['code'] == 'esbmc_timeout'
    assert lockfree.verify_mpsc(tmp_path / 'missing.c')['code'] == 'input_unavailable'
    wrong = tmp_path / 'queue.rs'; wrong.write_text(MPSC)
    assert lockfree.verify_mpsc(wrong)['code'] == 'UNSUPPORTED_BOUNDARY'
