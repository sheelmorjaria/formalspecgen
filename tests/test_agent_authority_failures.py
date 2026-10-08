# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Invalid supervised goals and interrupted actions cannot widen authority."""
from unittest.mock import Mock
from dataclasses import replace
import json
from pipeline.agentic import state_store

import pytest
from pipeline.agentic.action_gateway import AgentActionGateway
from pipeline.agentic.contracts import AgentRunError
from pipeline.agentic.planner import PlannedAction, next_action
from test_agentic_supervisor import _goal, _admission, _supervisor


@pytest.mark.parametrize('changes,code', [
    ({'run_id': '../escape'}, 'INVALID_GOAL'),
    ({'objective': ''}, 'INVALID_GOAL'),
    ({'base_revision': 'short'}, 'INVALID_BASE_REVISION'),
    ({'source_sha256': 'short'}, 'INVALID_SOURCE_DIGEST'),
    ({'source': '../escape.java'}, 'INVALID_SOURCE'),
    ({'source': '.git/config'}, 'PROTECTED_SOURCE'),
    ({'permitted_workflows': ('verify',)}, 'UNSUPPORTED_PLAN'),
    ({'allowed_paths': ('other.java',)}, 'PATH_SCOPE_DENIED'),
    ({'resource_budget': {'unknown': 1}}, 'INVALID_BUDGET'),
    ({'resource_budget': {'max_actions': -1}}, 'INVALID_BUDGET'),
    ({'resource_budget': {'max_actions': 1}}, 'INVALID_BUDGET'),
    ({'resource_budget': {'max_actions': 2, 'max_failures': 0}}, 'INVALID_BUDGET'),
    ({'resource_budget': {'max_actions': 2, 'max_failures': 1, 'max_input_bytes': 0}}, 'INVALID_BUDGET'),
    ({'acceptance_policy': 'always-accept'}, 'UNSUPPORTED_ACCEPTANCE'),
    ({'task_type': 'merge'}, 'UNSUPPORTED_GOAL'),
])
def test_goal_validation_refuses_unreviewed_authority(tmp_path, changes, code):
    source = tmp_path / 'Probe.java'; source.write_text('class Probe {}')
    with pytest.raises(AgentRunError) as error: replace(_goal(source), **changes)
    assert error.value.code == code
    assert error.value.as_dict()['claim'] == 'NO_PROOF'


@pytest.mark.parametrize('case,code', [('unauthorized', 'ACTION_NOT_AUTHORIZED'),
    ('missing', 'SOURCE_UNAVAILABLE'), ('changed', 'SOURCE_SNAPSHOT_MISMATCH'),
    ('unstructured', 'ACTION_RESULT_INVALID'), ('changes-during-action', 'SOURCE_SNAPSHOT_MISMATCH'),
    ('oversized', 'ACTION_RESULT_LIMIT_EXCEEDED')])
def test_gateway_rejects_unbound_or_invalid_action_results(tmp_path, case, code):
    source = tmp_path / 'Probe.java'; source.write_text('class Probe {}')
    goal = _goal(source)
    inspect = Mock(return_value={'status': 'INSPECTED'})
    if case == 'missing': source.unlink()
    elif case == 'changed': source.write_text('changed')
    elif case == 'unstructured': inspect.return_value = 'not a result'
    elif case == 'changes-during-action':
        def change(_source):
            source.write_text('changed'); return {'status': 'INSPECTED'}
        inspect.side_effect = change
    elif case == 'oversized': inspect.return_value = {'findings': 'x' * (2 * 1024 * 1024)}
    gateway = AgentActionGateway(workspace_root=tmp_path, admission=_admission(), inspect=inspect, verify=Mock())
    with pytest.raises(AgentRunError) as error:
        gateway.execute(goal, PlannedAction(1, 'merge' if case == 'unauthorized' else 'inspect', 'test'))
    assert error.value.code == code
    gateway._verify.assert_not_called()
    if case in {'unauthorized', 'missing', 'changed'}: inspect.assert_not_called()


@pytest.mark.parametrize('record,code', [
    ({'actions': [{'workflow': 'verify', 'state': 'completed'}]}, 'RUN_STATE_INVALID'),
    ({'active_action': {'workflow': 'inspect'}}, 'ACTION_OUTCOME_UNKNOWN'),
    ({'actions': [{'state': 'failed'}, {'state': 'failed'}]}, 'ACTION_BUDGET_EXHAUSTED'),
])
def test_planner_refuses_reordering_uncertain_replay_and_exhausted_budget(tmp_path, record, code):
    source = tmp_path / 'Probe.java'; source.write_text('class Probe {}')
    with pytest.raises(AgentRunError) as error: next_action(_goal(source), record)
    assert error.value.code == code


def test_source_symlink_cannot_escape_goal_workspace(tmp_path):
    source = tmp_path / 'Probe.java'; source.write_text('class Probe {}')
    goal = _goal(source)
    workspace = tmp_path / 'workspace'; workspace.mkdir()
    (workspace / source.name).symlink_to(source)
    with pytest.raises(AgentRunError) as error: goal.source_path(workspace)
    assert error.value.code == 'PATH_SCOPE_DENIED'


def test_completed_run_can_be_read_and_resumed_without_replaying_actions(tmp_path):
    source = tmp_path / 'Probe.java'; source.write_text('class Probe {}')
    inspect, verify = Mock(return_value={'status': 'INSPECTED'}), Mock()
    from test_agentic_supervisor import _result
    verify.return_value = _result()
    supervisor = _supervisor(tmp_path, source, inspect=inspect, verify=verify)
    goal = _goal(source); result = supervisor.start(goal, 'operator')
    assert supervisor.get(goal.run_id, 'operator') == result
    assert supervisor.resume(goal.run_id, 'operator') == result
    cancelled = supervisor.cancel(goal.run_id, 'operator')
    assert cancelled['state'] == 'completed' and cancelled['review'] == result['review']
    assert inspect.call_count == verify.call_count == 1


@pytest.mark.parametrize('kind', ['missing-lock', 'invalid-id', 'malformed-event', 'invalid-record', 'conflicting-goal', 'empty-principal'])
def test_agent_store_rejects_unavailable_or_unbound_state(tmp_path, kind):
    source = tmp_path / 'Probe.java'; source.write_text('class Probe {}')
    goal = _goal(source); store = state_store.AgentRunStore(tmp_path / 'state')
    if kind == 'missing-lock':
        with pytest.raises(AgentRunError) as error: store.get(goal.run_id, 'operator')
        assert error.value.code == 'RUN_STORE_UNAVAILABLE'
        return
    if kind == 'empty-principal':
        with pytest.raises(AgentRunError) as error: store.create(goal, '')
        assert error.value.code == 'RUN_ACCESS_DENIED'
        return
    store.create(goal, 'operator')
    if kind == 'invalid-id':
        with pytest.raises(AgentRunError) as error: store.get('../escape', 'operator')
        assert error.value.code == 'INVALID_GOAL'
    elif kind == 'conflicting-goal':
        with pytest.raises(AgentRunError) as error: store.create(replace(goal, objective='different'), 'operator')
        assert error.value.code == 'IDEMPOTENCY_CONFLICT'
    else:
        event = next(store.runs.rglob('*.json'))
        if kind == 'malformed-event': event.write_text('{')
        else:
            value = json.loads(event.read_text()); value['record'] = None
            value.pop('sha256'); value['sha256'] = state_store.digest(value)
            event.write_text(json.dumps(value))
        with pytest.raises(AgentRunError) as error: store.get(goal.run_id, 'operator')
        assert error.value.code == 'RUN_EVIDENCE_INVALID'
        with pytest.raises(AgentRunError): store.create(goal, 'operator')


def test_review_publication_is_idempotent_but_never_replaces_different_bytes(tmp_path):
    source = tmp_path / 'Probe.java'; source.write_text('class Probe {}')
    goal = _goal(source); store = state_store.AgentRunStore(tmp_path / 'state'); store.create(goal, 'operator')
    first = store.publish_review(goal.run_id, 'operator', {'status': 'blocked'})
    assert store.publish_review(goal.run_id, 'operator', {'status': 'blocked'}) == first
    with pytest.raises(AgentRunError) as error: store.publish_review(goal.run_id, 'operator', {'status': 'completed'})
    assert error.value.code == 'REVIEW_ALREADY_PUBLISHED'
    store.update(goal.run_id, 'operator', lambda record: record.update(review=first))
    from pathlib import Path
    Path(first['path']).unlink()
    with pytest.raises(AgentRunError) as error: store.get(goal.run_id, 'operator')
    assert error.value.code == 'REVIEW_EVIDENCE_INVALID'
