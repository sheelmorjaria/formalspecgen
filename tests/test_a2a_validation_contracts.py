# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Worker grants and stored references never widen authority."""
import json
from dataclasses import replace
from datetime import datetime, timezone
import threading
from unittest.mock import Mock

import pytest
from pipeline import a2a_coordination as a2a
from test_a2a_coordination import _coordinator, _item, REVISION
from test_a2a_coordination import LostReplyClient


@pytest.mark.parametrize('changes,code', [
    ({'work_item_id': '../escape'}, 'INVALID_WORK_ITEM'),
    ({'base_revision': 'short'}, 'INVALID_BASE_REVISION'),
    ({'objective': ''}, 'INVALID_WORK_ITEM'),
    ({'objective': 'a' * 8193}, 'INVALID_WORK_ITEM'),
    ({'workflow': '../bad'}, 'INVALID_WORK_ITEM'),
    ({'acceptance_plan_ref': ''}, 'INVALID_WORK_ITEM'),
    ({'authority_ref': ''}, 'INVALID_WORK_ITEM'),
    ({'allowed_paths': ()}, 'INVALID_WORK_ITEM'),
    ({'allowed_paths': ('../escape',)}, 'INVALID_PATH_SCOPE'),
    ({'allowed_paths': ('.git/**',)}, 'PROTECTED_PATH_SCOPE'),
    ({'allowed_paths': ('pipeline/*.py',)}, 'INVALID_PATH_SCOPE'),
    ({'requested_effects': ('unlimited',)}, 'UNKNOWN_EFFECT'),
    ({'deliverables': ()}, 'INVALID_WORK_ITEM'),
    ({'deliverables': ('secret',)}, 'INVALID_WORK_ITEM'),
    ({'resource_budget': {'wall_seconds': -1}}, 'INVALID_BUDGET'),
    ({'resource_budget': {'wall_seconds': '60'}}, 'INVALID_BUDGET'),
    ({'resource_budget': {'bad/key': 1}}, 'INVALID_BUDGET'),
    ({'parent_work_item_id': 'rust-worker-001'}, 'INVALID_WORK_ITEM'),
    ({'parent_work_item_id': '../parent'}, 'INVALID_WORK_ITEM'),
])
def test_invalid_work_is_rejected_before_persistence(changes, code):
    with pytest.raises(a2a.A2ACoordinationError) as error:
        _item(**changes)
    assert error.value.code == code
    assert error.value.as_dict()['claim'] == 'NO_PROOF'


@pytest.mark.parametrize('kind,changes', [
    ('grant', {'effects': ('unknown',)}),
    ('grant', {'expires_at': 'invalid'}),
    ('grant', {'expires_at': '2026-01-01T00:00:00'}),
    ('worker', {'endpoint': 'http://public.example'}),
    ('worker', {'agent_card_sha256': 'short'}),
    ('worker', {'effects': ('unknown',)}),
])
def test_invalid_policy_identity_is_rejected(tmp_path, kind, changes):
    coordinator, _ = _coordinator(tmp_path)
    value = (coordinator.policy.authorities['grant-001'] if kind == 'grant'
             else coordinator.policy.workers['rust-worker'])
    with pytest.raises(a2a.A2ACoordinationError) as error:
        replace(value, **changes)
    assert error.value.code == 'POLICY_INVALID'


def test_policy_load_preserves_grants_and_rejects_duplicate_identities(tmp_path):
    coordinator, _ = _coordinator(tmp_path)
    grant = coordinator.policy.authorities['grant-001']
    worker = coordinator.policy.workers['rust-worker']
    policy = tmp_path / 'policy.json'
    value = {'schema': a2a.COORDINATION_POLICY_SCHEMA,
             'authorities': [grant.as_dict()], 'workers': [worker.as_dict()]}
    policy.write_text(json.dumps(value))
    loaded = a2a.CoordinationPolicy.load(policy)
    assert loaded.authorities[grant.ref] == grant
    assert loaded.workers[worker.worker_id] == worker
    for key in ('authorities', 'workers'):
        invalid = {**value, key: value[key] * 2}
        policy.write_text(json.dumps(invalid))
        with pytest.raises(a2a.A2ACoordinationError) as error:
            a2a.CoordinationPolicy.load(policy)
        assert error.value.code == 'POLICY_INVALID'
    policy.write_text('{}')
    with pytest.raises(a2a.A2ACoordinationError) as error:
        a2a.CoordinationPolicy.load(policy)
    assert error.value.code == 'POLICY_INVALID'
    policy.write_text('{')
    with pytest.raises(a2a.A2ACoordinationError) as error:
        a2a.CoordinationPolicy.load(policy)
    assert error.value.code == 'POLICY_UNAVAILABLE'


@pytest.mark.parametrize('changes', [
    {'schema': 'wrong'}, {'work_item_id': 'other'}, {'base_revision': 'b' * 40},
    {'patch_sha256': 'invalid'}, {'changed_files': 'pipeline/worker.py'},
    {'artifacts': {}}, {'artifacts': [None]},
    {'artifacts': [{'artifact_id': '../bad', 'sha256': 'c' * 64}]},
    {'artifacts': [{'artifact_id': 'patch', 'sha256': 'bad'}]},
])
def test_worker_result_references_must_bind_request(changes):
    item = _item()
    value = {'schema': a2a.WORKER_RESULT_SCHEMA, 'work_item_id': item.work_item_id,
             'base_revision': item.base_revision, 'changed_files': [], 'artifacts': []}
    with pytest.raises(a2a.A2ACoordinationError) as error:
        a2a.A2ACoordinator._validate_result(item, {**value, **changes})
    assert error.value.code == 'WORKER_RESULT_INVALID'


@pytest.mark.parametrize('restriction', ['project', 'worker', 'workflow', 'effects', 'paths', 'budget'])
def test_authority_limits_prevent_remote_dispatch(tmp_path, restriction):
    coordinator, client = _coordinator(tmp_path)
    item = _item()
    worker_id = None
    grant = coordinator.policy.authorities['grant-001']
    if restriction == 'project':
        grant = replace(grant, project_root=tmp_path / 'other')
    elif restriction == 'worker':
        worker_id = 'missing'
    elif restriction == 'workflow':
        item = _item(workflow='unknown')
    elif restriction == 'effects':
        item = _item(requested_effects=('external_execution',))
    elif restriction == 'paths':
        item = _item(allowed_paths=('outside/**',))
    else:
        item = _item(resource_budget={'unallocated': 1})
    coordinator.policy = a2a.CoordinationPolicy({grant.ref: grant}, coordinator.policy.workers)
    with pytest.raises(a2a.A2ACoordinationError) as error:
        coordinator.submit(item, 'aiderdesk', worker_id)
    assert error.value.code == ('BUDGET_DENIED' if restriction == 'budget' else 'AUTHORITY_DENIED')
    assert client.calls == [] and list(coordinator.store.tasks.iterdir()) == []


@pytest.mark.parametrize('layout', ['detached', 'loose', 'packed', 'worktree', 'bad-head', 'bad-git', 'unresolved'])
def test_git_revision_binding_without_subprocess(tmp_path, layout):
    git = tmp_path / '.git'
    if layout == 'bad-git':
        git.write_text('not a gitdir')
    else:
        if layout == 'worktree':
            git.write_text('gitdir: actual-git')
            git = tmp_path / 'actual-git'
        git.mkdir()
        (git / 'HEAD').write_text(REVISION if layout == 'detached' else
                                 ('invalid' if layout == 'bad-head' else 'ref: refs/heads/main'))
        if layout in {'loose', 'worktree'}:
            (git / 'refs/heads').mkdir(parents=True)
            (git / 'refs/heads/main').write_text(REVISION)
        if layout == 'packed':
            (git / 'packed-refs').write_text('# packed\n\n^peeled\n' + 'b' * 40 + ' refs/heads/other\n' + REVISION + ' refs/heads/main\n')
    if layout in {'bad-head', 'bad-git', 'unresolved'}:
        with pytest.raises(a2a.A2ACoordinationError) as error:
            a2a.current_git_revision(tmp_path)
        assert error.value.code == 'REVISION_UNAVAILABLE'
    else:
        assert a2a.current_git_revision(tmp_path) == REVISION


@pytest.mark.parametrize('lease', ['invalid', '2026-01-01T00:00:00'])
def test_malformed_dispatch_lease_cannot_authorize_recovery(lease):
    with pytest.raises(a2a.A2ACoordinationError) as error:
        a2a.TaskStore._lease_expired(lease, datetime.now(timezone.utc))
    assert error.value.code == 'TASK_EVIDENCE_INVALID'


@pytest.mark.parametrize('changes', [{'dispatch_lease_seconds': 0}, {'dispatch_lease_seconds': float('inf')}, {'coordinator_id': '../bad'}])
def test_invalid_coordinator_identity_or_lease_cannot_start(tmp_path, changes):
    coordinator, client = _coordinator(tmp_path)
    with pytest.raises(ValueError):
        a2a.A2ACoordinator(coordinator.policy, coordinator.store, client, project_root=tmp_path, **changes)
    assert client.calls == []


@pytest.mark.parametrize('reply', ['absent', 'failure', 'invalid-state'])
def test_recovery_failure_reserves_task_and_never_accepts_proposal(tmp_path, reply):
    client = LostReplyClient(); coordinator, _ = _coordinator(tmp_path, client)
    item = _item(); coordinator.submit(item, 'aiderdesk')
    if reply == 'failure':
        def reconcile(*_args): raise TimeoutError('reconcile failed')
        client.reconcile = reconcile
    elif reply == 'invalid-state':
        client.reconciliation = a2a.RemoteTaskObservation('remote-1', 'unknown')
    result = coordinator.get(item.work_item_id, 'aiderdesk')
    assert result['state'] == 'dispatch_uncertain'
    assert result['acceptance'] == {'status': 'pending', 'claim': 'NO_PROOF'}
    assert result['worker_outcome']['code'] in {'WORKER_UNAVAILABLE', 'REMOTE_TASK_NOT_OBSERVED', 'WORKER_RESULT_INVALID'}


def test_recovery_without_attempt_id_has_stable_identity_and_exclusive_lease(tmp_path):
    store = a2a.TaskStore(tmp_path / 'state')
    store.create({'work_item_id': 'work', 'principal_id': 'operator', 'state': 'dispatch_uncertain',
                  'dispatch_state': 'uncertain', 'request_sha256': 'a' * 64})
    record, claimed = store.claim_reconciliation('work', 'operator', owner_id='first', lease_seconds=60)
    assert claimed and record['dispatch_attempt_id']
    again, claimed = store.claim_reconciliation('work', 'operator', owner_id='second', lease_seconds=60)
    assert not claimed and again == record
    assert not store.renew_dispatch_lease('work', 'operator', attempt_id=record['dispatch_attempt_id'], owner_id='first', lease_seconds=60)
    record, claimed = store.claim_reconciliation('work', 'operator', owner_id='second', lease_seconds=60,
        now=datetime(2099, 1, 1, tzinfo=timezone.utc))
    assert claimed and record['recovery_owner_id'] == 'second'


def test_pre_dispatch_cancellation_is_local_and_prevents_launch(tmp_path):
    store = a2a.TaskStore(tmp_path / 'state')
    store.create({'work_item_id': 'work', 'principal_id': 'operator', 'state': 'queued', 'request_sha256': 'a' * 64})
    record = store.request_cancellation('work', 'operator')
    assert record['state'] == 'cancelled' and record['cancellation_status'] == 'confirmed_local'
    assert store.begin_dispatch('work', 'operator', owner_id='owner', lease_seconds=60) == (record, False)


def test_task_store_missing_lock_or_invalid_event_never_returns_unverified_state(tmp_path):
    with pytest.raises(a2a.A2ACoordinationError) as error: a2a.TaskStore(tmp_path / 'missing', create=False)
    assert error.value.code == 'TASK_STORE_UNAVAILABLE'
    store = a2a.TaskStore(tmp_path / 'state')
    with pytest.raises(a2a.A2ACoordinationError) as error: store.get('work', 'operator')
    assert error.value.code == 'TASK_STORE_UNAVAILABLE'
    with pytest.raises(a2a.A2ACoordinationError) as error: store.create({'work_item_id': '../bad'})
    assert error.value.code == 'INVALID_WORK_ITEM'
    record = {'work_item_id': 'work', 'principal_id': 'operator', 'state': 'queued', 'request_sha256': 'a' * 64}
    store.create(record)
    with pytest.raises(a2a.A2ACoordinationError) as error: store.create({**record, 'request_sha256': 'b' * 64})
    assert error.value.code == 'IDEMPOTENCY_CONFLICT'
    event = next(store.tasks.rglob('*.json'))
    value = json.loads(event.read_text()); value['record'] = None
    value.pop('sha256'); value['sha256'] = a2a._digest(value)
    event.write_text(json.dumps(value))
    with pytest.raises(a2a.A2ACoordinationError) as error: store.get('work', 'operator')
    assert error.value.code == 'TASK_EVIDENCE_INVALID'


@pytest.mark.parametrize('event_kind', ['transport_error', 'protocol_error'])
def test_late_error_preserves_completed_outcome(tmp_path, event_kind):
    coordinator, _ = _coordinator(tmp_path)
    item = _item(); completed = coordinator.submit(item, 'aiderdesk')
    result = coordinator.store.transition_remote_event(item.work_item_id, 'aiderdesk',
        attempt_id=completed['dispatch_attempt_id'], event_kind=event_kind, code='WORKER_FAILURE')
    assert result['state'] == 'completed' and result['worker_result'] == completed['worker_result']
    assert result['coordination_diagnostics'][-1]['code'] == ('LATE_PROTOCOL_ERROR' if event_kind == 'protocol_error' else 'LATE_TRANSPORT_ERROR')


@pytest.mark.parametrize('failure', ['lost-ownership', 'store-unavailable'])
def test_dispatch_heartbeat_stops_when_ownership_cannot_be_renewed(tmp_path, monkeypatch, failure):
    coordinator, client = _coordinator(tmp_path)
    coordinator.dispatch_lease_seconds = 0.15
    renewed = threading.Event()

    def renewal(*args, **kwargs):
        renewed.set()
        if failure == 'store-unavailable': raise OSError('store unavailable')
        return False

    run = Mock(side_effect=renewal)
    monkeypatch.setattr(coordinator.store, 'renew_dispatch_lease', run)
    with coordinator._dispatch_lease('work', 'operator', 'attempt'):
        assert renewed.wait(timeout=2)
    run.assert_called_once_with('work', 'operator', attempt_id='attempt',
        owner_id=coordinator.coordinator_id, lease_seconds=0.15)
    assert client.calls == []


def test_refresh_with_pending_cancellation_confirms_remote_stop(tmp_path):
    from test_a2a_coordination import FakeWorkerClient
    client = FakeWorkerClient(state='working'); coordinator, _ = _coordinator(tmp_path, client)
    item = _item(); client.item = item
    coordinator.submit(item, 'aiderdesk')
    coordinator.store.request_cancellation(item.work_item_id, 'aiderdesk')
    result = coordinator.get(item.work_item_id, 'aiderdesk')
    assert result['state'] == 'cancelled'
    assert result['acceptance']['claim'] == 'NO_PROOF'
    assert client.calls[-1] == ('cancel', 'rust-worker', 'remote-1')
