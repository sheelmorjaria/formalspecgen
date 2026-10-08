# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Pinned SDK payloads, worker identity, and resource cleanup contracts."""
import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
pytest.importorskip('a2a')
from a2a.helpers import new_text_message
from a2a.types import Artifact, Part, Task, TaskState, TaskStatus

from pipeline import a2a_coordination as a2a
from test_a2a_coordination import _coordinator, _item


def task(*, result='{}', state=TaskState.TASK_STATE_COMPLETED, message=True):
    value = Task(id='remote-1', context_id='context', status=TaskStatus(state=state))
    if message:
        value.status.message.CopyFrom(new_text_message('worker diagnostic'))
    value.artifacts.extend([
        Artifact(name='other', parts=[Part(text='ignored')]),
        Artifact(name='formalspecgen-work-result', parts=[Part(text=result)]),
    ])
    return value


@pytest.mark.parametrize('operation', ['submit', 'get', 'cancel', 'reconcile'])
def test_sdk_request_identity_and_cleanup(tmp_path, monkeypatch, operation):
    worker = _coordinator(tmp_path)[0].policy.workers['rust-worker']
    item = _item()
    remote = task(result='{"patch_sha256":"candidate"}')
    requests = []

    async def send(request):
        requests.append(request)
        yield SimpleNamespace(HasField=lambda name: False)
        yield SimpleNamespace(HasField=lambda name: name == 'task', task=remote)

    async def get(request):
        requests.append(request)
        return remote

    async def listed(request):
        requests.append(request)
        return SimpleNamespace(tasks=[remote])

    client = SimpleNamespace(send_message=send, get_task=get, cancel_task=get,
                             list_tasks=listed, close=AsyncMock())
    http = SimpleNamespace(aclose=AsyncMock())
    adapter = a2a.OfficialA2AWorkerClient()
    monkeypatch.setattr(adapter, '_client', AsyncMock(return_value=(client, http)))
    result = getattr(adapter, operation)(worker, item if operation in {'submit', 'reconcile'} else 'remote-1')
    assert result.remote_task_id == 'remote-1'
    assert result.state == 'completed' and result.result == {'patch_sha256': 'candidate'}
    assert result.message == 'worker diagnostic'
    client.close.assert_awaited_once()
    http.aclose.assert_awaited_once()
    request = requests[0]
    if operation == 'submit':
        from a2a.helpers import get_message_text
        assert json.loads(get_message_text(request.message)) == json.loads(json.dumps(item.as_dict()))
        assert request.message.context_id == adapter._submission_context_id(item)
    elif operation == 'reconcile':
        assert request.context_id == adapter._submission_context_id(item)
        assert request.page_size == 2 and request.include_artifacts
    else:
        assert request.id == 'remote-1'


@pytest.mark.parametrize('count,code', [(0, None), (2, 'WORKER_RECONCILIATION_CONFLICT')])
def test_reconciliation_refuses_ambiguous_identity(tmp_path, monkeypatch, count, code):
    adapter = a2a.OfficialA2AWorkerClient()
    worker = _coordinator(tmp_path)[0].policy.workers['rust-worker']
    client = SimpleNamespace(list_tasks=AsyncMock(return_value=SimpleNamespace(tasks=[task()] * count)), close=AsyncMock())
    http = SimpleNamespace(aclose=AsyncMock())
    monkeypatch.setattr(adapter, '_client', AsyncMock(return_value=(client, http)))
    if code:
        with pytest.raises(a2a.A2ACoordinationError) as error:
            adapter.reconcile(worker, _item())
        assert error.value.code == code
    else:
        assert adapter.reconcile(worker, _item()) is None
    client.close.assert_awaited_once()
    http.aclose.assert_awaited_once()


def test_missing_task_and_malformed_result_close_resources(tmp_path, monkeypatch):
    adapter = a2a.OfficialA2AWorkerClient()
    worker = _coordinator(tmp_path)[0].policy.workers['rust-worker']

    async def empty(_request):
        yield SimpleNamespace(HasField=lambda _name: False)

    client = SimpleNamespace(send_message=empty, close=AsyncMock())
    http = SimpleNamespace(aclose=AsyncMock())
    monkeypatch.setattr(adapter, '_client', AsyncMock(return_value=(client, http)))
    with pytest.raises(a2a.A2ACoordinationError) as error:
        adapter.submit(worker, _item())
    assert error.value.code == 'WORKER_RESULT_INVALID'
    client.close.assert_awaited_once()
    http.aclose.assert_awaited_once()
    with pytest.raises(a2a.A2ACoordinationError) as error:
        adapter._observation(task(result='{'))
    assert error.value.code == 'WORKER_RESULT_INVALID'
    remote = task(message=False)
    remote.ClearField('artifacts')
    assert adapter._observation(remote).result is None
    assert adapter._observation(remote).message == ''


def test_sync_adapter_inside_event_loop_propagates_result_and_error():
    async def value():
        return 'observed'

    async def failure():
        raise a2a.A2ACoordinationError('WORKER_FAILURE', 'failed')

    async def caller():
        assert a2a.OfficialA2AWorkerClient._run_sync(value()) == 'observed'
        with pytest.raises(a2a.A2ACoordinationError, match='failed'):
            a2a.OfficialA2AWorkerClient._run_sync(failure())
    asyncio.run(caller())


@pytest.mark.parametrize('authenticated', [False, True])
def test_client_pins_agent_card_and_closes_http_on_identity_failure(tmp_path, monkeypatch, authenticated):
    from a2a import client as sdk_client
    import httpx
    from a2a.types import AgentCard
    card = AgentCard(name='worker', description='test', version='1')
    worker = replace(_coordinator(tmp_path)[0].policy.workers['rust-worker'],
                     agent_card_sha256=a2a.agent_card_sha256(card),
                     auth_token_env='TEST_WORKER_TOKEN' if authenticated else None)
    monkeypatch.setenv('TEST_WORKER_TOKEN', 'credential')
    http = SimpleNamespace(aclose=AsyncMock())
    captured = {}

    def make_http(**kwargs):
        captured.update(kwargs)
        return http

    async def create(endpoint, *, client_config, signature_verifier):
        assert endpoint == worker.endpoint
        assert client_config.httpx_client is http and not client_config.streaming
        signature_verifier(card)
        signature_verifier(AgentCard(name='changed', description='test', version='1'))

    monkeypatch.setattr(httpx, 'AsyncClient', make_http)
    monkeypatch.setattr(sdk_client, 'create_client', create)
    with pytest.raises(a2a.A2ACoordinationError) as error:
        asyncio.run(a2a.OfficialA2AWorkerClient(timeout_seconds=7)._client(worker))
    assert error.value.code == 'WORKER_IDENTITY_MISMATCH'
    assert captured['headers'] == ({'Authorization': 'Bearer credential'} if authenticated else {})
    assert captured['timeout'] == 7
    http.aclose.assert_awaited_once()
    if authenticated:
        monkeypatch.delenv('TEST_WORKER_TOKEN')
        with pytest.raises(a2a.A2ACoordinationError) as error:
            a2a.OfficialA2AWorkerClient._token(worker)
        assert error.value.code == 'WORKER_AUTH_UNAVAILABLE'


def test_matching_card_returns_owned_client_resources(tmp_path, monkeypatch):
    from a2a import client as sdk_client
    import httpx
    from a2a.types import AgentCard
    card = AgentCard(name='worker', description='test', version='1')
    worker = replace(_coordinator(tmp_path)[0].policy.workers['rust-worker'],
                     agent_card_sha256=a2a.agent_card_sha256(card))
    http = SimpleNamespace(aclose=AsyncMock()); client = SimpleNamespace(close=AsyncMock())

    async def create(_endpoint, *, signature_verifier, **_kwargs):
        signature_verifier(card)
        return client

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **_kwargs: http)
    monkeypatch.setattr(sdk_client, 'create_client', create)
    assert asyncio.run(a2a.OfficialA2AWorkerClient()._client(worker)) == (client, http)
    client.close.assert_not_awaited(); http.aclose.assert_not_awaited()
