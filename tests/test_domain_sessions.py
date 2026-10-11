# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Resumption, immutable publication and authority contracts for domain sessions."""
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
import mcp_server
from pipeline.domain_sessions import DomainSessionService,_bounded_chat
from pipeline.domain_v2 import DomainSpecV2
from pipeline.workflow_contracts import FixedEffectAuthority
from pipeline.workflow_sessions import SessionError,WorkflowSessionStore,MAX_REVISIONS
from test_domain_promotion_approval import candidate_value


@pytest.fixture
def session(tmp_path,monkeypatch):
    root=tmp_path/'protected';root.mkdir(mode=0o700)
    workspace=tmp_path/'workspace';workspace.mkdir();monkeypatch.chdir(workspace)
    clock=[100.0];store=WorkflowSessionStore(root,'alice',now=lambda:clock[0])
    service=DomainSessionService(store,workspace,workspace/'output')
    calls=[]
    questions=[{'id':'q1','question':'What initial state?','category':'state','required':True},
               {'id':'q2','question':'Any environment assumptions?','category':'environment','required':False}]
    monkeypatch.setattr('pipeline.domain_sessions._chat_fn',lambda *a,**k:lambda *a,**k:('{}','fixture',{}))
    monkeypatch.setattr('pipeline.domain_sessions.elicit_domain_questions',lambda *a:(questions,'fixture',{}))
    def compile(*args):
        calls.append(args)
        return DomainSpecV2.model_validate(candidate_value()),'ignored provider serialization','fixture',{}
    monkeypatch.setattr('pipeline.domain_sessions.compile_domain_spec_v2',compile)
    return SimpleNamespace(service=service,store=store,clock=clock,calls=calls,workspace=workspace,
        permission=FixedEffectAuthority(('workspace_read','workspace_write_new','provider_access',
            'service_state_read','service_state_write')),questions=questions)


def ready(p):
    initial=p.service.start('A switch with a boolean enabled state')
    return p.service.continue_session(initial['session_id'],{'q1':'Initially disabled'},initial['revision'])


def test_resumption_and_idempotent_finalization(session):
    p=session;initial=p.service.start('A switch')
    assert initial['status']=='CLARIFYING' and initial['revision']==0
    assert 'principal' not in initial and initial['claim']=='NO_PROOF'
    assert p.service.get(initial['session_id'])==initial
    with pytest.raises(SessionError,match='unanswered'):p.service.finalize(initial['session_id'],0,p.permission)
    record=p.service.continue_session(initial['session_id'],{'q1':'Initially disabled'},0)
    assert record['status']=='READY' and not record['remaining_questions']
    result=p.service.finalize(record['session_id'],1,p.permission)
    artifact=Path(result['candidate_artifact']['path']);raw=artifact.read_bytes()
    assert json.loads(raw)['review_status']=='unreviewed'
    assert result['validate_domain']['project_root']==str(artifact.parent.parent.parent)
    assert result['promotion_candidate']==str(artifact)
    assert 'candidate_text' not in result
    assert p.service.finalize(record['session_id'],1,p.permission)==result
    assert p.service.finalize(record['session_id'],result['revision'],p.permission)==result
    assert len(p.calls)==1 and artifact.read_bytes()==raw
    with pytest.raises(SessionError):p.service.continue_session(record['session_id'],{'q1':'Changed'},result['revision'])
    with pytest.raises(SessionError):p.service.finalize(record['session_id'],True,p.permission)


@pytest.mark.parametrize('answers',[{},[],{'unknown':'answer'},{'q1':''},{'q1':'a'*4097},{'q1':12},{'q1':'bad\0value'}])
def test_invalid_answers_leave_revision_unchanged(session,answers):
    p=session;r=p.service.start('A switch')
    with pytest.raises(SessionError):p.service.continue_session(r['session_id'],answers,0)
    assert p.service.get(r['session_id'])['revision']==0


def test_optional_answer_does_not_skip_required_question(session):
    p=session;r=p.service.start('A switch')
    r=p.service.continue_session(r['session_id'],{'q2':'No additional assumptions'},0)
    assert r['status']=='CLARIFYING' and len(r['remaining_questions'])==1
    with pytest.raises(SessionError):p.service.continue_session(r['session_id'],{'q1':'disabled'},0)


@pytest.mark.parametrize('mutation',['principal','expired','workspace','output','history','schema','symlink','missing','oversized','gap'])
def test_changed_session_context_fails_closed(session,mutation,tmp_path):
    p=session;r=ready(p);rid=r['session_id'];directory=p.store.directory(rid)
    if mutation=='principal':p.store.principal='mallory'
    elif mutation=='expired':p.clock[0]+=86401
    elif mutation=='workspace':p.service.workspace=tmp_path
    elif mutation=='output':p.service.output_root=p.workspace/'different'
    elif mutation=='missing':(directory/'000.json').unlink()
    elif mutation=='gap':(directory/'001.json').rename(directory/'002.json')
    elif mutation=='symlink':
        data=(directory/'001.json').read_bytes();(directory/'001.json').unlink()
        target=tmp_path/'target';target.write_bytes(data);(directory/'001.json').symlink_to(target)
    elif mutation=='oversized':(directory/'001.json').write_bytes(b' '*1024*1024+b'x')
    else:
        value=json.loads((directory/'001.json').read_text())
        if mutation=='history':value['answers']['q1']='tampered'
        else:value['schema']='unknown'
        (directory/'001.json').write_text(json.dumps(value))
    with pytest.raises((SessionError,OSError)):p.service.get(rid)


def test_competing_answer_updates_require_exact_revision(session):
    p=session;r=p.service.start('A switch')
    def update(answer):
        try:return p.service.continue_session(r['session_id'],{'q1':answer},0)['status']
        except SessionError as error:return error.code
    with ThreadPoolExecutor(max_workers=2) as pool:outcomes=list(pool.map(update,['disabled','enabled']))
    assert sorted(outcomes)==['READY','SESSION_REVISION_CONFLICT']


@pytest.mark.parametrize('mutation',['tamper','missing','symlink'])
def test_finalized_candidate_is_never_silently_reused_or_replaced(session,mutation,tmp_path):
    p=session;r=ready(p);result=p.service.finalize(r['session_id'],1,p.permission)
    path=Path(result['candidate_artifact']['path'])
    if mutation=='tamper':path.write_text('{}')
    elif mutation=='missing':path.unlink()
    else:
        target=tmp_path/'candidate';target.write_bytes(path.read_bytes());path.unlink();path.symlink_to(target)
    with pytest.raises((ValueError,OSError)):p.service.finalize(r['session_id'],1,p.permission)
    assert len(p.calls)==1


def test_interruption_after_publication_recovers_without_recompilation(session,monkeypatch):
    p=session;r=ready(p);original=p.store.append
    def interrupted(record,changes):
        if changes.get('status')=='FINALIZED':raise OSError('receipt interrupted')
        return original(record,changes)
    monkeypatch.setattr(p.store,'append',interrupted)
    with pytest.raises(OSError):p.service.finalize(r['session_id'],1,p.permission)
    assert p.service.get(r['session_id'])['status']=='PREPARED'
    monkeypatch.setattr(p.store,'append',original)
    assert p.service.finalize(r['session_id'],1,p.permission)['status']=='FINALIZED'
    assert len(p.calls)==1


def test_provider_failure_leaves_ready_session_retryable(session,monkeypatch):
    p=session;r=ready(p)
    monkeypatch.setattr('pipeline.domain_sessions.compile_domain_spec_v2',lambda *a: (_ for _ in ()).throw(ValueError('malformed provider response')))
    with pytest.raises(ValueError):p.service.finalize(r['session_id'],1,p.permission)
    assert p.service.get(r['session_id'])['status']=='READY'


@pytest.mark.parametrize('field,value',[('idea',''),('idea','a'*16385),('provider','unsupported'),('model','a'*257)])
def test_start_rejects_unbounded_or_unsupported_inputs(session,field,value):
    arguments={'idea':'A switch',field:value}
    with pytest.raises(SessionError):session.service.start(**arguments)
    assert not list(session.store.root.iterdir())


def test_provider_response_and_call_limits(monkeypatch):
    def factory(*a,**k):return lambda *a:('x'*131073,'fixture',{})
    monkeypatch.setattr('pipeline.domain_sessions._chat_fn',factory)
    with pytest.raises(SessionError):_bounded_chat('ollama')([],None,0)
    monkeypatch.setattr('pipeline.domain_sessions._chat_fn',lambda *a,**k:lambda *a:('{}','fixture',{}))
    bounded=_bounded_chat('ollama')
    for _ in range(32):bounded([],None,0)
    with pytest.raises(SessionError):bounded([],None,0)


def test_read_and_continue_mcp_tools_do_not_invoke_provider(session,monkeypatch):
    p=session;monkeypatch.setattr('pipeline.domain_sessions.configured_service',lambda *a:p.service)
    r=mcp_server.start_domain_session('A switch')
    assert r['status']=='CLARIFYING'
    r=mcp_server.continue_domain_session(r['session_id'],{'q1':'disabled'},0)
    assert r['status']=='READY'
    assert mcp_server.get_domain_session(r['session_id'])['revision']==1
    r=mcp_server.finalize_domain_candidate(r['session_id'],1)
    assert r['status']=='FINALIZED' and r['claim']=='NO_PROOF'
    assert len(p.calls)==1


def test_store_configuration_and_identifier_checks(session,tmp_path):
    for root,principal in [(tmp_path/'absent','alice'),(session.store.root,''),(Path('relative'),'alice')]:
        with pytest.raises(SessionError):WorkflowSessionStore(root,principal)
    link=tmp_path/'link';link.symlink_to(session.store.root,target_is_directory=True)
    with pytest.raises(SessionError):WorkflowSessionStore(link,'alice')
    session.store.root.chmod(0o777)
    with pytest.raises(SessionError):WorkflowSessionStore(session.store.root,'alice')
    for rid in ('../escape','','not-an-id',None):
        with pytest.raises(SessionError):session.store.directory(rid)
    with pytest.raises(SessionError):DomainSessionService(session.store,session.workspace,tmp_path)


def test_history_limits(session):
    p=session;r=ready(p)
    with pytest.raises(SessionError):p.store.append({**r,'revision':MAX_REVISIONS-1},{})
    with pytest.raises(SessionError):p.store.append(p.store.load(r['session_id']),{'huge':'a'*1024*1024})


def test_zero_question_session_and_configured_operator_identity(session,monkeypatch):
    p=session
    monkeypatch.setattr('pipeline.domain_sessions.elicit_domain_questions',lambda *a:([],'fixture',{}))
    r=p.service.start('A switch',model='fixture-model')
    assert r['status']=='READY'
    monkeypatch.setenv('FORMALSPECGEN_SESSION_ROOT',str(p.store.root))
    monkeypatch.setenv('FORMALSPECGEN_SESSION_PRINCIPAL','alice')
    from pipeline.domain_sessions import configured_service
    service=configured_service(p.service.output_root)
    service.store.now=lambda:p.clock[0]
    assert service.get(r['session_id'])['status']=='READY'
    assert service.finalize(r['session_id'],0,p.permission)['status']=='FINALIZED'


def test_structured_provider_retains_bounds_and_rejects_non_text(monkeypatch):
    def chat(*a):return '{}','fixture',{}
    chat.structured_for=lambda *a,**k:chat
    monkeypatch.setattr('pipeline.domain_sessions._chat_fn',lambda *a,**k:chat)
    bounded=_bounded_chat('ollama',schema={}).structured_for({})
    assert bounded([],None,0)[0]=='{}'
    monkeypatch.setattr('pipeline.domain_sessions._chat_fn',lambda *a,**k:lambda *a:(None,'fixture',{}))
    with pytest.raises(SessionError):_bounded_chat('ollama')([],None,0)
    monkeypatch.setattr('pipeline.domain_sessions._chat_fn',lambda *a,**k:lambda *a:('x'*131072,'fixture',{}))
    bounded=_bounded_chat('ollama')
    for _ in range(8):bounded([],None,0)
    with pytest.raises(SessionError):bounded([],None,0)


def test_non_object_record_and_symlinked_session_rejected(session,tmp_path):
    p=session;r=p.service.start('A switch');directory=p.store.directory(r['session_id'])
    (directory/'000.json').write_text('[]')
    with pytest.raises(SessionError):p.service.get(r['session_id'])
    linked='a'*32;(p.store.root/linked).symlink_to(directory,target_is_directory=True)
    with pytest.raises(SessionError):p.store.directory(linked)


def test_unsupported_mcp_provider_is_rejected_before_service_creation(session,monkeypatch):
    def forbidden(*a):raise AssertionError('service creation before admission')
    monkeypatch.setattr('pipeline.domain_sessions.configured_service',forbidden)
    assert mcp_server.start_domain_session('A switch',provider='unsupported')['claim']=='NO_PROOF'


def test_nested_provider_http_limits_attenuate_and_reset():
    from io import BytesIO
    from pipeline.llm import provider_response_limit,_read_provider_response,LLMError
    with pytest.raises(ValueError):
        with provider_response_limit(0):pass
    with provider_response_limit(4):
        assert _read_provider_response(BytesIO(b'1234'))==b'1234'
        with provider_response_limit(10):
            with pytest.raises(LLMError):_read_provider_response(BytesIO(b'12345'))
        with provider_response_limit(2):
            with pytest.raises(LLMError):_read_provider_response(BytesIO(b'123'))
    assert _read_provider_response(BytesIO(b'12345'))==b'12345'


def test_session_mutation_cannot_change_owner_or_scope(session):
    p=session;r=ready(p)
    with pytest.raises(SessionError):p.store.append(p.store.load(r['session_id']),{'principal':'mallory'})
    assert p.service.get(r['session_id'])['status']=='READY'


def test_finalization_cannot_resurrect_read_or_provider_authority(session):
    from pipeline.mcp_policy import MCPPolicyViolation
    p=session;r=ready(p)
    for missing in ('workspace_read','provider_access','service_state_write'):
        authority=FixedEffectAuthority(tuple(e for e in p.permission.effects if e!=missing))
        with pytest.raises(MCPPolicyViolation):p.service.finalize(r['session_id'],1,authority)
    assert p.service.get(r['session_id'])['revision']==1 and not p.calls


def test_empty_history_is_not_a_resumable_session(session):
    rid='b'*32;session.store.directory(rid).mkdir(mode=0o700)
    with pytest.raises(SessionError):session.store.load(rid)
