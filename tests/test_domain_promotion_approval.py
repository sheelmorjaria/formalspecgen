# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Authenticated promotion contracts; synthetic validation is never proof."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import mcp_server
from pipeline.approval_service import ApprovalError, record_human_decision
from pipeline.domain_promotion_approval import DomainPromotionApprovalService
from pipeline.domain_v2 import DomainSpecV2
from pipeline.domain_v2_promotion import candidate_sha256
from pipeline.domain_v2_publication import ContextBoundValidatedEvidence, TlcEvidence, publish_validation_success
from pipeline.domain_validation_identity import domain_validation_context
from pipeline.domain_validation_workflow import DOMAIN_VALIDATION_LIMITS

REVIEWER, SIGNER = 'A' * 40, 'B' * 40


def candidate_value():
    return {'schema_version': 2, 'review_status': 'unreviewed', 'domain_name': 'Switch', 'module_name': 'switch',
        'actors': 1, 'state_variables': [{'kind': 'bool', 'name': 'enabled', 'initial': False}],
        'operations': [{'name': 'enable', 'return_type': 'void', 'failure_semantics': 'unavailable',
            'guards': [], 'effects': [{'id': 'set_enabled', 'target': 'enabled', 'value': {'kind': 'boolean', 'value': True}}], 'frame': ['enabled']}],
        'tlc_invariants': [{'id': 'EnabledIsBoolean', 'expression': {'kind': 'or', 'left': {'kind': 'field', 'name': 'enabled'},
            'right': {'kind': 'eq', 'left': {'kind': 'field', 'name': 'enabled'}, 'right': {'kind': 'boolean', 'value': False}}}}]}


@pytest.fixture
def promotion(tmp_path, monkeypatch, domain_identity_java):
    jar = tmp_path / 'tlc.jar'; jar.write_bytes(b'synthetic tool identity; no execution')
    monkeypatch.setattr('pipeline.config.TLC_JAR', str(jar))
    registry = tmp_path / 'registry'; registry.mkdir()
    policy = tmp_path / 'policy.json'; policy.write_text('{}')
    revocations = tmp_path / 'revocations.json'
    revocations.write_text(json.dumps({'schema': 'formalspecgen-promotion-revocations-v1', 'request_ids': []}))
    candidate = tmp_path / 'candidate.json'; candidate.write_text(json.dumps(candidate_value()))
    context = domain_validation_context(candidate.read_bytes(), limits=DOMAIN_VALIDATION_LIMITS, timeout=120)
    validation = tmp_path / 'validation.json'
    publish_validation_success(validation, ContextBoundValidatedEvidence(
        applicability_context=context, candidate_sha256=candidate_sha256(DomainSpecV2.model_validate(candidate_value())),
        generated_tla_sha256=next(v['sha256'] for k,v in context['generated_models'].items() if k.endswith('.tla')),
        execution_assumption='atomic_last_result_abstraction', abstraction_mode='atomic_operations',
        bounds={'enabled':2,'actors':1}, state_space_upper_bound=2, reachable_state_count=2,
        reachable_transition_count=1, tools={'tlc':TlcEvidence(version='fixture', command=['fixture'])}, tlc_exit_status=0))
    signer = tmp_path / 'protected-signer'; signer.write_text('#!/bin/sh\nexit 1\n'); signer.chmod(0o700)
    publisher = tmp_path / 'publisher'; publisher.write_text('#!/bin/sh\nexit 1\n'); publisher.chmod(0o700)
    public_home = tmp_path / 'public'; public_home.mkdir()
    state = SimpleNamespace(signer_calls=0, identity=REVIEWER, clock=datetime.now(timezone.utc))
    def runner(command, **kwargs):
        if str(command[0]) == str(publisher):
            service.publish_approved(command[-1])
        elif str(command[0]) == str(signer):
            state.signer_calls += 1
            Path(command[command.index('--output') + 1]).write_bytes(b'fixture signature')
        elif '--detach-sign' in command:
            Path(command[command.index('--output') + 1]).write_bytes(b'fixture decision signature')
        elif '--verify' in command:
            identity = state.identity if Path(command[-1]).name == 'decision.json' else SIGNER
            return SimpleNamespace(returncode=0, stdout=f'[GNUPG:] VALIDSIG {identity} 0 0\n')
        else: raise AssertionError(command)
        return SimpleNamespace(returncode=0, stdout='')
    service = DomainPromotionApprovalService(tmp_path / 'approvals', verifier_home=public_home,
        authorized_reviewers={REVIEWER}, signer=signer, signing_identity=SIGNER, reviewer_identity=REVIEWER,
        runner=runner, now=lambda:state.clock, registry=registry, validation_policy=policy,
        revocations=revocations, principal='operator-session', publisher=publisher)
    from pipeline.mcp_policy import authorize_mcp_invocation
    profile = authorize_mcp_invocation('request_domain_promotion',mode='request',language='model',backend='protected-domain-publisher-v1',effects=('workspace_read','service_state_read','service_state_write')).summary()['profile_sha256']
    def request(**kwargs):
        return service.request_promotion(name='switch',candidate=candidate,validation=validation,
            admission_profile_sha256=profile,**kwargs)['approval']['request_id']
    def decide(request_id, decision='approve'):
        record_human_decision(service.root,request_id,decision=decision,signing_key=REVIEWER,runner=runner)
    return SimpleNamespace(service=service,request=request,decide=decide,candidate=candidate,validation=validation,
        registry=registry,policy=policy,revocations=revocations,state=state,runner=runner)


@pytest.mark.parametrize('sign',[False,True])
def test_authenticated_promotion_publishes_exact_bytes_once(promotion,sign):
    p=promotion; rid=p.request(sign=sign)
    assert p.service.status(rid)['status']=='PENDING'
    with pytest.raises(ApprovalError,match='absent'): p.service.execute(rid)
    assert not (p.registry/'switch.json').exists()
    p.decide(rid); result=p.service.execute(rid)
    assert result['status']=='PROMOTED' and result['claim']=='NO_PROOF'
    assert result['request_satisfied']
    raw=(p.registry/'switch.json').read_bytes()
    reviewed=json.loads(raw)
    assert reviewed['approval_operation_id']==rid
    assert reviewed['accepted_validation_artifact_sha256']==hashlib.sha256(p.validation.read_bytes()).hexdigest()
    assert result['publication']['sha256']==hashlib.sha256(raw).hexdigest()
    assert p.service.execute(rid)['approval_receipt']==result['approval_receipt']
    assert p.state.signer_calls==int(sign)


@pytest.mark.parametrize('change',['candidate','validation','configuration','destination','reviewer','principal','revoked','expired','descriptor','payload'])
def test_changes_never_authorize_publication(promotion,change):
    p=promotion; rid=p.request(); p.decide(rid)
    if change=='candidate': p.candidate.write_bytes(p.candidate.read_bytes()+b' ')
    elif change=='validation': p.validation.write_bytes(p.validation.read_bytes()+b' ')
    elif change=='configuration': p.policy.write_text('{"max_states":2}')
    elif change=='destination': (p.registry/'switch.json').write_text('different existing domain')
    elif change=='reviewer': p.state.identity='D'*40
    elif change=='principal': p.service.principal='other-session'
    elif change=='revoked': p.revocations.write_text(json.dumps({'schema':'formalspecgen-promotion-revocations-v1','request_ids':[rid]}))
    elif change=='expired': p.state.clock+=timedelta(days=2)
    else:
        req=json.loads((p.service.root/rid/'request.json').read_text())
        Path(req['artifact' if change=='payload' else 'evidence_manifest']['path']).write_text('{}')
    with pytest.raises((ApprovalError,ValueError)): p.service.execute(rid)
    if change!='destination': assert not (p.registry/'switch.json').exists()


def test_replacement_binds_prior_destination_and_denial(promotion):
    p=promotion; dest=p.registry/'switch.json';dest.write_text('previous reviewed artifact')
    with pytest.raises(ApprovalError,match='replacement'): p.request()
    rid=p.request(replace=True);p.decide(rid,'deny')
    assert p.service.execute(rid)['status']=='DENIED'
    assert dest.read_text()=='previous reviewed artifact'
    rid=p.request(replace=True);p.decide(rid)
    assert p.service.execute(rid)['status']=='PROMOTED'
    assert json.loads(dest.read_text())['approval_operation_id']==rid


def test_interrupted_publication_recovers_exact_action(promotion):
    p=promotion;rid=p.request(sign=True);p.decide(rid)
    def interrupt(): raise RuntimeError('simulated interruption')
    with pytest.raises(RuntimeError): p.service.publish_approved(rid,before_receipt=interrupt)
    raw=(p.registry/'switch.json').read_bytes()
    assert not (p.service.root/rid/'receipt.json').exists()
    assert p.service.status(rid)['phases'] == {
        'approval':'DECISION_RECORDED','publication':'PUBLISHED',
        'signing':'SIGNED','receipt':'NOT_COMMITTED'}
    result=p.service.execute(rid)
    assert result['status']=='PROMOTED' and (p.registry/'switch.json').read_bytes()==raw
    assert p.state.signer_calls==1


def test_competing_approved_replacements_publish_only_one(promotion):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    p=promotion; destination=p.registry/'switch.json'
    destination.write_text('the reviewed prior artifact')
    requests=[p.request(replace=True,sign=True) for _ in range(2)]
    for rid in requests: p.decide(rid)
    barrier=Barrier(2)
    def complete(rid):
        barrier.wait(timeout=10)
        try: return rid,p.service.publish_approved(rid)['status']
        except ApprovalError as error: return rid,error.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes=list(pool.map(complete,requests))
    assert sorted(status for _,status in outcomes)==['DESTINATION_CHANGED','PROMOTED']
    winner=next(rid for rid,status in outcomes if status=='PROMOTED')
    assert json.loads(destination.read_text())['approval_operation_id']==winner
    assert p.state.signer_calls==1


def test_destination_change_during_signing_rejects_publication(promotion,monkeypatch):
    p=promotion; destination=p.registry/'switch.json';destination.write_text('prior')
    rid=p.request(replace=True,sign=True);p.decide(rid)
    original=p.service._invoke_signer
    def changing_signer(*args):
        original(*args)
        destination.write_text('changed by another operator')
    monkeypatch.setattr(p.service,'_invoke_signer',changing_signer)
    with pytest.raises(ApprovalError,match='during signing'): p.service.publish_approved(rid)
    assert destination.read_text()=='changed by another operator'
    assert not (p.service.root/rid/'receipt.json').exists()


def test_signing_failure_exposes_pending_phase_and_safe_retry(promotion,monkeypatch):
    p=promotion;rid=p.request(sign=True);p.decide(rid)
    original=p.service._invoke_signer
    def failed(*args): raise ApprovalError('SIGNING_FAILED','injected signer interruption')
    monkeypatch.setattr(p.service,'_invoke_signer',failed)
    with pytest.raises(ApprovalError,match='interruption'):p.service.publish_approved(rid)
    status=p.service.status(rid)
    assert status['phases']['publication']=='NOT_PUBLISHED'
    assert status['phases']['signing']=='PENDING'
    assert status['phases']['receipt']=='NOT_COMMITTED'
    monkeypatch.setattr(p.service,'_invoke_signer',original)
    assert p.service.publish_approved(rid)['status']=='PROMOTED'


def test_decision_replay_cannot_authorize_another_request(promotion):
    p=promotion;a=p.request();b=p.request();p.decide(a)
    for name in ('decision.json','decision.json.sig'):
        (p.service.root/b/name).write_bytes((p.service.root/a/name).read_bytes())
    with pytest.raises(ApprovalError):p.service.execute(b)
    assert not (p.registry/'switch.json').exists()


def test_mcp_coordinates_without_accepting_a_human_decision(promotion,monkeypatch):
    p=promotion; monkeypatch.chdir(p.candidate.parent); monkeypatch.setattr('pipeline.domain_promotion_approval.configured_service',lambda **kw:p.service)
    response=mcp_server.request_domain_promotion('switch',str(p.candidate),str(p.validation),sign=True)
    rid=response['approval']['request_id']
    assert response['status']=='PENDING'
    assert mcp_server.complete_domain_promotion(rid)['status']=='APPROVAL_REQUIRED'
    p.decide(rid)
    assert mcp_server.complete_domain_promotion(rid)['status']=='PROMOTED'
    assert mcp_server.get_domain_promotion(rid)['publication']['path']==str(p.registry/'switch.json')


@pytest.mark.parametrize('mutation',['claim','publication','signature-path','signature-removed','status','reviewer'])
def test_receipt_tampering_never_reports_success(promotion,mutation):
    p=promotion;rid=p.request(sign=True);p.decide(rid);p.service.execute(rid)
    path=p.service.root/rid/'receipt.json';receipt=json.loads(path.read_text())
    if mutation=='claim':receipt['verification']['claim']='UNBOUNDED_PROOF'
    elif mutation=='publication':receipt['publication']['path']=str(p.candidate)
    elif mutation=='signature-path':receipt['signature']['path']=str(p.validation)
    elif mutation=='signature-removed':receipt['signature']=None
    elif mutation=='status':receipt['status']='SIGNED'
    else:receipt['reviewer_identity']='F'*40
    path.write_text(json.dumps(receipt))
    with pytest.raises(ApprovalError):p.service.status(rid)


@pytest.mark.parametrize('mutation',['tool','staged-source','intent','request-schema','revocation-schema','revocation-id'])
def test_publisher_rechecks_context_and_control_state(promotion,monkeypatch,mutation):
    p=promotion;rid=p.request();p.decide(rid);request=json.loads((p.service.root/rid/'request.json').read_text())
    if mutation=='tool':monkeypatch.setattr('pipeline.domain_validation_identity.java_runtime_identity',lambda **kw:{'different-jvm':'0'*64})
    elif mutation=='staged-source':Path(request['operation']['captured_candidate']['path']).write_text('{}')
    elif mutation=='intent':(p.service.root/rid/'publication-intent.json').write_text('{}')
    elif mutation=='request-schema':(p.service.root/rid/'request.json').write_text('[]')
    elif mutation=='revocation-schema':p.revocations.write_text('{}')
    else:p.revocations.write_text(json.dumps({'schema':'formalspecgen-promotion-revocations-v1','request_ids':['not-a-request']}))
    with pytest.raises((ApprovalError,ValueError)):p.service.publish_approved(rid)
    assert not (p.registry/'switch.json').exists()


def test_private_preparation_cannot_substitute_reviewed_output(promotion,monkeypatch):
    p=promotion;rid=p.request();p.decide(rid)
    from pipeline.domain_promotion_approval import promote_validated_candidate
    def changed(*args,**kwargs):
        return promote_validated_candidate(*args,**kwargs).model_copy(update={'domain_name':'Changed'})
    monkeypatch.setattr('pipeline.domain_promotion_approval.promote_validated_candidate',changed)
    with pytest.raises(ApprovalError,match='artifact or applicability'):p.service.publish_approved(rid)
    assert not (p.registry/'switch.json').exists()


def test_invalid_preparation_inputs_and_missing_publisher(promotion):
    p=promotion
    with pytest.raises(ApprovalError):p.service.request_promotion(name='../unsafe',candidate=p.candidate,validation=p.validation,admission_profile_sha256='c'*64)
    with pytest.raises(ApprovalError):p.service.request_promotion(name='other',candidate=p.candidate,validation=p.validation,admission_profile_sha256='c'*64)
    link=p.candidate.parent/'link.json';link.symlink_to(p.candidate)
    with pytest.raises(ApprovalError):p.service.request_promotion(name='switch',candidate=link,validation=p.validation,admission_profile_sha256='c'*64)
    rid=p.request();p.decide(rid);p.service.publisher=None
    with pytest.raises(ApprovalError,match='publisher'):p.service.execute(rid)
    p.service.publisher=p.candidate
    with pytest.raises(ApprovalError):p.service.execute(rid)


def test_protected_publisher_failure_is_fail_closed(promotion):
    p=promotion;rid=p.request();p.decide(rid)
    p.service.runner=lambda command,**kw: (SimpleNamespace(returncode=1,stdout='') if str(command[0])==str(p.service.publisher) else p.runner(command,**kw))
    with pytest.raises(ApprovalError,match='operator publisher'):p.service.execute(rid)
    assert not (p.registry/'switch.json').exists()


def test_operator_configuration_and_publisher_entry_point(promotion,monkeypatch,capsys):
    from pipeline import domain_promotion_approval as module
    p=promotion;trust=p.candidate.parent/'trusted.json';trust.write_text(json.dumps({'keys':[{'key_id':REVIEWER}]}))
    mapping={'FORMALSPECGEN_APPROVAL_ROOT':p.service.root,'FORMALSPECGEN_APPROVAL_GNUPGHOME':p.service.verifier_home,
        'FORMALSPECGEN_APPROVAL_TRUST_REGISTRY':trust,'FORMALSPECGEN_APPROVAL_SIGNER':p.service.signer,
        'FORMALSPECGEN_PROMOTION_REGISTRY':p.registry,'FORMALSPECGEN_PROMOTION_VALIDATION_POLICY':p.policy,
        'FORMALSPECGEN_PROMOTION_REVOCATIONS':p.revocations,'FORMALSPECGEN_PROMOTION_PUBLISHER':p.service.publisher}
    monkeypatch.setattr('pipeline.operator_configuration.operator_controlled_path',lambda variable,**kw:mapping[variable])
    monkeypatch.setenv('FORMALSPECGEN_SIGNING_IDENTITY',SIGNER);monkeypatch.setenv('FORMALSPECGEN_REVIEWER_IDENTITY',REVIEWER)
    monkeypatch.setenv('FORMALSPECGEN_PROMOTION_PRINCIPAL',p.service.principal)
    assert module.configured_service(publisher=True).registry==p.registry
    assert module.configured_service(publisher=False).publisher is None
    monkeypatch.setattr(module,'configured_service',lambda **kw:p.service)
    assert module.main(['--request-id','invalid'])==2
    rid=p.request();p.decide(rid)
    assert module.main(['--request-id',rid])==0
    assert json.loads(capsys.readouterr().out.splitlines()[-1])['status']=='PROMOTED'


def test_mcp_rejects_inputs_outside_workspace_and_unsupported_profile(promotion,monkeypatch):
    from dataclasses import replace
    p=promotion;workspace=p.candidate.parent/'workspace';workspace.mkdir();monkeypatch.chdir(workspace)
    result=mcp_server.request_domain_promotion('switch',str(p.candidate),str(p.validation))
    assert result['status']=='PROMOTION_SERVICE_UNAVAILABLE'
    monkeypatch.chdir(p.candidate.parent)
    link=workspace/'candidate.json';link.symlink_to(p.candidate)
    assert mcp_server.request_domain_promotion('switch',str(link),str(p.validation))['request_satisfied'] is False
    admission=mcp_server.authorize_mcp_invocation('get_domain_promotion',mode='status',language='model',
        backend='protected-domain-publisher-v1',effects=('service_state_read',))
    monkeypatch.setattr(mcp_server,'authorize_mcp_invocation',lambda *a,**kw:replace(admission,admitted=False))
    assert mcp_server.get_domain_promotion('0'*32)['status']=='ISOLATION_UNSUPPORTED'


@pytest.mark.parametrize('sign',[True,False])
def test_protected_signer_understands_only_approved_promotion_signing(promotion,monkeypatch,sign):
    from pipeline.protected_signer import sign_approved_artifact
    p=promotion;rid=p.request(sign=sign);p.decide(rid)
    root=p.service.root/rid;request=json.loads((root/'request.json').read_text())
    trust=p.candidate.parent/'trust.json';trust.write_text(json.dumps({'keys':[{'key_id':REVIEWER}]}))
    for name,value in {'FORMALSPECGEN_APPROVAL_GNUPGHOME':p.service.verifier_home,
        'FORMALSPECGEN_APPROVAL_TRUST_REGISTRY':trust,'FORMALSPECGEN_SIGNER_GNUPGHOME':p.service.verifier_home,
        'FORMALSPECGEN_SIGNING_KEY':SIGNER}.items():monkeypatch.setenv(name,str(value))
    kwargs=dict(request_path=root/'request.json',decision_path=root/'decision.json',approval_signature=root/'decision.json.sig',
        artifact=Path(request['artifact']['path']),output=Path(request['operation']['signature_destination']),runner=p.runner)
    if sign:
        result=sign_approved_artifact(**kwargs)
        assert result['status']=='SIGNED' and result['signed_artifact_sha256']==request['artifact']['sha256']
    else:
        with pytest.raises(ApprovalError,match='not requested'):sign_approved_artifact(**kwargs)


def test_registry_and_requester_must_be_configured(promotion):
    p=promotion
    kwargs=dict(verifier_home=p.service.verifier_home,authorized_reviewers={REVIEWER},signer=None,
        signing_identity=SIGNER,reviewer_identity=REVIEWER,validation_policy=p.policy,revocations=p.revocations)
    with pytest.raises(ApprovalError,match='principal'):DomainPromotionApprovalService(p.service.root,registry=p.registry,principal='',**kwargs)
    link=p.candidate.parent/'linked-registry';link.symlink_to(p.registry,target_is_directory=True)
    with pytest.raises(ApprovalError,match='registry'):DomainPromotionApprovalService(p.service.root,registry=link,principal='operator',**kwargs)


@pytest.mark.parametrize('mutation',['profile','claim','snapshot-path','signature-path','binding-size','descriptor-context'])
def test_signed_malformed_request_cannot_expand_authority(promotion,mutation):
    p=promotion;rid=p.request();path=p.service.root/rid/'request.json';request=json.loads(path.read_text())
    if mutation=='profile':request['admission_profile_sha256']='0'*64
    elif mutation=='claim':request['verification']['claim']='UNBOUNDED_PROOF'
    elif mutation=='snapshot-path':request['operation']['captured_candidate']['path']=str(p.candidate)
    elif mutation=='signature-path':request['operation']['signature_destination']=str(p.registry/'unapproved.sig')
    elif mutation=='binding-size':request['operation']['candidate']['size']=-1
    else:request['operation']['context_sha256']='0'*64
    path.write_text(json.dumps(request));p.decide(rid)
    with pytest.raises(ApprovalError):p.service.execute(rid)
    assert not (p.registry/'switch.json').exists()


@pytest.mark.parametrize('raw',[b'\xff',b'['*6000+b']'*6000,b'{"schema":"a","schema":"b"}'])
def test_ambiguous_or_unreadable_control_json_is_rejected(promotion,raw):
    p=promotion;rid=p.request();(p.service.root/rid/'request.json').write_bytes(raw)
    with pytest.raises((ApprovalError,ValueError)):p.service.publish_approved(rid)
    assert not (p.registry/'switch.json').exists()


def test_retry_recovers_intent_created_before_publication(promotion,monkeypatch):
    p=promotion;rid=p.request(sign=True);p.decide(rid)
    import pipeline.domain_promotion_approval as module
    original=module.os.replace
    def interrupt(source,destination):
        if Path(destination)==p.registry/'switch.json':
            raise OSError('simulated interruption before rename')
        return original(source,destination)
    monkeypatch.setattr(module.os,'replace',interrupt)
    with pytest.raises(OSError):p.service.publish_approved(rid)
    assert not (p.registry/'switch.json').exists()
    assert (p.service.root/rid/'publication-intent.json').exists()
    monkeypatch.setattr(module.os,'replace',original)
    assert p.service.execute(rid)['status']=='PROMOTED'
    assert p.state.signer_calls==1


def test_approved_inconsistent_snapshot_is_not_promoted(promotion):
    from pipeline.approval_service import _canonical_bytes
    p=promotion;rid=p.request();path=p.service.root/rid/'request.json';request=json.loads(path.read_text())
    snapshot=Path(request['operation']['captured_candidate']['path'])
    snapshot.write_bytes(snapshot.read_bytes()+b' ')
    request['operation']['captured_candidate'].update(sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),size=snapshot.stat().st_size)
    descriptor=Path(request['evidence_manifest']['path']);descriptor.write_bytes(_canonical_bytes(request['operation']))
    request['evidence_manifest'].update(sha256=hashlib.sha256(descriptor.read_bytes()).hexdigest(),size=descriptor.stat().st_size)
    path.write_text(json.dumps(request));p.decide(rid)
    with pytest.raises(ApprovalError,match='captured promotion inputs'):p.service.publish_approved(rid)
    assert not (p.registry/'switch.json').exists()
