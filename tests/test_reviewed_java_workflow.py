# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Captured input, contract preservation and publication boundary contracts."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace

import pytest
import mcp_server
from pipeline.execution import ExecutionObservation
from pipeline.isolated_verification import IsolatedVerificationResult
from pipeline.reviewed_java_workflow import ReviewedJavaRequest, run_reviewed_java, REVIEWED_JAVA_LIMITS
from pipeline.workflow_contracts import WorkflowContext
from pipeline.v2_jml_serializer import render_class
from pipeline.domain_v2_promotion import ReviewedDomainSpecV2
from test_domain_promotion_approval import promotion


@pytest.fixture
def java(promotion, tmp_path, monkeypatch):
    p = promotion
    rid = p.request(); p.decide(rid); p.service.execute(rid)
    reviewed = p.registry / 'switch.json'
    code = render_class(ReviewedDomainSpecV2.model_validate_json(reviewed.read_bytes()))
    scaffold = tmp_path / 'Switch.java'; scaffold.write_text(code)
    candidate = tmp_path / 'candidate' / 'Switch.java'; candidate.parent.mkdir()
    candidate.write_text(code.replace('public void enable() {}', 'public void enable() { enabled = true; }'))
    monkeypatch.chdir(tmp_path)
    request = ReviewedJavaRequest(str(reviewed), str(p.validation), str(p.candidate))
    def run(request=request, **kwargs):
        return run_reviewed_java(request, WorkflowContext.for_cli(request.required_effects(),
            output_root=tmp_path / 'output', resource_budget=REVIEWED_JAVA_LIMITS), **kwargs)
    return SimpleNamespace(p=p, reviewed=reviewed, scaffold=scaffold, candidate=candidate,
        code=code, request=request, run=run, root=tmp_path)


def observed(source, mode, backend):
    raw = source.read_bytes()
    observation = ExecutionObservation(status='COMPLETED', exit_code=0, output='',
        requested_policy={'network':'denied'}, enforced_policy={'network':'denied'},
        policy_compliance='ENFORCED', snapshot_files=({'path':source.name,
        'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)},),
        snapshot_manifest_sha256='a'*64, tool='openjml', command=('openjml','--esc',source.name))
    return IsolatedVerificationResult({'exit_code':0,'output':''},(observation,))


def impl(java, **kwargs):
    return replace(java.request, operation='implement', scaffold=str(java.scaffold),
        candidate=str(java.candidate), **kwargs)


def test_generation_is_deterministic_and_never_executes_or_calls_provider(java):
    def forbidden(*a, **k):raise AssertionError('generation performed an unauthorized effect')
    a=java.run(execute=forbidden,chat=forbidden); b=java.run(execute=forbidden,chat=forbidden)
    assert a['status']=='CANONICAL_CONTRACT' and a['claim']=='NO_PROOF'
    assert a['request_satisfied'] and not a['source_refinement_proved']
    assert Path(a['code_file']).read_bytes()==Path(b['code_file']).read_bytes()==java.code.encode()
    receipt=json.loads(Path(a['evidence_file']).read_bytes())
    assert receipt['contract_sha256']==hashlib.sha256(java.code.encode()).hexdigest()
    for label, identity in receipt['input_identities'].items():
        assert hashlib.sha256(Path(a['code_file']+f'.inputs/{label}').read_bytes()).hexdigest()==identity['sha256']


def test_explicit_candidate_preserves_native_claim_and_exact_bytes(java):
    result=java.run(impl(java),execute=observed)
    assert result['status']=='VERIFIED',result
    assert result['claim']=='DEDUCTIVE_PROOF' and result['request_satisfied']
    assert not result['source_refinement_proved'] and not result['review_authenticity_established']
    assert Path(result['code_file']).read_bytes()==java.candidate.read_bytes()


@pytest.mark.parametrize('change',['candidate','reviewed','validation','candidate-format','legacy','scaffold','contract','assumption','annotation'])
def test_mismatched_inputs_fail_before_execution(java,change):
    request=impl(java)
    if change=='candidate':
        value=json.loads(java.p.candidate.read_text());value['state_variables'][0]['initial']=True;java.p.candidate.write_text(json.dumps(value))
    elif change=='reviewed':
        value=json.loads(java.reviewed.read_text());value['state_variables'][0]['initial']=True;java.reviewed.write_text(json.dumps(value))
    elif change=='validation':java.p.validation.write_text('{}')
    elif change=='candidate-format':java.p.candidate.write_text(java.p.candidate.read_text()+'\n')
    elif change=='legacy':
        value=json.loads(java.reviewed.read_text());value.pop('accepted_validation_artifact_sha256');java.reviewed.write_text(json.dumps(value))
    elif change=='scaffold':java.scaffold.write_text(java.code+'\n')
    else:
        text=java.candidate.read_text()
        if change=='contract':text=text.replace('ensures enabled == true','ensures true')
        elif change=='assumption':text=text.replace('enabled = true;', '//@ assume false;\n enabled = true;')
        else:text=text.replace('public void enable()', '/*@ skipesc @*/ public void enable()')
        java.candidate.write_text(text)
    def forbidden(*a,**k):raise AssertionError('invalid input reached execution')
    result=java.run(request,execute=forbidden)
    assert not result['request_satisfied'] and result['claim']=='NO_PROOF',result
    assert not (java.root/'output').exists()


@pytest.mark.parametrize('kind',['symlink','outside','oversize','fifo'])
def test_unsafe_capture_is_rejected(java,kind):
    path=java.root/'bad'
    if kind=='symlink':path.symlink_to(java.reviewed)
    elif kind=='outside':path=java.root.parent/'outside'
    elif kind=='oversize':path.write_bytes(b'x'*(REVIEWED_JAVA_LIMITS['max_input_bytes']+1))
    else:
        import os
        os.mkfifo(path)
    result=java.run(replace(java.request,reviewed_domain=str(path)))
    assert result['status']=='FAIL' and result['claim']=='NO_PROOF'


@pytest.mark.parametrize('effect',['workspace_read','workspace_write_new','external_execution','evidence_publication','provider_access'])
def test_missing_effect_rejects_before_any_side_effect(java,effect):
    request=replace(impl(java),candidate=None)
    context=WorkflowContext.for_cli(tuple(e for e in request.required_effects() if e!=effect), output_root=java.root/'out')
    def forbidden(*a,**k):raise AssertionError('missing authority reached an effect')
    result=run_reviewed_java(request,context,execute=forbidden,chat=forbidden)
    assert result['status']=='FAIL' and result['claim']=='NO_PROOF'


def test_one_bounded_provider_call(java):
    calls=[]
    def chat(*args):calls.append(args);return '```java\n'+java.candidate.read_text()+'\n```','fixture',{}
    result=java.run(replace(impl(java),candidate=None),execute=observed,chat=chat)
    assert result['status']=='VERIFIED' and len(calls)==1,result
    assert result['implementation_provenance']['kind']=='provider'


@pytest.mark.parametrize('output',[None,'x'*(128*1024+1),'```java\npublic class Other {}\n```'])
def test_bad_provider_output_cannot_execute(java,output):
    def forbidden(*a,**k):raise AssertionError('invalid provider output executed')
    result=java.run(replace(impl(java),candidate=None),execute=forbidden,chat=lambda *a:(output,'fixture',{}))
    assert result['status']=='FAIL' and not result['request_satisfied']


@pytest.mark.parametrize('backend',['unbound','unenforced','wrong-source','failed','dropped','timeout'])
def test_backend_failure_or_missing_observation_cannot_mint_proof(java,backend):
    def execute(*a,**k):
        if backend=='unbound':return IsolatedVerificationResult({'exit_code':0,'output':''})
        result=observed(*a,**k)
        if backend=='unenforced':
            return IsolatedVerificationResult(result.payload,(replace(result.observations[0],policy_compliance='NOT_ENFORCED'),))
        if backend=='wrong-source':
            return IsolatedVerificationResult(result.payload,(replace(result.observations[0],snapshot_files=({'path':'Switch.java','sha256':'f'*64},)),))
        return IsolatedVerificationResult({'exit_code':124 if backend=='timeout' else 1 if backend=='failed' else 0,
            'output':'Not implemented for static checking' if backend=='dropped' else ''},result.observations)
    result=java.run(impl(java),execute=execute)
    assert not result['request_satisfied'] and result['claim']=='NO_PROOF',result
    assert Path(result['evidence_file']).is_file()


def test_no_replacement_and_symlinked_output(java):
    request=replace(java.request,out_file='Switch.java')
    first=java.run(request); assert first['request_satisfied']
    assert java.run(request)['code']=='OUTPUT_ALREADY_EXISTS'
    link=java.root/'output'/'link';link.symlink_to(java.root,target_is_directory=True)
    assert not java.run(replace(request,out_file='link/Switch.java'))['request_satisfied']
    for name in ('../Switch.java','/Switch.java','Wrong.java'):
        assert not java.run(replace(request,out_file=name))['request_satisfied']


def test_mcp_profiles_use_same_service_and_reject_unsupported(java,monkeypatch):
    monkeypatch.setenv('FORMALSPECGEN_MCP_STRICT_JAVA_ONLY','1')
    monkeypatch.setenv('FORMALSPECGEN_MCP_OUTPUT_ROOT','output')
    domains=java.root/'domains'/'v2';domains.mkdir(parents=True)
    (domains/'switch.json').write_bytes(java.reviewed.read_bytes())
    result=mcp_server.draft_canonical_contract('switch',validation_evidence=str(java.p.validation),domain_candidate=str(java.p.candidate))
    assert result['status']=='CANONICAL_CONTRACT' and result['mcp_admission']['profile'],result
    assert not mcp_server.draft_canonical_contract('switch',lang='rust')['request_satisfied']
    assert not mcp_server.implement_code(str(java.scaffold),assurance_level='lightweight')['request_satisfied']
    monkeypatch.setattr('pipeline.reviewed_java_workflow.execute_isolated_verification',observed)
    result=mcp_server.implement_code(str(java.scaffold),v2_reviewed_domain=str(java.reviewed),
        v2_validation_evidence=str(java.p.validation),domain_candidate=str(java.p.candidate),candidate=str(java.candidate))
    assert result['status']=='VERIFIED' and result['mcp_admission']['profile'],result


@pytest.mark.parametrize('values',[{'operation':'other'},{'reviewed_domain':None},{'requirement':'x'*16385},
    {'provider':'unknown'},{'model':' '},{'candidate':'x'},{'operation':'implement'},
    {'out_file':False},{'operation':'implement','scaffold':'x','candidate':True},
    {'operation':'implement','scaffold':'x','candidate':'y','model':'unused'}])
def test_invalid_request_never_dispatches(java,values):
    with pytest.raises(ValueError):replace(java.request,**values)


def test_cli_uses_same_captured_generation_and_implementation(java,monkeypatch,capfd):
    from pipeline import cli
    domains=java.root/'domains'/'v2';domains.mkdir(parents=True)
    (domains/'switch.json').write_bytes(java.reviewed.read_bytes())
    draft=['draft','A switch','--canonical-domain','switch','--generation-only','--no-clarify',
        '--domain-candidate',str(java.p.candidate),'--validation-evidence',str(java.p.validation),
        '--out','output','--out-file','cli/Switch.java','--json','-']
    assert cli.main(draft)==0
    value=json.loads(capfd.readouterr().out)
    assert value['operation_satisfied'] and value['result']['claim']=='NO_PROOF'
    assert Path(value['result']['code_file']).read_bytes()==java.code.encode()
    monkeypatch.setattr('pipeline.reviewed_java_workflow.execute_isolated_verification',observed)
    command=['implement',str(java.scaffold),'--canonical-java','--v2-reviewed-domain',str(java.reviewed),
        '--v2-validation-evidence',str(java.p.validation),'--domain-candidate',str(java.p.candidate),
        '--candidate',str(java.candidate),'--out','output','--json','-']
    assert cli.main(command)==0
    value=json.loads(capfd.readouterr().out)
    assert value['operation_satisfied'] and value['result']['claim']=='DEDUCTIVE_PROOF'
    assert value['result']['source_refinement_proved'] is False


@pytest.mark.parametrize('arguments',[
    ['draft','Switch','--generation-only','--no-clarify'],
    ['draft','Switch','--generation-only','--no-clarify','--canonical-domain','switch','--model','ignored'],
    ['draft','Switch','--domain-candidate','candidate.json'],
    ['implement','Switch.java','--canonical-java','--method-proof-only'],
    ['implement','Switch.java','--canonical-java'],
    ['implement','Switch.java','--candidate','candidate.java'],
])
def test_cli_rejects_incomplete_or_unsupported_new_profiles(java,capfd,arguments):
    from pipeline import cli
    assert cli.main(arguments)==2
    capfd.readouterr()
    assert not (java.root/'output').exists()


def test_missing_output_invalid_limits_and_output_publication_failure(java,monkeypatch):
    request=java.request
    context=WorkflowContext.for_cli(request.required_effects())
    assert run_reviewed_java(request,context)['status']=='FAIL'
    context=WorkflowContext.for_cli(request.required_effects(),output_root=java.root/'out',resource_budget={'max_result_bytes':0})
    assert run_reviewed_java(request,context)['status']=='FAIL'
    context=WorkflowContext.for_cli(request.required_effects(),output_root=java.root/'out',resource_budget={'max_result_bytes':1})
    assert run_reviewed_java(request,context)['code']=='RESULT_LIMIT_EXCEEDED'
    def fail(*a,**k):raise OSError('interrupted publication')
    monkeypatch.setattr('pipeline.reviewed_java_workflow.publish_new_artifacts',fail)
    result=java.run()
    assert result['claim']=='NO_PROOF' and not result['request_satisfied']
    assert 'publication' not in result


def test_generated_source_limit_and_actual_tool_identity(java):
    request=java.request
    context=WorkflowContext.for_cli(request.required_effects(),output_root=java.root/'out',resource_budget={'max_source_bytes':1})
    assert run_reviewed_java(request,context)['status']=='FAIL'
    tool=java.root/'openjml';tool.write_bytes(b'synthetic identity')
    def execute(*a,**k):
        result=observed(*a,**k)
        return IsolatedVerificationResult(result.payload,(replace(result.observations[0],command=(str(tool),'-esc')),))
    result=java.run(impl(java),execute=execute)
    assert result['tool_identities']==[{'path':str(tool),'sha256':hashlib.sha256(tool.read_bytes()).hexdigest()}]


def test_reviewed_candidate_cannot_replace_original_input(java):
    value=json.loads(java.p.candidate.read_text());value['review_status']='reviewed'
    java.p.candidate.write_text(json.dumps(value))
    assert 'must be unreviewed' in java.run()['message']


def test_native_proof_cannot_survive_failed_publication(java,monkeypatch):
    def fail(*a,**k):raise OSError('receipt publication interrupted')
    monkeypatch.setattr('pipeline.reviewed_java_workflow.publish_new_artifacts',fail)
    result=java.run(impl(java),execute=observed)
    assert not result['request_satisfied'] and result['claim']=='NO_PROOF'
    assert result['execution_stages'] and 'publication' not in result
