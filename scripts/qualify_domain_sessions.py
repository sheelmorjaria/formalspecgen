#!/usr/bin/env python3
# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Replay trusted CI's scoped domain-session and human promotion handoff."""
import argparse
import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

import anyio
import mcp_server
from pipeline.approval_service import ApprovalService,_canonical_bytes,_verify_detached_signature
from pipeline.domain_v2 import DomainSpecV2
from pipeline.domain_v2_evidence import verify_evidence_envelope,canonical_sha256
from pipeline.domain_v2_promotion import candidate_sha256
from pipeline.parity_inventory import _canonical_sha256


def require(value,message):
    if not value:raise ValueError(message)


def evaluate(record,revision,tree,plan):
    require(record['schema']=='formalspecgen-domain-session-acceptance-v1','unsupported session observation')
    require(record['revision']==revision and record['tree']==tree,'revision/tree mismatch')
    require(record['plan_sha256']==_canonical_sha256(plan),'plan mismatch')
    schemas={tool.name:tool.inputSchema for tool in anyio.run(mcp_server.create_server().list_tools)}
    required={'start_domain_session','get_domain_session','continue_domain_session','finalize_domain_candidate',
              'validate_domain','request_domain_promotion','complete_domain_promotion'}
    require(required<=record['schemas'].keys(),'missing transport stages')
    for name,schema in record['schemas'].items():require(schema==schemas[name],'observed tool schema mismatch')
    calls=record['calls']
    def results(tool):return [c for c in calls if c['tool']==tool]
    start=results('start_domain_session')[0];rid=start['result']['session_id']
    require(start['result']['status']=='CLARIFYING','elicitation not observed')
    require(any(c['result']['status']=='SESSION_ACCESS_DENIED' for c in results('get_domain_session')),'ownership rejection missing')
    require(any(c['result']['status']=='SESSION_REVISION_CONFLICT' for c in results('continue_domain_session')),'revision rejection missing')
    versions=record['session_events'];require(set(versions)=={f'{i:03d}.json' for i in range(4)},'session history incomplete')
    previous=None
    states=[]
    for i in range(4):
        event=dict(versions[f'{i:03d}.json']);observed=event.pop('sha256')
        require(observed==hashlib.sha256(_canonical_bytes(event)).hexdigest(),'session event digest mismatch')
        require(event['session_id']==rid and event['revision']==i and event['previous_sha256']==previous,'session history mismatch')
        previous=observed;states.append(event['status'])
    require(states==['CLARIFYING','READY','PREPARED','FINALIZED'],'session state transition mismatch')
    initial,last=versions['000.json'],versions['003.json']
    for key in ('idea','provider','model'):require(initial[key]==start['arguments'][key],'session request mismatch')
    require(last['answers']==next(c['arguments']['answers'] for c in results('continue_domain_session') if c['result']['status']=='READY'),'answer binding mismatch')
    content=record['candidate_bytes'].encode();spec=DomainSpecV2.model_validate_json(content)
    require(spec.review_status=='unreviewed' and candidate_sha256(spec)==last['candidate_sha256'],'candidate semantic identity mismatch')
    require(last['candidate_text'].encode()==content,'prepared candidate bytes mismatch')
    binding=last['candidate_artifact']
    require(binding=={'path':str(Path(last['output_root'])/last['candidate_relative']),
        'sha256':hashlib.sha256(content).hexdigest(),'size':len(content)},'candidate artifact binding mismatch')
    finalized=results('finalize_domain_candidate');require(len(finalized)==2,'finalization retry missing')
    for call in finalized:
        require(call['result']['status']=='FINALIZED' and call['result']['candidate_artifact']==binding and
            call['result']['claim']=='NO_PROOF','finalization outcome mismatch')
    validation_call=results('validate_domain')[0];validated=validation_call['result']
    require(validation_call['arguments']==finalized[0]['result']['validate_domain'] and validated['status']=='VALIDATED','validation handoff mismatch')
    raw_validation=record['validation_bytes'].encode();envelope=json.loads(raw_validation)
    require(verify_evidence_envelope(envelope),'invalid validation envelope')
    require(envelope['evidence']['candidate_sha256']==last['candidate_sha256'],'validation candidate mismatch')
    require(hashlib.sha256(raw_validation).hexdigest()==validated['validation_artifact']['sha256'],'validation artifact mismatch')
    context=envelope['evidence']['applicability_context']
    for name,digest in context['implementation']['components'].items():
        require(hashlib.sha256(subprocess.check_output(['git','show',f'HEAD:pipeline/{name}'])).hexdigest()==digest,'validation implementation mismatch')
    controls={name:base64.b64decode(value,validate=True) for name,value in record['approval_files'].items()}
    request=json.loads(controls['request.json']);decision=json.loads(controls['decision.json']);receipt=json.loads(controls['receipt.json'])
    request_sha=hashlib.sha256(controls['request.json']).hexdigest()
    ApprovalService._validate_decision(decision,request,request_sha)
    require(decision['decision']=='approve' and receipt['request_sha256']==request_sha,'human decision mismatch')
    require(receipt['operation']==request['operation'] and receipt['verification']==request['verification'] and
        receipt['verification']['claim']=='NO_PROOF' and receipt['claim_upgraded_by_signing'] is False,'promotion receipt mismatch')
    op=request['operation'];reviewed=record['reviewed_bytes'].encode();domain=json.loads(reviewed)
    requested=results('request_domain_promotion')[0]
    require(requested['result']['approval']['request_sha256']==request_sha and request['action']=='promote-domain-v2' and
        request['request_id']==request['operation_id']==requested['result']['approval']['request_id'],'promotion request mismatch')
    require(request['admission_profile_sha256']==requested['result']['mcp_admission']['profile_sha256'],'promotion admission mismatch')
    require(hashlib.sha256(_canonical_bytes(op)).hexdigest()==request['evidence_manifest']['sha256'],'promotion descriptor mismatch')
    require(requested['arguments']=={'name':spec.module_name,'candidate':binding['path'],
        'validation_evidence':validated['validation_artifact']['path']},'promotion argument handoff mismatch')
    require(op['candidate']['sha256']==binding['sha256'] and op['validation_artifact_sha256']==hashlib.sha256(raw_validation).hexdigest(),'promotion input binding mismatch')
    require(domain['accepted_candidate_sha256']==last['candidate_sha256'] and domain['accepted_validation_artifact_sha256']==op['validation_artifact_sha256'] and
        domain['approval_operation_id']==request['request_id'],'reviewed artifact identity mismatch')
    require(hashlib.sha256(reviewed).hexdigest()==request['artifact']['sha256']==receipt['publication']['sha256'],'reviewed artifact bytes mismatch')
    require(receipt['status']=='PROMOTED' and receipt['decision']=='approve' and
        receipt['artifact']==request['artifact'] and receipt['evidence_manifest']==request['evidence_manifest'] and
        receipt['publication']=={**request['artifact'],'path':op['destination']} and
        receipt['publication']['size']==len(reviewed),'publication receipt binding mismatch')
    expected={**context,'envelope_candidate_sha256':context['candidate_sha256'],
        'envelope_generated_tla_sha256':next(v['sha256'] for k,v in context['generated_models'].items() if k.endswith('.tla'))}
    require(domain['accepted_applicability_sha256']==canonical_sha256(expected)==op['context_sha256'],'applicability context mismatch')
    require(any(c['result']['status']=='APPROVAL_REQUIRED' for c in results('complete_domain_promotion')),'approval absence not observed')
    promoted=next(c['result'] for c in results('complete_domain_promotion') if c['result']['status']=='PROMOTED')
    require(promoted['approval_receipt']['sha256']==hashlib.sha256(controls['receipt.json']).hexdigest(),'returned receipt mismatch')
    with tempfile.TemporaryDirectory(prefix='session-replay-') as directory:
        root=Path(directory);home=root/'gpg';home.mkdir(mode=0o700)
        subprocess.run(['gpg','--homedir',str(home),'--batch','--import'],input=record['public_keys'],text=True,check=True,capture_output=True)
        decision_path=root/'decision.json';decision_path.write_bytes(controls['decision.json'])
        signature=root/'decision.sig';signature.write_bytes(controls['decision.json.sig'])
        _verify_detached_signature(decision_path,signature,gpg_home=home,authorized_keys={record['reviewer']},expected_identity=record['reviewer'],runner=subprocess.run)
    return {'schema':'formalspecgen-domain-session-qualification-v1','revision':revision,'tree':tree,
        'plan_sha256':_canonical_sha256(plan),'status':'QUALIFIED','scope':'V2 resumable domain creation and authenticated promotion handoff',
        'whole_command_parity_complete':False,'candidate_sha256':last['candidate_sha256'],
        'candidate_artifact_sha256':binding['sha256'],'reviewed_artifact_sha256':hashlib.sha256(reviewed).hexdigest(),
        'acceptance_sha256':canonical_sha256(record)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    require(not subprocess.check_output(['git','status','--porcelain'],text=True).strip(),'qualification requires a clean revision')
    revision=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    tree=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip()
    report=evaluate(json.loads(args.evidence.read_text()),revision,tree,json.loads(Path('mcpdocs/mcp_parity_plan.json').read_text()))
    args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))


if __name__=='__main__':main()
