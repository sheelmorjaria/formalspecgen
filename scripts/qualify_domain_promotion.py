#!/usr/bin/env python3
# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Replay trusted CI's scoped V2 promotion observations; never grant V1 parity."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

import anyio
import mcp_server
from pipeline.approval_service import ApprovalService, _verify_detached_signature
from pipeline.mcp_policy import authorize_mcp_invocation
from pipeline.parity_inventory import _canonical_sha256

CASES = {'create_unsigned','create_signed','replace_unsigned','replace_signed',
         'denied','stale_candidate','destination_changed','interrupted','competing'}


def require(value, message):
    if not value:
        raise ValueError(message)


def evaluate(directory: Path, *, revision: str, tree: str, plan: dict) -> dict:
    records=[json.loads(path.read_text()) for path in sorted(directory.glob('*.json'))
            if path.name != 'qualification.json']
    require(len(records)==len(CASES) and {r['case'] for r in records}==CASES,'missing or duplicate V2 cases')
    tools={tool.name:tool.inputSchema for tool in anyio.run(mcp_server.create_server().list_tools)}
    profile=authorize_mcp_invocation('request_domain_promotion',mode='request',language='model',
        backend='protected-domain-publisher-v1',effects=('workspace_read','service_state_read','service_state_write')).summary()['profile_sha256']
    outcomes=[]
    for record in records:
        case=record['case']
        require(record['schema']=='formalspecgen-domain-promotion-acceptance-v1','unsupported acceptance schema')
        require(record['revision']==revision and record['tree']==tree,'revision/tree mismatch')
        require(record['plan_sha256']==_canonical_sha256(plan),'plan mismatch')
        python=Path(record['installed_python'] or '')
        server=Path(record['installed_server'] or '')
        require(python.is_absolute() and server.is_relative_to(python.parent.parent),'installed server identity missing')
        for tool,schema in record['schemas'].items():
            require(schema==tools[tool],f'observed schema drift: {tool}')
        require({'request_domain_promotion','get_domain_promotion','complete_domain_promotion','validate_domain'} <= record['schemas'].keys(),'missing transport stages')
        calls=record['calls']
        require(any(c['tool']=='complete_domain_promotion' and c['result']['status']=='APPROVAL_REQUIRED' for c in calls),'approval absence not observed')
        require(any(c['tool']=='get_domain_promotion' and c['result']['status']=='DECISION_RECORDED' for c in calls),'inspection not observed')
        expected='DENIED' if case=='denied' else 'PROTECTED_PUBLICATION_FAILED' if case in {'stale_candidate','destination_changed'} else 'PROMOTED'
        require(record['completion']['status']==expected,'unexpected completion')
        require(record['completion']['claim']=='NO_PROOF','claim upgraded')
        require(any(c['tool']=='complete_domain_promotion' and c['result']==record['completion'] for c in calls),'completion is not a transport result')
        files={name:base64.b64decode(encoded,validate=True) for name,encoded in record['files'].items()}
        def bound(binding):
            content=files[binding['path']]
            require(len(content)==binding['size'] and hashlib.sha256(content).hexdigest()==binding['sha256'],'artifact binding mismatch')
            return content
        with tempfile.TemporaryDirectory(prefix='promotion-replay-') as temporary:
            root=Path(temporary);home=root/'gpg';home.mkdir(mode=0o700)
            subprocess.run(['gpg','--homedir',str(home),'--batch','--import'],input=record['public_keys'],text=True,check=True,capture_output=True)
            for rid in record['request_ids']:
                def control(name):
                    matches=[content for path,content in files.items() if path.endswith('/'+rid+'/'+name)]
                    require(len(matches)==1,'missing/ambiguous control artifact')
                    path=root/name;path.write_bytes(matches[0]);return path
                request_path=control('request.json');request=json.loads(request_path.read_bytes())
                decision_path=control('decision.json');decision=json.loads(decision_path.read_bytes())
                signature_path=control('decision.json.sig')
                request_sha=hashlib.sha256(request_path.read_bytes()).hexdigest()
                ApprovalService._validate_decision(decision,request,request_sha)
                _verify_detached_signature(decision_path,signature_path,gpg_home=home,
                    authorized_keys={record['reviewer']},expected_identity=record['reviewer'],runner=subprocess.run)
                require(request['request_id']==rid and request['operation_id']==rid and request['action']=='promote-domain-v2','operation identity mismatch')
                require(request['admission_profile_sha256']==profile,'admission profile mismatch')
                op=request['operation']
                requests=[c for c in calls if c['tool']=='request_domain_promotion' and c['result']['approval']['request_id']==rid]
                require(len(requests)==1,'request transport missing')
                observed=requests[0]
                require(observed['result']['approval']['request_sha256']==request_sha,'returned request digest mismatch')
                require(observed['arguments']=={'name':op['name'],'candidate':op['candidate']['path'],
                    'validation_evidence':op['validation']['path'],'sign':op['sign'],
                    'replace_reviewed_domain':op['replace']},'requested arguments not bound')
                require(request['verification']=={'status':'BOUNDED_VALIDATION_APPLICABLE','claim':'NO_PROOF','claim_upgraded_by_signing':False},'request claim upgraded')
                require(json.loads(bound(request['evidence_manifest']))==op,'operation descriptor mismatch')
                reviewed=json.loads(bound(request['artifact']))
                require(reviewed['approval_operation_id']==rid,'reviewed operation mismatch')
                require(reviewed['accepted_candidate_sha256']==op['candidate_sha256'] and reviewed['accepted_applicability_sha256']==op['context_sha256'],'applicability binding mismatch')
                validation=bound(op['captured_validation']);candidate=bound(op['captured_candidate'])
                require(hashlib.sha256(candidate).hexdigest()==op['candidate']['sha256'] and len(candidate)==op['candidate']['size'],'captured candidate mismatch')
                require(hashlib.sha256(validation).hexdigest()==op['validation']['sha256'] and len(validation)==op['validation']['size'],'captured validation mismatch')
                require(hashlib.sha256(validation).hexdigest()==op['validation_artifact_sha256']==reviewed['accepted_validation_artifact_sha256'],'validation digest mismatch')
                require(op['destination']==request['destination'] and op['sign']==(case in {'create_signed','replace_signed','interrupted','competing'}),'intent mismatch')
                require(bool(op['prior_destination'])==op['replace']==(case.startswith('replace') or case=='competing'),'replacement binding missing')
                receipts=[content for path,content in files.items() if path.endswith('/'+rid+'/receipt.json')]
                completed=[c['result'] for c in calls if c['tool']=='complete_domain_promotion' and c['arguments']['request_id']==rid and c['result']['status'] in {'PROMOTED','DENIED'}]
                if completed:
                    require(len(receipts)==1,'receipt missing')
                    receipt=json.loads(receipts[0])
                    require(receipt['request_sha256']==request_sha and receipt['operation']==op and receipt['verification']==request['verification'],'receipt binding mismatch')
                    require(receipt['claim_upgraded_by_signing'] is False and receipt['decision']==decision['decision'],'receipt claim/decision mismatch')
                    require(receipt['artifact']==request['artifact'] and receipt['evidence_manifest']==request['evidence_manifest'] and
                        receipt['admission_profile_sha256']==profile and receipt['policy_version']==request['policy_version'] and
                        receipt['reviewer_identity']==record['reviewer'],'receipt authority mismatch')
                    for result in completed:
                        require(result['approval_receipt']['sha256']==hashlib.sha256(receipts[0]).hexdigest(),'returned receipt digest mismatch')
                    if receipt['status']=='PROMOTED':
                        require(bound(receipt['publication'])==bound(request['artifact']),'published bytes mismatch')
                        require(receipt['publication']['path']==op['destination'],'publication destination mismatch')
                        require(bool(receipt['signature'])==op['sign'],'signing state mismatch')
                        if op['sign']:
                            signature=root/'published.sig';signature.write_bytes(bound(receipt['signature']))
                            artifact=root/'published.json';artifact.write_bytes(bound(receipt['publication']))
                            _verify_detached_signature(artifact,signature,gpg_home=home,
                                authorized_keys={record['signer']},expected_identity=record['signer'],runner=subprocess.run)
                else: require(not receipts,'failed action has completion receipt')
        if case=='competing':
            statuses=[c['result']['status'] for c in calls if c['tool']=='complete_domain_promotion']
            require(statuses.count('PROTECTED_PUBLICATION_FAILED')==1 and statuses.count('PROMOTED')==2,'competing request/retry outcome mismatch')
        if case=='interrupted':
            require(any(c['result'].get('phases',{}).get('receipt')=='NOT_COMMITTED' and c['result']['phases']['publication']=='PUBLISHED' for c in calls),'interrupted publication not observed')
        outcomes.append({'case':case,'status':expected,'artifact_sha256':hashlib.sha256(json.dumps(record,sort_keys=True,separators=(',',':')).encode()).hexdigest()})
    return {'schema':'formalspecgen-domain-promotion-qualification-v1','revision':revision,'tree':tree,
        'plan_sha256':_canonical_sha256(plan),'scope':'V2 authenticated promotion only',
        'status':'QUALIFIED','whole_command_parity_complete':False,'legacy_v1':'operator-only','cases':outcomes}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    revision=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    tree=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip()
    require(not subprocess.check_output(['git','status','--porcelain'],text=True).strip(),'qualification requires a clean committed revision')
    report=evaluate(args.evidence,revision=revision,tree=tree,plan=json.loads(Path('mcpdocs/mcp_parity_plan.json').read_text()))
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'revision':revision,'scope':report['scope'],'cases':len(report['cases'])}))


if __name__=='__main__':
    main()
