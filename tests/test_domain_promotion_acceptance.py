# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Provisioned real TLC/MCP/GPG/protected-publisher handoff."""
import base64
import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import anyio
import pytest

from pipeline.approval_service import record_human_decision
from scripts.mcp_acceptance_adapters import _call_tool
from test_domain_promotion_approval import candidate_value


CASES = ('create_unsigned','create_signed','replace_unsigned','replace_signed',
         'denied','stale_candidate','destination_changed','interrupted','competing')


@pytest.mark.parametrize('case',CASES)
def test_real_mcp_promotion_requires_external_human_decision(tmp_path,case):
    if os.environ.get('FORMALSPECGEN_REQUIRE_APPROVAL_ACCEPTANCE') != '1':
        pytest.skip('real promotion requires provisioned TLC, sandbox and GPG identities')
    name = 'switch_' + uuid.uuid4().hex[:12]
    value = candidate_value(); value['module_name'] = name
    untrusted = tmp_path / 'pipeline'; untrusted.mkdir()
    (untrusted / '__init__.py').write_text('raise RuntimeError("protected helper imported workspace code")\n')
    candidate = tmp_path / f'domains/candidates/{name}.v2.yaml'
    candidate.parent.mkdir(parents=True)
    candidate.write_text(json.dumps(value))
    python=os.environ.get('FORMALSPECGEN_PROMOTION_ACCEPTANCE_PYTHON')
    server=os.environ.get('FORMALSPECGEN_PROMOTION_ACCEPTANCE_SERVER')
    calls=[];schemas={}
    def decide(rid,decision='approve'):
        record_human_decision(Path(os.environ['FORMALSPECGEN_APPROVAL_ROOT']),rid,
            decision=decision,signing_key=os.environ['FORMALSPECGEN_ACCEPTANCE_REVIEWER_KEY'],
            gpg_home=Path(os.environ['FORMALSPECGEN_ACCEPTANCE_REVIEWER_GNUPGHOME']))
    async def run():
        async def call(tool, arguments):
            transport=await _call_tool(tmp_path,tool,[arguments],timeout_s=180,python=python,server=server)
            schemas[tool]=transport[2];result=transport[3][0]
            calls.append({'tool':tool,'arguments':arguments,'result':result})
            return result
        validated=await call('validate_domain',{'name':name})
        assert validated['status']=='VALIDATED',validated
        validation=validated['validation_artifact']
        destination=Path(os.environ['FORMALSPECGEN_PROMOTION_REGISTRY'])/(name+'.json')
        replace=case.startswith('replace') or case=='competing'
        if replace: destination.write_text('previous reviewed artifact')
        sign=case in ('create_signed','replace_signed','interrupted','competing')
        arguments={'name':name,'candidate':str(candidate),'validation_evidence':validation['path'],
                   'sign':sign,'replace_reviewed_domain':replace}
        requested=await call('request_domain_promotion',arguments)
        assert requested['status']=='PENDING',requested
        rid=requested['approval']['request_id'];request_ids=[rid]
        pending=await call('complete_domain_promotion',{'request_id':rid})
        assert pending['status']=='APPROVAL_REQUIRED',pending
        assert destination.exists()==replace
        decide(rid,'deny' if case=='denied' else 'approve')
        inspected=await call('get_domain_promotion',{'request_id':rid})
        assert inspected['status']=='DECISION_RECORDED',inspected
        if case=='stale_candidate': candidate.write_bytes(candidate.read_bytes()+b' ')
        if case=='destination_changed': destination.write_text('changed after approval')
        if case=='interrupted':
            program=("from pipeline.domain_promotion_approval import configured_service; "
                     "configured_service(publisher=False).publish_approved("+repr(rid)+
                     ",before_receipt=lambda: (_ for _ in ()).throw(RuntimeError('injected interruption')))")
            interrupted=subprocess.run([python or sys.executable,'-I','-c',program],cwd=tmp_path,
                capture_output=True,text=True)
            assert interrupted.returncode!=0 and 'injected interruption' in interrupted.stderr,interrupted.stderr
            inspected=await call('get_domain_promotion',{'request_id':rid})
            assert inspected['phases']['publication']=='PUBLISHED',inspected
            assert inspected['phases']['signing']=='SIGNED'
            assert inspected['phases']['receipt']=='NOT_COMMITTED'
        if case=='competing':
            other=await call('request_domain_promotion',arguments)
            other_id=other['approval']['request_id'];request_ids.append(other_id);decide(other_id)
            results=[]
            async def complete(request_id):
                results.append(await call('complete_domain_promotion',{'request_id':request_id}))
            async with anyio.create_task_group() as group:
                for request_id in request_ids:group.start_soon(complete,request_id)
            assert sorted(r['status'] for r in results)==['PROMOTED','PROTECTED_PUBLICATION_FAILED'],results
            result=next(r for r in results if r['status']=='PROMOTED')
            rid=json.loads(destination.read_text())['approval_operation_id']
        else: result=await call('complete_domain_promotion',{'request_id':rid})
        expected=('DENIED' if case=='denied' else
                  'PROTECTED_PUBLICATION_FAILED' if case in ('stale_candidate','destination_changed') else 'PROMOTED')
        assert result['status']==expected,result
        assert result['claim']=='NO_PROOF'
        if expected=='PROMOTED':
            assert result['publication']['sha256']==hashlib.sha256(destination.read_bytes()).hexdigest()
            reviewed=json.loads(destination.read_text())
            assert reviewed['accepted_validation_artifact_sha256']==validation['sha256']
            assert reviewed['accepted_candidate_sha256']==validated['candidate_sha256']
            assert reviewed['approval_operation_id']==rid
            assert bool(result.get('signature'))==sign
            if sign:
                verify=subprocess.run(['gpg','--homedir',os.environ['FORMALSPECGEN_APPROVAL_GNUPGHOME'],
                    '--batch','--verify',result['signature']['path'],str(destination)],capture_output=True,text=True)
                assert verify.returncode==0,verify.stderr
            retried=await call('complete_domain_promotion',{'request_id':rid})
            assert retried['approval_receipt']==result['approval_receipt']
        elif case=='denied': assert not destination.exists()
        elif case=='destination_changed':assert destination.read_text()=='changed after approval'
        else:assert not destination.exists()
        files={}
        def capture(path):
            path=Path(path)
            if path.is_file():files[str(path)]=base64.b64encode(path.read_bytes()).decode('ascii')
        capture(candidate);capture(validation['path']);capture(destination)
        for request_id in request_ids:
            root=Path(os.environ['FORMALSPECGEN_APPROVAL_ROOT'])/request_id
            for path in root.iterdir():capture(path)
            request=json.loads((root/'request.json').read_text())
            for binding in (request['artifact'],request['evidence_manifest'],request['operation']['captured_candidate'],request['operation']['captured_validation']):capture(binding['path'])
            capture(request['operation']['signature_destination'])
        public=subprocess.check_output(['gpg','--homedir',os.environ['FORMALSPECGEN_APPROVAL_GNUPGHOME'],
            '--batch','--armor','--export'],text=True)
        retained={'schema':'formalspecgen-domain-promotion-acceptance-v1','case':case,
            'revision':os.environ.get('GITHUB_SHA'),'tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip(),
            'plan_sha256':hashlib.sha256(json.dumps(json.loads(Path('mcpdocs/mcp_parity_plan.json').read_text()),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest(),
            'validation':validated,'request_ids':request_ids,'completion':result,'calls':calls,'schemas':schemas,
            'files':files,'public_keys':public,'reviewer':os.environ['FORMALSPECGEN_REVIEWER_IDENTITY'],
            'signer':os.environ['FORMALSPECGEN_SIGNING_IDENTITY'],'installed_python':python,'installed_server':server}
        export=os.environ.get('FORMALSPECGEN_PROMOTION_ACCEPTANCE_DIR')
        if export:
            path=Path(export);path.mkdir(parents=True,exist_ok=True)
            (path/(case+'.json')).write_text(json.dumps(retained,indent=2)+'\n')
    anyio.run(run)
