# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Real MCP sessions across restarted servers and an explicit local provider."""
import json
import base64
import os
import subprocess
import threading
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

import anyio
import pytest
from pipeline.domain_generator import DOMAIN_QUESTIONS_SYSTEM
from pipeline.implementation import IMPLEMENT_SYSTEM
from pipeline.approval_service import record_human_decision
from scripts.mcp_acceptance_adapters import _call_tool
from test_domain_promotion_approval import candidate_value


@contextmanager
def fixture_provider():
    module_name='switch_'+uuid.uuid4().hex[:12]
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            questions=request['messages'][0]['content']==DOMAIN_QUESTIONS_SYSTEM
            value={'questions':[{'id':'q1','category':'state','question':'Initial enabled state?','required':True}]} if questions else candidate_value()
            if not questions:value['module_name']=module_name
            answer=json.dumps(value)
            if request['messages'][0]['content']==IMPLEMENT_SYSTEM:
                answer=request['messages'][1]['content'].split('```java\n',1)[1].rsplit('\n```',1)[0]
                answer=answer.replace('public void enable() {}','public void enable() { enabled = true; }')
            content=json.dumps({'choices':[{'message':{'content':answer},'finish_reason':'stop'}],'model':'fixture','usage':{}}).encode()
            self.send_response(200);self.send_header('Content-Length',str(len(content)));self.end_headers();self.wfile.write(content)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield f'http://127.0.0.1:{server.server_port}/v1'
    finally:server.shutdown();server.server_close();thread.join(timeout=5)


def test_real_resumable_domain_session_transport(tmp_path):
    if os.environ.get('FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE')!='1':
        pytest.skip('requires explicitly provisioned MCP transport acceptance')
    root=tmp_path/'protected';root.mkdir(mode=0o700)
    workspace=tmp_path/'workspace';workspace.mkdir()
    with fixture_provider() as endpoint:
        env={'FORMALSPECGEN_SESSION_ROOT':str(root),'FORMALSPECGEN_SESSION_PRINCIPAL':'alice',
             'FORMALSPECGEN_MCP_OUTPUT_ROOT':'output','OPENAI_BASE_URL':endpoint,'OPENAI_API_KEY':'fixture'}
        calls=[];schemas={}
        async def run():
            async def call(tool,args,extra=None):
                transport=await _call_tool(workspace,tool,[args],environment={**env,**(extra or {})},timeout_s=120,
                    python=os.environ.get('FORMALSPECGEN_PROMOTION_ACCEPTANCE_PYTHON'),
                    server=os.environ.get('FORMALSPECGEN_PROMOTION_ACCEPTANCE_SERVER'))
                result=transport[3][0];schemas[tool]=transport[2]
                calls.append({'tool':tool,'arguments':args,'result':result});return result
            r=await call('start_domain_session',{'idea':'A switch with a boolean enabled state','provider':'openai','model':'fixture'})
            assert r['status']=='CLARIFYING',r
            rid=r['session_id']
            assert (await call('get_domain_session',{'session_id':rid},{'FORMALSPECGEN_SESSION_PRINCIPAL':'mallory'}))['status']=='SESSION_ACCESS_DENIED'
            r=await call('continue_domain_session',{'session_id':rid,'answers':{'q1':'Initially disabled'},'expected_revision':0})
            assert r['status']=='READY',r
            assert (await call('continue_domain_session',{'session_id':rid,'answers':{'q1':'enabled'},'expected_revision':0}))['status']=='SESSION_REVISION_CONFLICT'
            r=await call('finalize_domain_candidate',{'session_id':rid,'expected_revision':1})
            assert r['status']=='FINALIZED',r
            candidate=Path(r['candidate_artifact']['path']);raw=candidate.read_bytes()
            assert json.loads(raw)['review_status']=='unreviewed'
            retry=await call('finalize_domain_candidate',{'session_id':rid,'expected_revision':1})
            assert retry['candidate_artifact']==r['candidate_artifact'] and candidate.read_bytes()==raw
            if os.environ.get('FORMALSPECGEN_REQUIRE_DOMAIN_VALIDATION_ACCEPTANCE')=='1':
                validated=await call('validate_domain',r['validate_domain'])
                assert validated['status']=='VALIDATED',validated
                if os.environ.get('FORMALSPECGEN_REQUIRE_APPROVAL_ACCEPTANCE')=='1':
                    requested=await call('request_domain_promotion',{'name':r['validate_domain']['name'],'candidate':str(candidate),
                        'validation_evidence':validated['validation_artifact']['path']})
                    assert requested['status']=='PENDING',requested
                    pending=await call('complete_domain_promotion',{'request_id':requested['approval']['request_id']})
                    assert pending['status']=='APPROVAL_REQUIRED',pending
                    record_human_decision(Path(os.environ['FORMALSPECGEN_APPROVAL_ROOT']),requested['approval']['request_id'],
                        decision='approve',signing_key=os.environ['FORMALSPECGEN_ACCEPTANCE_REVIEWER_KEY'],
                        gpg_home=Path(os.environ['FORMALSPECGEN_ACCEPTANCE_REVIEWER_GNUPGHOME']))
                    promoted=await call('complete_domain_promotion',{'request_id':requested['approval']['request_id']})
                    assert promoted['status']=='PROMOTED' and promoted['claim']=='NO_PROOF',promoted
                    reviewed=json.loads(Path(promoted['publication']['path']).read_text())
                    assert reviewed['accepted_candidate_sha256']==r['candidate_sha256']
                    assert reviewed['accepted_validation_artifact_sha256']==validated['validation_artifact']['sha256']
                    if os.environ.get('FORMALSPECGEN_REQUIRE_REVIEWED_JAVA_ACCEPTANCE')=='1':
                        reviewed_copy=workspace/'domains'/'v2'/f"{reviewed['module_name']}.json"
                        reviewed_copy.parent.mkdir(parents=True,exist_ok=True)
                        reviewed_copy.write_bytes(Path(promoted['publication']['path']).read_bytes())
                        draft_args={'domain':reviewed['module_name'],'validation_evidence':validated['validation_artifact']['path'],
                            'domain_candidate':str(candidate),'out_file':'draft/Switch.java','requirement':'A boolean switch'}
                        drafted=await call('draft_canonical_contract',draft_args)
                        assert drafted['status']=='CANONICAL_CONTRACT' and drafted['claim']=='NO_PROOF',drafted
                        assert (await call('draft_canonical_contract',{**draft_args,'lang':'rust'}))['request_satisfied'] is False
                        assert (await call('draft_canonical_contract',draft_args))['code']=='OUTPUT_ALREADY_EXISTS'
                        implementation=workspace/'implementation'/'Switch.java';implementation.parent.mkdir()
                        implementation.write_text(Path(drafted['code_file']).read_text().replace('public void enable() {}','public void enable() { enabled = true; }'))
                        impl_args={'spec_path':drafted['code_file'],'v2_reviewed_domain':str(reviewed_copy),
                            'v2_validation_evidence':validated['validation_artifact']['path'],'domain_candidate':str(candidate),
                            'candidate':str(implementation),'out_file':'implementation/Switch.java'}
                        implemented=await call('implement_code',impl_args)
                        assert implemented['status']=='VERIFIED' and implemented['claim']=='DEDUCTIVE_PROOF',implemented
                        generated=await call('implement_code',{**impl_args,'candidate':None,'provider':'openai','model':'fixture','out_file':'provider/Switch.java'})
                        assert generated['status']=='VERIFIED' and generated['implementation_sha256']==implemented['implementation_sha256'],generated
                        invalid=workspace/'invalid.java';invalid.write_bytes(Path(drafted['code_file']).read_bytes())
                        failed=await call('implement_code',{**impl_args,'candidate':str(invalid),'out_file':'failed/Switch.java'})
                        assert not failed['request_satisfied'] and failed['claim']=='NO_PROOF',failed
                        altered=workspace/'altered.java';altered.write_text(implementation.read_text().replace('ensures enabled == true','ensures true'))
                        rejected=await call('implement_code',{**impl_args,'candidate':str(altered),'out_file':'altered/Switch.java'})
                        assert not rejected['request_satisfied'] and rejected['claim']=='NO_PROOF',rejected
                        missing=await call('implement_code',{**impl_args,'out_file':'unavailable/Switch.java'},{'OPENJML_BIN':'/nonexistent/openjml'})
                        assert not missing['request_satisfied'] and missing['claim']=='NO_PROOF',missing
                        python=os.environ.get('FORMALSPECGEN_PROMOTION_ACCEPTANCE_PYTHON',os.sys.executable)
                        cli_env={**os.environ,**env}
                        cli=[]
                        commands=[['draft','A boolean switch','--canonical-domain',reviewed['module_name'],'--no-clarify',
                            '--generation-only','--domain-candidate',str(candidate),'--validation-evidence',validated['validation_artifact']['path'],
                            '--out','output','--out-file','cli/Switch.java','--json','-'],
                            ['implement',drafted['code_file'],'--canonical-java','--v2-reviewed-domain',str(reviewed_copy),
                             '--v2-validation-evidence',validated['validation_artifact']['path'],'--domain-candidate',str(candidate),
                             '--candidate',str(implementation),'--out','output','--json','-']]
                        for command in commands:
                            process=subprocess.run([python,'-I','-m','pipeline.cli',*command],cwd=workspace,env=cli_env,capture_output=True,text=True,timeout=120)
                            assert process.returncode==0,(process.stdout,process.stderr)
                            envelope=json.loads(process.stdout)
                            assert envelope['operation_satisfied'] and envelope['exit_code']==0,envelope
                            value=envelope['result'];assert value['request_satisfied'],value
                            cli.append({'arguments':command,'envelope':envelope,'result':value})
                        assert Path(cli[0]['result']['code_file']).read_bytes()==Path(drafted['code_file']).read_bytes()
                        assert Path(cli[1]['result']['code_file']).read_bytes()==Path(implemented['code_file']).read_bytes()
                        java_acceptance={'cli':cli,'artifacts':{}}
                        for result in [drafted,implemented,generated,failed,*[c['result'] for c in cli]]:
                            for key,metadata in result['publication'].items():
                                java_acceptance['artifacts'][metadata['path']]={'metadata':metadata,
                                    'bytes_base64':base64.b64encode(Path(metadata['path']).read_bytes()).decode()}
            export=os.environ.get('FORMALSPECGEN_DOMAIN_SESSION_ACCEPTANCE_DIR')
            if export:
                path=Path(export);path.mkdir(parents=True,exist_ok=True)
                retained={'schema':'formalspecgen-domain-session-acceptance-v1',
                    'revision':os.environ.get('GITHUB_SHA'),
                    'run':{'provider':'github-actions','id':os.environ.get('GITHUB_RUN_ID'),
                           'attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),'repository':os.environ.get('GITHUB_REPOSITORY')},
                    'tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip(),
                    'calls':calls,'schemas':schemas,'candidate_bytes':raw.decode(),
                    'session_events':{p.name:json.loads(p.read_text()) for p in sorted((root/rid).glob('*.json'))}}
                from pipeline.parity_inventory import _canonical_sha256
                retained['plan_sha256']=_canonical_sha256(json.loads(Path('mcpdocs/mcp_parity_plan.json').read_text()))
                if os.environ.get('FORMALSPECGEN_REQUIRE_DOMAIN_VALIDATION_ACCEPTANCE')=='1':
                    retained['validation_bytes']=Path(validated['validation_artifact']['path']).read_text()
                if os.environ.get('FORMALSPECGEN_REQUIRE_APPROVAL_ACCEPTANCE')=='1':
                    approval=Path(os.environ['FORMALSPECGEN_APPROVAL_ROOT'])/requested['approval']['request_id']
                    retained['approval_files']={p.name:base64.b64encode(p.read_bytes()).decode() for p in approval.iterdir() if p.is_file()}
                    retained['reviewed_bytes']=Path(promoted['publication']['path']).read_text()
                    retained['public_keys']=subprocess.check_output(['gpg','--homedir',os.environ['FORMALSPECGEN_APPROVAL_GNUPGHOME'],'--batch','--armor','--export'],text=True)
                    retained['reviewer']=os.environ['FORMALSPECGEN_REVIEWER_IDENTITY']
                if os.environ.get('FORMALSPECGEN_REQUIRE_REVIEWED_JAVA_ACCEPTANCE')=='1':
                    retained['reviewed_java']=java_acceptance
                (path/'session.json').write_text(json.dumps({'schema':'formalspecgen-domain-session-acceptance-v1',
                    **retained},indent=2)+'\n')
        anyio.run(run)
