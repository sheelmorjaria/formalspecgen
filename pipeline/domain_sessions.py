# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Resumable V2 elicitation and immutable unreviewed candidate publication."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .domain_generator import elicit_domain_questions,compile_domain_spec_v2
from .domain_v2 import DomainSpecV2
from .domain_v2_promotion import candidate_sha256
from .llm import _chat_fn,provider_response_limit
from .mcp_artifacts import publish_new_artifacts
from .workflow_sessions import WorkflowSessionStore,SessionError


def _text(value, limit, name):
    if not isinstance(value,str) or not value.strip() or len(value.encode('utf-8'))>limit or '\0' in value:
        raise SessionError('SESSION_INPUT_INVALID',f'{name} must be nonempty bounded text')
    return value.strip()


def _bounded_chat(provider, *, schema=None):
    calls=0;total=0
    def wrap(chat):
        def bounded(*args,**kwargs):
            nonlocal calls,total
            calls+=1
            if calls>32:raise SessionError('SESSION_PROVIDER_LIMIT','provider call limit exceeded')
            with provider_response_limit(256*1024):
                content,model,usage=chat(*args,**kwargs)
            if not isinstance(content,str):raise SessionError('SESSION_PROVIDER_LIMIT','provider response must be text')
            size=len(content.encode('utf-8'));total+=size
            if size>128*1024 or total>1024*1024:raise SessionError('SESSION_PROVIDER_LIMIT','provider output limit exceeded')
            return content,model,usage
        if hasattr(chat,'structured_for'):
            bounded.structured_for=lambda *a,**k:wrap(chat.structured_for(*a,**k))
        return bounded
    return wrap(_chat_fn(provider,json_schema=schema))


class DomainSessionService:
    def __init__(self, store: WorkflowSessionStore,workspace: Path,output_root: Path):
        self.store,self.workspace,self.output_root=store,workspace.resolve(),output_root
        if output_root!=self.workspace and self.workspace not in output_root.parents:
            raise SessionError('SESSION_CONFIGURATION_INVALID','output root must remain in the workspace')

    def _load(self, session_id):
        record=self.store.load(session_id)
        if record['kind']!='domain-v2' or record['workspace']!=str(self.workspace) or record['output_root']!=str(self.output_root):
            raise SessionError('SESSION_CONTEXT_CHANGED','session workspace or output configuration changed')
        return record

    def public(self, record):
        result={key:value for key,value in record.items() if key not in {'principal','candidate_text','previous_sha256'}}
        result.update(claim='NO_PROOF',request_satisfied=True,review_status='unreviewed',clarification_provenance='caller-supplied; not authenticated human approval')
        result['remaining_questions']=[q for q in record['questions'] if q['required'] and not record['answers'].get(q['id'])]
        return result

    def get(self, session_id):
        with self.store.locked(session_id):return self.public(self._load(session_id))

    def start(self, idea,provider='ollama',model=None):
        idea=_text(idea,16*1024,'idea')
        if provider not in {'glm','openai','ollama'}:raise SessionError('SESSION_INPUT_INVALID','unsupported provider')
        if model is not None:model=_text(model,256,'model')
        questions,_,_=elicit_domain_questions(idea,_bounded_chat(provider),model)
        return self.public(self.store.create('domain-v2',{'workspace':str(self.workspace),
            'output_root':str(self.output_root),'idea':idea,'provider':provider,'model':model,
            'questions':questions,'answers':{},'status':'CLARIFYING' if any(q['required'] for q in questions) else 'READY'}))

    def continue_session(self, session_id,answers,expected_revision):
        with self.store.locked(session_id):
            record=self._load(session_id);self.store.require_revision(record,expected_revision)
            if record['status'] not in {'CLARIFYING','READY'}:raise SessionError('SESSION_FINALIZED','candidate preparation has already begun')
            if not isinstance(answers,dict) or not answers or set(answers)-{q['id'] for q in record['questions']}:
                raise SessionError('SESSION_INPUT_INVALID','answers must name known questions')
            normalized={key:_text(value,4096,'answer') for key,value in answers.items()}
            merged={**record['answers'],**normalized}
            ready=all(not q['required'] or merged.get(q['id']) for q in record['questions'])
            return self.public(self.store.append(record,{'answers':merged,'status':'READY' if ready else 'CLARIFYING'}))

    def finalize(self, session_id,expected_revision,admission):
        from .workflow_contracts import WorkflowContext
        context=WorkflowContext.for_mcp(admission,('workspace_read','workspace_write_new',
            'provider_access','service_state_read','service_state_write'),workspace_root=self.workspace,
            output_root=self.output_root)
        with self.store.locked(session_id):
            record=self._load(session_id)
            if record['status'] in {'PREPARED','FINALIZED'}:
                if type(expected_revision) is not int or expected_revision not in {record['revision'],record['finalize_base_revision']}:
                    raise SessionError('SESSION_REVISION_CONFLICT','finalization revision changed')
            else:
                self.store.require_revision(record,expected_revision)
                if record['status']!='READY':raise SessionError('SESSION_CLARIFICATION_REQUIRED','required questions remain unanswered')
                spec,_,_,_=compile_domain_spec_v2(record['idea'],record['questions'],
                    [{'id':k,'answer':v} for k,v in record['answers'].items()],
                    _bounded_chat(record['provider'],schema=DomainSpecV2.model_json_schema()),record['model'])
                if spec.review_status!='unreviewed':raise SessionError('SESSION_INPUT_INVALID','compiler must produce an unreviewed candidate')
                content=spec.model_dump_json(indent=2)+'\n'
                relative=f'domain-sessions/{session_id}/domains/candidates/{spec.module_name}.v2.yaml'
                record=self.store.append(record,{'status':'PREPARED','candidate_text':content,
                    'candidate_sha256':candidate_sha256(spec),'candidate_relative':relative,
                    'module_name':spec.module_name,'finalize_base_revision':expected_revision})
            destination=self.output_root/record['candidate_relative'];content=record['candidate_text'].encode()
            if destination.exists() or destination.is_symlink():
                from .bounded_inputs import CaptureBudget,capture,input_directory,input_path
                _,relative=input_path(str(destination),context)
                with input_directory(relative,context) as fd:
                    observed=capture(relative.name,fd,context,CaptureBudget(1024*1024,1))
                if observed!=content:raise SessionError('SESSION_CANDIDATE_CHANGED','published candidate changed; start a new session')
                artifact={'path':str(destination),'sha256':hashlib.sha256(content).hexdigest(),'size':len(content)}
            else:
                if record['status']=='FINALIZED':raise SessionError('SESSION_CANDIDATE_CHANGED','finalized candidate is missing')
                artifact=publish_new_artifacts(self.output_root,{record['candidate_relative']:content},admission,max_total_bytes=1024*1024)[record['candidate_relative']]
            if record['status']!='FINALIZED':record=self.store.append(record,{'status':'FINALIZED','candidate_artifact':artifact})
            result=self.public(record)
            result['validate_domain']={'name':record['module_name'],'project_root':str(destination.parent.parent.parent)}
            result['promotion_candidate']=str(destination)
            return result


def configured_service(output_root):
    import os
    from .operator_configuration import operator_controlled_path
    root=operator_controlled_path('FORMALSPECGEN_SESSION_ROOT')
    principal=os.environ.get('FORMALSPECGEN_SESSION_PRINCIPAL','')
    return DomainSessionService(WorkflowSessionStore(root,principal),Path.cwd(),output_root)
