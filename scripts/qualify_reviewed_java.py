#!/usr/bin/env python3
# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Replay scoped trusted-CI reviewed-domain -> Java native verification evidence."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess

from scripts.qualify_domain_sessions import evaluate as evaluate_session, require
from pipeline.domain_v2_promotion import ReviewedDomainSpecV2
from pipeline.v2_jml_serializer import render_class
from pipeline.implementation import trusted_surface_matches
from pipeline.verification_policy import decide_verification
from pipeline.domain_v2_evidence import canonical_sha256


def evaluate(record, revision, tree, plan):
    session = evaluate_session(record, revision, tree, plan)
    java = record['reviewed_java']
    calls = record['calls']
    drafts = [call for call in calls if call['tool'] == 'draft_canonical_contract']
    implementations = [call for call in calls if call['tool'] == 'implement_code']
    require(len(drafts) == 3 and len(implementations) == 5, 'Java transport cases incomplete')
    require(drafts[1]['result']['request_satisfied'] is False and
        drafts[2]['result']['code'] == 'OUTPUT_ALREADY_EXISTS', 'draft rejection cases missing')
    require(all(call['result']['request_satisfied'] is False and call['result']['claim'] == 'NO_PROOF'
        for call in implementations[2:]), 'implementation rejection cases missing')
    reviewed = ReviewedDomainSpecV2.model_validate_json(record['reviewed_bytes'])
    contract = render_class(reviewed).encode()
    artifacts = java['artifacts']
    raw = {}
    for path, item in artifacts.items():
        content = base64.b64decode(item['bytes_base64'], validate=True)
        metadata = item['metadata']
        require(metadata == {'path': path, 'sha256': hashlib.sha256(content).hexdigest(), 'size': len(content)},
            'publication digest/size mismatch')
        raw[path] = content
    results = [drafts[0]['result'], *[call['result'] for call in implementations[:3]],
               *[call['result'] for call in java['cli']]]
    require(len(java['cli']) == 2, 'CLI comparisons missing')
    for call in [drafts[0], *implementations[:3]]:
        result = call['result']
        receipt = json.loads(raw[result['evidence_file']])
        request = receipt['workflow_request']
        mapping = ({'validation_evidence':'validation_evidence','domain_candidate':'domain_candidate',
                    'requirement':'requirement','out_file':'out_file'} if call['tool']=='draft_canonical_contract' else
                   {'spec_path':'scaffold','v2_reviewed_domain':'reviewed_domain',
                    'v2_validation_evidence':'validation_evidence','domain_candidate':'domain_candidate',
                    'candidate':'candidate','out_file':'out_file'})
        for argument, field in mapping.items():
            require(call['arguments'].get(argument) == request[field], 'transport argument delivery mismatch')
        require(receipt['authority']['profile_sha256'] == result['mcp_admission']['profile_sha256'], 'admission binding mismatch')
    for call in java['cli']:
        envelope = call['envelope']
        require(envelope['schema']=='formalspecgen-cli-result-v1' and envelope['exit_code']==0
            and envelope['operation_satisfied'] and envelope['result']==call['result'], 'CLI response mismatch')
    for result in results:
        for item in result['publication'].values():
            require(item['path'] in raw and item == artifacts[item['path']]['metadata'], 'returned publication mismatch')
        receipt = json.loads(raw[result['evidence_file']])
        require(receipt['schema'] == 'formalspecgen-reviewed-java-v1', 'receipt schema mismatch')
        require(all(result[key] == value for key, value in receipt.items()), 'receipt/result mismatch')
        source = raw[result['code_file']]
        require(receipt['accepted_candidate_sha256'] == session['candidate_sha256'], 'domain candidate mismatch')
        require(receipt['contract_sha256'] == hashlib.sha256(contract).hexdigest(), 'canonical contract mismatch')
        require(receipt['source_refinement_proved'] is False and receipt['review_authenticity_established'] is False,
            'claim boundary upgraded')
        for name, digest in receipt['implementation_identity'].items():
            require(hashlib.sha256(subprocess.check_output(['git', 'show', f'HEAD:pipeline/{name}'])).hexdigest() == digest,
                'generator/policy identity mismatch')
        for name, identity in receipt['input_identities'].items():
            captured = raw[result['code_file'] + f'.inputs/{name}']
            require(identity == {'sha256': hashlib.sha256(captured).hexdigest(), 'size': len(captured)}, 'captured input mismatch')
        require(raw[result['code_file']+'.inputs/reviewed_domain'] == record['reviewed_bytes'].encode(),
            'reviewed promotion artifact mismatch')
        require(raw[result['code_file']+'.inputs/domain_candidate'] == record['candidate_bytes'].encode(),
            'original candidate mismatch')
        require(raw[result['code_file']+'.inputs/validation_evidence'] == record['validation_bytes'].encode(),
            'validation artifact mismatch')
        if receipt['operation'] == 'draft':
            require(source == contract and receipt['claim'] == 'NO_PROOF' and receipt['request_satisfied'], 'draft bytes/claim mismatch')
            continue
        require(trusted_surface_matches(contract.decode(), source.decode())[0], 'trusted contract changed')
        digest = hashlib.sha256(source).hexdigest()
        require(receipt['implementation_sha256'] == digest, 'implementation digest mismatch')
        require(receipt['execution_stages'], 'native execution missing')
        observation = receipt['execution_stages'][-1]
        require(observation['policy_compliance'] == 'ENFORCED' and
            any(item['sha256'] == digest and item['path'] == 'Switch.java' for item in observation['snapshot_files']),
            'executed source/policy mismatch')
        decision = decide_verification(tool='openjml', mode='esc', exit_code=observation['exit_code'], output=receipt['output'])
        require(decision['claim'] == receipt['claim'] and decision['request_satisfied'] == receipt['request_satisfied'],
            'native policy verdict mismatch')
        require(receipt['tool_identities'], 'native tool identity missing')
    require(raw[java['cli'][0]['result']['code_file']] == raw[drafts[0]['result']['code_file']], 'CLI/MCP generation mismatch')
    require(raw[java['cli'][1]['result']['code_file']] == raw[implementations[0]['result']['code_file']], 'CLI/MCP implementation mismatch')
    require(implementations[0]['result']['claim'] == implementations[1]['result']['claim'] == 'DEDUCTIVE_PROOF',
        'explicit/provider success missing')
    return {'schema': 'formalspecgen-reviewed-java-qualification-v1', 'revision': revision, 'tree': tree,
        'status': 'QUALIFIED', 'scope': 'Sequential atomic V2 Java generation and native ESC',
        'whole_command_parity_complete': False, 'source_refinement_proved': False,
        'acceptance_sha256': canonical_sha256(record), 'artifacts_checked': len(raw),
        'mcp_cases': 8, 'cli_comparisons': 2}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--promotion-qualification', type=Path)
    args = parser.parse_args()
    require(not subprocess.check_output(['git','status','--porcelain'],text=True).strip(), 'qualification requires a clean revision')
    revision = subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    tree = subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip()
    record = json.loads(args.evidence.read_text())
    report = evaluate(record, revision, tree, json.loads(Path('mcpdocs/mcp_parity_plan.json').read_text()))
    args.output.write_text(json.dumps(report,indent=2)+'\n'); print(json.dumps(report))
    files = [args.evidence, args.output, args.output.parent/'qualification.json']
    if args.promotion_qualification is not None:
        promotion = json.loads(args.promotion_qualification.read_text())
        require(promotion['revision'] == revision and promotion['tree'] == tree and promotion['status'] == 'QUALIFIED', 'promotion report mismatch')
        files.append(args.promotion_qualification)
    index = {'schema':'formalspecgen-qualification-index-v1','revision':revision,'tree':tree,
        'run':record.get('run'),'reports':{str(path.name if path.parent == args.output.parent else 'promotion/'+path.name):
            {'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'size':path.stat().st_size}
            for path in files if path.is_file()},
        'retention_days':90, 'whole_command_parity_complete':False}
    (args.output.parent/'qualification-index.json').write_text(json.dumps(index,indent=2)+'\n')


if __name__ == '__main__':
    main()
