# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Publication and input failures preserve workflow authority boundaries."""
import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.console import Console
from pipeline import cli, doctor, workflow_services as services
from pipeline.workflow_contracts import WorkflowContext, VerificationWorkflowRequest, InspectionWorkflowRequest
from test_codebase_analysis_workflow import _request, _context, JAVA


def context(root, **budget):
    return WorkflowContext.for_cli(('workspace_read', 'external_execution'), workspace_root=root, resource_budget=budget)


@pytest.mark.parametrize('published,keys', [({}, {}), ({'artifact': {}}, {('extraction', 'architecture.json'): 'artifact'}),
    ({'artifact': {'path': ''}}, {('extraction', 'architecture.json'): 'artifact'}),
    ({'artifact': {'path': None}}, {('extraction', 'architecture.json'): 'artifact'})])
def test_incomplete_publication_cannot_claim_artifact_path(published, keys):
    service = services.CodebaseAnalysisServiceResult({}, {}, {}, ('extraction', 'architecture.json'))
    with pytest.raises(ValueError, match='publication'):
        services.bind_codebase_analysis_publication(service, published, keys)


@pytest.mark.parametrize('failure', ['scan', 'open-directory', 'open-file'])
def test_analysis_input_io_errors_fail_before_extraction(tmp_path, monkeypatch, failure):
    root = tmp_path / 'src'; root.mkdir()
    (root / 'nested').mkdir(); (root / 'Counter.java').write_text(JAVA)
    request = _request(tmp_path)
    extract = Mock()
    monkeypatch.setattr('pipeline.codebase_analysis.analyze_codebase', extract)
    if failure == 'scan':
        monkeypatch.setattr(services.os, 'scandir', Mock(side_effect=OSError('scan denied')))
    else:
        original = services.os.open

        def opened(path, flags, *args, **kwargs):
            if path == ('nested' if failure == 'open-directory' else 'Counter.java'):
                raise OSError('input changed')
            return original(path, flags, *args, **kwargs)
        monkeypatch.setattr(services.os, 'open', opened)
    with pytest.raises(ValueError, match='input_unavailable'):
        services.run_codebase_analysis(request, _context(request, tmp_path))
    extract.assert_not_called()
    assert not (tmp_path / 'extracted').exists()


@pytest.mark.parametrize('kind', ['symlink', 'oversized'])
def test_generated_analysis_artifacts_cannot_escape_capture_budget(tmp_path, kind):
    output = tmp_path / 'output'; output.mkdir()
    (output / 'nested').mkdir()
    if kind == 'symlink': (output / 'link').symlink_to(tmp_path / 'outside')
    else: (output / 'result.json').write_text('too long')
    with pytest.raises(ValueError, match='symlink' if kind == 'symlink' else 'RESULT_LIMIT_EXCEEDED'):
        services._capture_analysis_artifacts(output, context(tmp_path, max_result_bytes=2), 'analysis')
    assert services._capture_analysis_artifacts(tmp_path / 'missing', context(tmp_path), 'analysis') == {}


def test_analysis_normalization_preserves_non_json_and_malformed_documents(tmp_path):
    for name, content in [('file.txt', b'text'), ('file.json', b'{'), ('file.json', b'\xff')]:
        assert services._normalize_analysis_artifact(name, content, snapshot=tmp_path / 'snapshot', input_root=tmp_path) == content


@pytest.mark.parametrize('kind', ['baseline-link', 'candidate-link', 'unsupported-multifile', 'empty-multifile', 'missing-candidate', 'file-limit'])
def test_refactor_capture_rejects_unsafe_or_incomplete_source_sets(tmp_path, kind):
    baseline = tmp_path / 'Counter.java'; baseline.write_text('class Counter {}')
    candidate = tmp_path / 'candidate.java'; candidate.write_text('class Counter {}')
    budget = {}
    if kind == 'baseline-link':
        link = tmp_path / 'baseline-link.java'; link.symlink_to(baseline); baseline = link
    elif kind == 'candidate-link':
        link = tmp_path / 'candidate-link.java'; link.symlink_to(candidate); candidate = link
    elif kind in {'unsupported-multifile', 'empty-multifile'}:
        candidate.unlink(); candidate.mkdir()
        if kind == 'unsupported-multifile':
            baseline = tmp_path / 'source.rs'; baseline.write_text('fn f(){}')
    elif kind == 'missing-candidate': candidate.unlink()
    else: budget = {'max_input_files': 1}
    with pytest.raises((ValueError, FileNotFoundError)):
        services._refactor_inputs(baseline, candidate, context(tmp_path, **budget))


@pytest.mark.parametrize('value', [-1, True, '1'])
def test_refactor_resource_limits_reject_non_integer_or_negative_values(tmp_path, value):
    with pytest.raises(ValueError, match='non-negative integer'):
        services._refactor_resource_limit(context(tmp_path, max_input_bytes=value), 'max_input_bytes')


def test_refactor_scan_enforces_regular_file_and_remaining_file_budget(tmp_path):
    (tmp_path / 'directory.java').mkdir()
    file = tmp_path / 'A.java'; file.write_text('class A {}')
    assert services._bounded_refactor_sources(tmp_path, suffixes={'.java'}, excluded=set(), remaining=None, label='source') == (file,)
    for remaining in (-1, 0):
        with pytest.raises(ValueError, match='file limit'):
            services._bounded_refactor_sources(tmp_path, suffixes={'.java'}, excluded=set(), remaining=remaining, label='source')
    link = tmp_path / 'B.java'; link.symlink_to(file)
    with pytest.raises(ValueError, match='symlinks'):
        services._bounded_refactor_sources(tmp_path, suffixes={'.java'}, excluded=set(), remaining=None, label='source')


def test_java_inspection_io_and_encoding_errors_are_no_proof(tmp_path, monkeypatch):
    source = tmp_path / 'Counter.java'; source.write_bytes(b'\xff')
    request = InspectionWorkflowRequest(str(source))
    result = services.run_java_inspection(request, context(tmp_path))
    assert result['code'] == 'source_unavailable' and result['claim'] == 'NO_PROOF'
    original = Path.open

    def opened(path, *args, **kwargs):
        if path == source: raise OSError('read denied')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', opened)
    assert services.run_java_inspection(request, context(tmp_path))['code'] == 'source_unavailable'


def test_java_verification_object_observation_is_preserved(tmp_path):
    source = tmp_path / 'Counter.java'; source.write_text('class Counter {}')
    request = VerificationWorkflowRequest(str(source))
    observation = SimpleNamespace(exit_code=1, output='verification failed')
    result = services.run_java_verification(request, context(tmp_path), lambda *_args: observation)
    assert result.backend_result is observation
    assert result.payload['exit_code'] == 1 and result.payload['claim'] == 'NO_PROOF'
    with pytest.raises(ValueError, match='Java/JML'):
        services.run_java_verification(VerificationWorkflowRequest(str(tmp_path / 'source.rs')), context(tmp_path), Mock())


@pytest.mark.parametrize('strict,required,expected', [(False, [], 0), (True, [], 1), (False, ['Prusti'], 1)])
def test_doctor_cli_distinguishes_readiness_from_proof_and_required_judges(monkeypatch, strict, required, expected):
    report = {'status': 'ATTENTION_REQUIRED', 'claim': 'NO_PROOF',
              'capabilities': [{'name': 'Prusti', 'status': 'ERROR', 'claims_enabled': ['DEDUCTIVE_RUST_EVIDENCE'],
                               'judge_pending': 'prusti', 'message': 'runtime [failure]'},
                              {'name': 'Z3', 'status': 'READY', 'claims_enabled': ['SMT_MODEL_PROVED'], 'judge_pending': 'z3'}],
              'domains': [{'name': 'vfs', 'maturity': 'production', 'evidence_ceiling': 'NO_PROOF'}],
              'lanes': [{'lane': 'M55_vfs', 'current_step': 4, 'maturity': 'production', 'status': 'JUDGE_PENDING', 'claims_locked': ['DEDUCTIVE_RUST_EVIDENCE']},
                        {'lane': 'other', 'current_step': 1, 'maturity': 'scaffold', 'status': 'READY', 'claims_locked': []}]}
    monkeypatch.setattr(doctor, 'inspect_environment', lambda: report)
    stream = io.StringIO(); ui = cli.TerminalUI(Console(file=stream))
    args = SimpleNamespace(judges=True, require=required, json=None, strict=strict)
    assert cli.command_doctor(args, ui) == expected
    output = stream.getvalue()
    assert 'judge_pending:prusti' in output and 'NO_PROOF' in output
    assert 'runtime [failure]' in output
    assert report['judge_manifest']['Prusti']['status'] == 'ERROR'


@pytest.mark.parametrize('case', ['missing-source', 'oversized', 'missing-files', 'unsafe-name', 'wrong-extension'])
def test_invalid_transformer_output_never_reaches_verification_or_publication(tmp_path, monkeypatch, case):
    from pipeline.workflow_contracts import ApplyRefactorWorkflowRequest
    source = tmp_path / ('Counter.java' if case in {'missing-files', 'unsafe-name', 'wrong-extension'} else 'source.c')
    source.write_text('class Counter {}' if source.suffix == '.java' else 'int f(void){return 1;}')
    inspection = tmp_path / 'inspection.json'; inspection.write_text('{}')
    multifile = source.suffix == '.java'
    request = ApplyRefactorWorkflowRequest(str(source), str(inspection) if multifile else None,
        pattern='decorator' if multifile else 'extract-method', method='f', out='candidate')
    transformed = {'status': 'TRANSFORMED'}
    if case == 'oversized': transformed['source'] = 'x' * 100
    elif case == 'unsafe-name': transformed['files'] = {'../escape.java': 'class Escape {}'}
    elif case == 'wrong-extension': transformed['files'] = {'payload.py': 'code'}
    monkeypatch.setattr(services, '_apply_deterministic_transform', lambda *_args: transformed)
    verify = Mock(); monkeypatch.setattr(services, 'run_refactor_verification', verify)
    with pytest.raises(ValueError): services.run_apply_refactor(request, context(tmp_path, max_result_bytes=10))
    verify.assert_not_called()
    assert not (tmp_path / 'candidate').exists()


@pytest.mark.parametrize('command,args', [
    ('capabilities', {'name': 'invalid/name'}),
    ('contract', {'source': 'missing.java', 'operation': 'unknown', 'candidate': None}),
    ('project', {'manifest': 'missing.json', 'operation': 'unknown', 'target': None, 'changed': None}),
    ('evidence', {'manifest': 'missing.json', 'operation': 'show', 'expected_sha256': 'invalid',
                  'comparison_manifest': None, 'comparison_expected_sha256': None, 'source': None}),
])
def test_cli_invalid_requests_emit_structured_no_proof_failure(command, args, capsys):
    stream = io.StringIO(); ui = cli.TerminalUI(Console(file=stream))
    assert getattr(cli, 'command_' + command)(SimpleNamespace(json='-', **args), ui) == 1
    result = json.loads(capsys.readouterr().out)
    assert result['claim'] == 'NO_PROOF' and result['request_satisfied'] is False
    assert result['code'] == 'INVALID_REQUEST'
