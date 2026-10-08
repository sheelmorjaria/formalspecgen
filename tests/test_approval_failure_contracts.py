# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Malformed or unauthenticated approvals never reach protected signing."""
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pipeline import approval_service as approval
from pipeline import protected_signer as signer
from test_approval_service import FakeCommands, _service, _request, _decide, REVIEWER, SIGNER


@pytest.mark.parametrize('mutation', [
    {'operation_id': 'different'}, {'policy_version': 'old'}, {'action': 'other'},
    {'artifact': None}, {'evidence_manifest': None}, {'destination': None},
    {'signing_identity': ''}, {'reviewer_identity': ''},
    {'admission_profile_sha256': 'invalid'}, {'expires_at': 'invalid'},
    {'expires_at': '2026-01-01T00:00:00'},
    {'artifact': {'path': None, 'sha256': 'a' * 64, 'size': 1}},
    {'artifact': {'path': '/tmp/artifact', 'sha256': 'bad', 'size': 1}},
    {'artifact': {'path': '/tmp/artifact', 'sha256': 'a' * 64, 'size': -1}},
])
def test_tampered_request_is_refused_before_execution(tmp_path, mutation):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, _, _ = _request(tmp_path, service)
    _decide(tmp_path, request, commands)
    request_id = request['approval']['request_id']
    request_path = service.root / request_id / 'request.json'
    value = json.loads(request_path.read_text())
    value.update(mutation)
    request_path.write_text(json.dumps(value))
    with pytest.raises(approval.ApprovalError) as error:
        service.execute(request_id)
    assert error.value.code == 'APPROVAL_STATE_INVALID'
    assert commands.signer_calls == 0
    assert not (service.root / request_id / 'receipt.json').exists()


@pytest.mark.parametrize('decision', ['approve', 'deny'])
def test_failed_human_signature_leaves_no_decision_or_receipt(tmp_path, decision):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, _, _ = _request(tmp_path, service)
    request_id = request['approval']['request_id']
    run = Mock(return_value=SimpleNamespace(returncode=1))
    with pytest.raises(approval.ApprovalError) as error:
        approval.record_human_decision(service.root, request_id, decision=decision,
                                       signing_key=REVIEWER, runner=run)
    assert error.value.code == 'APPROVAL_SIGNATURE_FAILED'
    assert not (service.root / request_id / 'decision.json').exists()
    assert not (service.root / request_id / 'decision.json.sig').exists()
    with pytest.raises(approval.ApprovalError) as error:
        service.execute(request_id)
    assert error.value.code == 'APPROVAL_REQUIRED'
    assert commands.signer_calls == 0


def test_invalid_decision_identifiers_and_request_locations(tmp_path):
    for request_id, decision, code in [('a' * 32, 'invalid', 'APPROVAL_DECISION_INVALID'),
                                       ('../escape', 'approve', 'APPROVAL_NOT_FOUND')]:
        with pytest.raises(approval.ApprovalError) as error:
            approval.record_human_decision(tmp_path, request_id, decision=decision, signing_key=REVIEWER)
        assert error.value.code == code
    service = _service(tmp_path, FakeCommands())
    for request_id in ('../escape', 'a' * 32):
        with pytest.raises(approval.ApprovalError) as error:
            service.execute(request_id)
        assert error.value.code == 'APPROVAL_NOT_FOUND'
        assert error.value.as_dict()['claim'] == 'NO_PROOF'


@pytest.mark.parametrize('case,code', [
    ('nonzero', 'APPROVAL_SIGNATURE_INVALID'), ('no-validsig', 'APPROVAL_SIGNATURE_INVALID'),
    ('short-id', 'APPROVAL_SIGNATURE_INVALID'), ('untrusted', 'APPROVAL_REVIEWER_UNAUTHORIZED'),
    ('mismatch', 'APPROVAL_REVIEWER_MISMATCH'),
])
def test_signature_requires_trusted_full_fingerprint(case, code, tmp_path):
    output = '[GNUPG:] VALIDSIG ' + REVIEWER
    if case == 'no-validsig': output = '[GNUPG:] GOODSIG short reviewer'
    if case == 'short-id': output = '[GNUPG:] VALIDSIG ABCD'
    run = Mock(return_value=SimpleNamespace(returncode=int(case == 'nonzero'), stdout=output))
    with pytest.raises(approval.ApprovalError) as error:
        approval._verify_detached_signature(tmp_path / 'artifact', tmp_path / 'signature',
            gpg_home=tmp_path, authorized_keys={SIGNER} if case == 'untrusted' else {REVIEWER},
            expected_identity=SIGNER if case == 'mismatch' else REVIEWER, runner=run)
    assert error.value.code == code


@pytest.mark.parametrize('kind', ['missing', 'symlink', 'directory', 'oversize'])
def test_signer_capture_refuses_unsafe_or_oversized_inputs(tmp_path, kind):
    source = tmp_path / 'source'
    if kind == 'symlink':
        actual = tmp_path / 'actual'; actual.write_text('bytes')
        source.symlink_to(actual)
    elif kind == 'directory': source.mkdir()
    elif kind == 'oversize': source.write_text('12345')
    destination = tmp_path / 'snapshot'
    with pytest.raises(approval.ApprovalError) as error:
        signer._capture_file(source, destination, max_bytes=4, label='artifact')
    assert error.value.code == ('SIGNER_INPUT_LIMIT_EXCEEDED' if kind == 'oversize' else 'ARTIFACT_UNAVAILABLE')
    assert not destination.exists()


@pytest.mark.parametrize('binding', [None, {}, {'size': '1'}, {'size': -1}, {'size': signer._SIGNED_INPUT_LIMIT + 1}])
def test_signer_binding_must_be_bounded(binding):
    with pytest.raises(approval.ApprovalError) as error:
        signer._binding_limit(binding, 'artifact')
    assert error.value.code in {'APPROVAL_BINDING_MISMATCH', 'SIGNER_INPUT_LIMIT_EXCEEDED'}


@pytest.mark.parametrize('contents', ['{', '{}', '{"keys":[{"key_id":"short"}]}'])
def test_signer_trust_registry_requires_full_fingerprints(tmp_path, monkeypatch, contents):
    registry = tmp_path / 'registry.json'; registry.write_text(contents)
    monkeypatch.setenv('FORMALSPECGEN_APPROVAL_TRUST_REGISTRY', str(registry))
    with pytest.raises(approval.ApprovalError) as error:
        signer._authorized_reviewers()
    assert error.value.code == 'SIGNER_POLICY_UNAVAILABLE'


def test_operator_signer_paths_are_required(tmp_path, monkeypatch):
    monkeypatch.delenv('TEST_SIGNER_PATH', raising=False)
    with pytest.raises(approval.ApprovalError): signer._required_path('TEST_SIGNER_PATH')
    monkeypatch.setenv('TEST_SIGNER_PATH', str(tmp_path / 'absent'))
    with pytest.raises(approval.ApprovalError): signer._required_path('TEST_SIGNER_PATH')


def test_human_decision_cli_preserves_explicit_signing_arguments(tmp_path, monkeypatch, capsys):
    run = Mock(return_value={'status': 'DECISION_RECORDED'})
    monkeypatch.setattr(approval, 'record_human_decision', run)
    assert approval.main(['--root', str(tmp_path), '--request-id', 'a' * 32,
                          '--decision', 'deny', '--key', REVIEWER,
                          '--gpg-home', str(tmp_path / 'keys')]) == 0
    assert run.call_args.kwargs == {'decision': 'deny', 'signing_key': REVIEWER, 'gpg_home': tmp_path / 'keys'}
    assert json.loads(capsys.readouterr().out)['status'] == 'DECISION_RECORDED'


@pytest.mark.parametrize('fails', [False, True])
def test_protected_signer_cli_reports_failure_without_proof_upgrade(tmp_path, monkeypatch, capsys, fails):
    run = Mock(return_value={'status': 'SIGNED'})
    if fails: run.side_effect = approval.ApprovalError('APPROVAL_REPLAY', 'already exists')
    monkeypatch.setattr(signer, 'sign_approved_artifact', run)
    arguments = []
    for name in ('request', 'decision', 'approval-signature', 'artifact', 'output'):
        arguments += ['--' + name, str(tmp_path / name)]
    assert signer.main(arguments) == (2 if fails else 0)
    output = json.loads(capsys.readouterr().out)
    assert output['status'] == ('APPROVAL_REPLAY' if fails else 'SIGNED')
    if fails: assert output['claim'] == 'NO_PROOF'


@pytest.mark.parametrize('kind', ['missing-signer', 'signer-rejects', 'no-signature'])
def test_protected_signer_failure_never_publishes_receipt(tmp_path, kind):
    commands = FakeCommands()
    service = _service(tmp_path, commands)
    request, _, _ = _request(tmp_path, service)
    _decide(tmp_path, request, commands)
    if kind == 'missing-signer':
        service.signer = None
    else:
        def run(command, **kwargs):
            if str(command[0]).endswith('protected-signer'):
                return SimpleNamespace(returncode=int(kind == 'signer-rejects'))
            return commands(command, **kwargs)
        service.runner = run
    with pytest.raises(approval.ApprovalError) as error:
        service.execute(request['approval']['request_id'])
    assert error.value.code == ('PROTECTED_SIGNER_UNAVAILABLE' if kind == 'missing-signer' else 'PROTECTED_SIGNING_FAILED')
    assert not (service.root / request['approval']['request_id'] / 'receipt.json').exists()


@pytest.mark.parametrize('mutation', [{'signature': None}, {'status': 'unknown'},
    {'signature_identity': 'changed'}, {'signing_fingerprint': 'changed'}])
def test_receipt_replay_revalidates_signature_identity(tmp_path, mutation):
    commands = FakeCommands(); service = _service(tmp_path, commands)
    request, _, _ = _request(tmp_path, service); _decide(tmp_path, request, commands)
    request_id = request['approval']['request_id']; service.execute(request_id)
    receipt = service.root / request_id / 'receipt.json'
    value = json.loads(receipt.read_text())
    if 'signature_identity' in mutation: value['signature']['signer_identity'] = 'changed'
    elif 'signing_fingerprint' in mutation: value['signature']['signing_fingerprint'] = 'changed'
    else: value.update(mutation)
    receipt.write_text(json.dumps(value))
    with pytest.raises(approval.ApprovalError) as error: service.execute(request_id)
    assert error.value.code == 'APPROVAL_STATE_INVALID'
    assert commands.signer_calls == 1


@pytest.mark.parametrize('changes', [{'authorized_reviewers': set()}, {'signing_identity': ''},
    {'reviewer_identity': ''}, {'reviewer_identity': 'short'}, {'reviewer_identity': 'C' * 40}])
def test_service_requires_operator_trust_configuration(tmp_path, changes):
    args = dict(verifier_home=tmp_path, authorized_reviewers={REVIEWER}, signer=None,
                signing_identity=SIGNER, reviewer_identity=REVIEWER)
    args.update(changes)
    with pytest.raises(approval.ApprovalError) as error: approval.ApprovalService(tmp_path / 'state', **args)
    assert error.value.code == 'APPROVAL_POLICY_UNAVAILABLE'
    assert not (tmp_path / 'state').exists()


@pytest.mark.parametrize('ttl,digest', [(0, 'a' * 64), (86401, 'a' * 64), (900, 'invalid')])
def test_invalid_approval_lifetime_or_admission_digest_does_not_create_request(tmp_path, ttl, digest):
    service = _service(tmp_path, FakeCommands())
    artifact = tmp_path / 'artifact'; artifact.write_text('candidate')
    with pytest.raises(approval.ApprovalError) as error:
        service.create_request(artifact=artifact, evidence_manifest=artifact,
            admission_profile_sha256=digest, claim='NO_PROOF', verification_status='FAIL', ttl_seconds=ttl)
    assert error.value.code == 'APPROVAL_POLICY_INVALID'
    assert not list(service.root.iterdir())


@pytest.mark.parametrize('contents', ['{', '[]', '{}'])
def test_approval_json_state_requires_valid_schema(tmp_path, contents):
    source = tmp_path / 'request'; source.write_text(contents)
    with pytest.raises(approval.ApprovalError) as error:
        approval._load_json(source, approval.APPROVAL_REQUEST_SCHEMA)
    assert error.value.code == 'APPROVAL_STATE_INVALID'
    with pytest.raises(approval.ApprovalError) as error: approval._sha256_file(tmp_path / 'missing')
    assert error.value.code == 'ARTIFACT_UNAVAILABLE'


@pytest.mark.parametrize('case,code', [
    ('invalid-expiry', 'APPROVAL_BINDING_MISMATCH'), ('unsupported-action', 'APPROVAL_BINDING_MISMATCH'),
    ('noncanonical-evidence', 'APPROVAL_BINDING_MISMATCH'), ('denied-decision', 'APPROVAL_BINDING_MISMATCH'),
    ('artifact-drift', 'APPROVED_ARTIFACT_CHANGED'), ('evidence-drift', 'APPROVED_ARTIFACT_CHANGED'),
    ('wrong-signing-key', 'SIGNER_POLICY_UNAVAILABLE'), ('existing-output', 'APPROVAL_REPLAY'),
    ('gpg-fails', 'PROTECTED_SIGNING_FAILED'), ('output-race', 'APPROVAL_REPLAY'),
])
def test_operator_signer_independently_rejects_tampering_and_replay(tmp_path, monkeypatch, case, code):
    commands = FakeCommands(); service = _service(tmp_path, commands)
    request, artifact, evidence = _request(tmp_path, service)
    _decide(tmp_path, request, commands)
    root = service.root / request['approval']['request_id']
    signing_home = tmp_path / 'signing-home'; signing_home.mkdir()
    registry = tmp_path / 'reviewers.json'; registry.write_text(json.dumps({'keys': [{'key_id': REVIEWER}]}))
    monkeypatch.setenv('FORMALSPECGEN_APPROVAL_GNUPGHOME', str(tmp_path / 'public-keys'))
    monkeypatch.setenv('FORMALSPECGEN_APPROVAL_TRUST_REGISTRY', str(registry))
    monkeypatch.setenv('FORMALSPECGEN_SIGNER_GNUPGHOME', str(signing_home))
    monkeypatch.setenv('FORMALSPECGEN_SIGNING_KEY', 'C' * 40 if case == 'wrong-signing-key' else SIGNER)
    output = root / 'artifact.sig'
    if case in {'invalid-expiry', 'unsupported-action', 'noncanonical-evidence'}:
        path = root / 'request.json'; value = json.loads(path.read_text())
        if case == 'invalid-expiry': value['expires_at'] = 'invalid'
        elif case == 'unsupported-action': value['action'] = 'merge'
        else: value['evidence_manifest']['path'] = str(evidence.parent / 'unused') + '/../' + evidence.name
        path.write_text(json.dumps(value))
    elif case == 'denied-decision':
        path = root / 'decision.json'; value = json.loads(path.read_text()); value['decision'] = 'deny'; path.write_text(json.dumps(value))
    elif case in {'artifact-drift', 'evidence-drift'}:
        path = artifact if case == 'artifact-drift' else evidence
        original = path.read_bytes(); path.write_bytes(b'X' + original[1:])
    elif case == 'existing-output': output.write_bytes(b'existing')

    def run(command, **kwargs):
        if '--detach-sign' in command and case == 'gpg-fails':
            return SimpleNamespace(returncode=1)
        result = commands(command, **kwargs)
        if '--detach-sign' in command and case == 'output-race': output.write_bytes(b'other operation')
        return result

    with pytest.raises(approval.ApprovalError) as error:
        signer.sign_approved_artifact(request_path=root / 'request.json', decision_path=root / 'decision.json',
            approval_signature=root / 'decision.json.sig', artifact=artifact, output=output, runner=run)
    assert error.value.code == code
    if case in {'existing-output', 'output-race'}:
        assert output.read_bytes() == (b'existing' if case == 'existing-output' else b'other operation')
    else: assert not output.exists()
    assert not list(root.glob('.signature-*'))
