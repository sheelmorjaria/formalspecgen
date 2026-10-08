# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Isolation and tool failures cannot be interpreted as proof evidence."""
from dataclasses import replace
from pathlib import Path

import pytest
from pipeline import isolated_verification as isolated
from pipeline.operator_configuration import operator_controlled_path
from test_verify_workflow_parity import RecordingExecutor, _observation, _tool


class FailedExecutor(RecordingExecutor):
    def __init__(self, failed_tool, status, output='', compliance='ENFORCED'):
        super().__init__()
        self.failed_tool, self.status = failed_tool, status
        self.output, self.compliance = output, compliance

    def execute(self, request):
        self.requests.append(request)
        result = _observation(request, self.output if request.tool == self.failed_tool else '')
        if request.tool == self.failed_tool:
            result = replace(result, status=self.status, exit_code=125,
                             policy_compliance=self.compliance, message='execution rejected')
        return result


@pytest.fixture
def tools(tmp_path, monkeypatch):
    for name in ('RUSTC_BIN', 'PRUSTI_BIN', 'KANI_BIN', 'CC_BIN', 'FRAMAC_BIN'):
        monkeypatch.setattr(isolated.config, name, _tool(tmp_path, name.lower()))
    monkeypatch.setattr(isolated.shutil, 'which', lambda name: _tool(tmp_path, name))


@pytest.mark.parametrize('suffix,backend,tool', [
    ('.rs', 'prusti', 'prusti'), ('.rs', 'kani', 'kani'),
    ('.c', 'prusti', 'c-compiler'), ('.c', 'prusti', 'frama-c'),
    ('.cpp', 'prusti', 'esbmc'),
])
@pytest.mark.parametrize('status,output,compliance', [
    ('TIMEOUT', '', 'ENFORCED'),
    ('SANDBOX_UNAVAILABLE', '', 'NOT_ENFORCED'),
    ('COMPLETED', 'error while loading shared libraries', 'ENFORCED'),
])
def test_backend_infrastructure_failures_never_mint_claim(tmp_path, tools, suffix, backend, tool, status, output, compliance):
    source = tmp_path / ('proof' + suffix)
    source.write_text('#[ensures(result == 1)]\n#[kani::proof]\nfn f() -> i32 {1}' if suffix == '.rs'
                      else ('/*@ assigns \\nothing; ensures \\result == 1; */\nint f(void){return 1;}' if suffix == '.c' else 'int main(){return 0;}'))
    executor = FailedExecutor(tool, status, output, compliance)
    result = isolated.execute_isolated_verification(source, backend=backend, executor=executor)
    assert result.payload['claim'] == 'NO_PROOF'
    assert not result.payload.get('request_satisfied', False)
    assert result.payload['status'] != 'VERIFIED'
    assert result.observation is not None and result.exit_code != 0
    assert result.as_dict()['execution_stages'][-1]['tool'] == tool
    if tool == 'c-compiler': assert len(executor.requests) == 1


@pytest.mark.parametrize('suffix,mode,backend,status', [
    ('.c', 'parse', 'prusti', 'UNSUPPORTED_MODE'),
    ('.cpp', 'check', 'prusti', 'UNSUPPORTED_MODE'),
    ('.rs', 'unsupported', 'prusti', 'UNSUPPORTED_MODE'),
    ('.txt', 'esc', 'prusti', 'UNSUPPORTED_LANGUAGE'),
])
def test_unsupported_requests_do_not_execute(tmp_path, suffix, mode, backend, status):
    source = tmp_path / ('source' + suffix); source.write_text('')
    executor = RecordingExecutor()
    result = isolated.execute_isolated_verification(source, mode, backend, executor=executor)
    assert result.payload['status'] == status
    assert result.payload['claim'] == 'NO_PROOF' and executor.requests == []


@pytest.mark.parametrize('mode', ['parse', 'check'])
def test_rust_static_check_failure_retains_diagnostics(tmp_path, tools, mode):
    source = tmp_path / 'source.rs'; source.write_text('fn f() {}')
    executor = RecordingExecutor({'rustc': 'type mismatch'}, {'rustc': 1})
    result = isolated.execute_isolated_verification(source, mode=mode, executor=executor)
    assert result.payload['status'] == 'RUST_CHECK_FAILED'
    assert result.output == 'type mismatch' and result.payload['claim'] == 'NO_PROOF'


@pytest.mark.parametrize('configuration', ['RUSTC_BIN', 'PRUSTI_BIN', 'KANI_BIN', 'CC_BIN', 'FRAMAC_BIN'])
def test_missing_tool_halts_at_correct_stage(tmp_path, tools, monkeypatch, configuration):
    monkeypatch.setattr(isolated.config, configuration, '/absent/tool')
    monkeypatch.setattr(isolated.shutil, 'which', lambda _name: None)
    source = tmp_path / ('proof.c' if configuration in {'CC_BIN', 'FRAMAC_BIN'} else 'proof.rs')
    source.write_text('/*@ assigns \\nothing; ensures \\result == 1; */\nint f(void){return 1;}' if source.suffix == '.c'
                      else '#[ensures(result == 1)]\n#[kani::proof]\nfn f()->i32{1}')
    executor = RecordingExecutor()
    result = isolated.execute_isolated_verification(source,
        mode='check' if configuration == 'RUSTC_BIN' else 'esc',
        backend='kani' if configuration == 'KANI_BIN' else 'prusti', executor=executor)
    assert result.payload['status'] == 'TOOL_MISSING'
    assert result.payload['claim'] == 'NO_PROOF'
    assert len(executor.requests) == int(configuration == 'FRAMAC_BIN')


def test_cpp_class_harness_calls_methods_and_excludes_invariant_helper(tmp_path, tools):
    source = tmp_path / 'proof.cpp'
    source.write_text('class Counter { public: void increment() {} bool ready() {return true;} void check_invariants() {} };')

    class Executor(RecordingExecutor):
        def execute(self, request):
            harness = (request.snapshot.root / 'harness.cpp').read_text()
            assert 'object.increment();' in harness and 'object.ready();' in harness
            assert 'object.check_invariants' not in harness
            assert request.command[1] == '/input/harness.cpp'
            return _observation(request, 'VERIFICATION SUCCESSFUL')
    result = isolated.execute_isolated_verification(source, executor=Executor())
    assert result.payload['claim'] == 'BOUNDED_CPP_PROOF'
    assert result.payload['unbounded_loop_proved'] is False


def test_prover_selection_preserves_builtins_and_refuses_missing_external_prover(monkeypatch):
    monkeypatch.setattr(isolated.config, 'FRAMAC_PROVERS', 'qed, native, none,script,tip,')
    assert isolated._framac_provers() == ((), {}, None)
    monkeypatch.setattr(isolated.config, 'FRAMAC_PROVERS', 'qed,absent')
    monkeypatch.setattr(isolated.shutil, 'which', lambda _name: None)
    paths, env, error = isolated._framac_provers()
    assert paths == () and env == {} and error['status'] == 'PROVER_MISSING'


@pytest.mark.parametrize('mode', [0o600, 0o640, 0o620, 0o602])
def test_operator_policy_permissions_are_not_inherited_from_umask(tmp_path, monkeypatch, mode):
    workspace = tmp_path / 'workspace'; workspace.mkdir()
    monkeypatch.chdir(workspace)
    policy = tmp_path / 'policy'; policy.write_text('{}'); policy.chmod(mode)
    monkeypatch.setenv('TEST_POLICY', str(policy))
    if mode & 0o022:
        with pytest.raises(ValueError, match='writable'):
            operator_controlled_path('TEST_POLICY', require_file=True)
    else:
        assert operator_controlled_path('TEST_POLICY', require_file=True) == policy
    policy.unlink()
    with pytest.raises(ValueError, match='regular file'):
        operator_controlled_path('TEST_POLICY', require_file=True)


def test_jdk_symlink_mounts_are_narrow_and_deduplicated(tmp_path, monkeypatch):
    jdk = tmp_path / 'jdk'; (jdk / 'conf').mkdir(parents=True); (jdk / 'lib').mkdir()
    targets = {'/etc/java-test', '/etc/ssl/certs/java'}
    original = Path.exists
    monkeypatch.setattr(Path, 'exists', lambda path: True if str(path) in targets else original(path))
    (jdk / 'conf/security').symlink_to('/etc/java-test/security')
    (jdk / 'conf/duplicate').symlink_to('/etc/java-test/other')
    (jdk / 'lib/cacerts').symlink_to('/etc/ssl/certs/java/cacerts')
    (jdk / 'conf/other').symlink_to('/etc/unrelated/config')
    (jdk / 'conf/private').symlink_to('/home/operator/secrets')
    (jdk / 'conf/regular').write_text('configuration')
    assert set(isolated._java_configuration_paths(str(jdk))) == {Path(value) for value in targets}
    assert isolated._java_configuration_paths(str(tmp_path / 'missing')) == ()


def test_kani_external_toolchain_is_exposed_without_its_parent_home(tmp_path):
    distribution = tmp_path / 'kani'; (distribution / 'bin').mkdir(parents=True)
    toolchain = tmp_path / 'rust-toolchain'; toolchain.mkdir()
    (distribution / 'toolchain').symlink_to(toolchain)
    paths = isolated._kani_tool_paths(distribution / 'bin/kani-driver')
    assert paths == (distribution, toolchain)
    assert tmp_path not in paths


def test_prusti_failure_diagnostics_do_not_mint_proof(tmp_path, tools):
    source = tmp_path / 'proof.rs'; source.write_text('#[ensures(result == 2)]\nfn f()->i32{1}')
    executor = RecordingExecutor({'prusti': 'verification failed'}, {'prusti': 1})
    result = isolated.execute_isolated_verification(source, executor=executor)
    assert result.payload['status'] == 'VERIFY_FAILED' and result.payload['claim'] == 'NO_PROOF'
    assert result.output == 'verification failed'
