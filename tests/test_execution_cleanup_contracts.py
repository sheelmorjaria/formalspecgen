# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Resource-control failures remain visible and prevent compliant evidence."""
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from pipeline import execution
from test_execution_boundary import _request


def test_cgroup_missing_event_files_and_malformed_counters_are_tolerated(tmp_path):
    handle = execution.CgroupV2Handle(tmp_path / 'absent')
    assert handle.events() == {}
    (tmp_path / 'memory.events').write_text('oom 2\ninvalid nonnumeric\nmax 3\n')
    (tmp_path / 'pids.events').write_text('max 1\n')
    assert execution.CgroupV2Handle(tmp_path).events() == {'oom': 2, 'max': 3, 'pids_max': 1}


def test_cgroup_cleanup_reports_retained_resources(tmp_path, monkeypatch):
    group = tmp_path / 'group'; group.mkdir()
    handle = execution.CgroupV2Handle(group)
    assert handle.close() is False
    assert (group / 'cgroup.kill').read_text() == '1'
    monkeypatch.setattr(handle, 'kill', lambda: None)
    (group / 'cgroup.kill').unlink()
    assert handle.close() is True
    handle.kill()  # removed delegation must not mask the original failure


def test_partial_cgroup_setup_failure_is_not_accepted(tmp_path, monkeypatch):
    executor = execution.StrictSandboxExecutor(cgroup_root=tmp_path)
    with pytest.raises(OSError, match='delegation'): executor._create_cgroup(execution.ExecutionPolicy())
    (tmp_path / 'cgroup.controllers').write_text('memory pids')
    original = Path.write_text

    def write(path, value, **kwargs):
        if path.name == 'pids.max': raise OSError('pids denied')
        return original(path, value, **kwargs)
    monkeypatch.setattr(Path, 'write_text', write)
    with pytest.raises(OSError, match='pids denied'): executor._create_cgroup(execution.ExecutionPolicy())


def test_cgroup_failure_before_limits_are_written_removes_empty_delegation(tmp_path, monkeypatch):
    (tmp_path / 'cgroup.controllers').write_text('memory pids')
    executor = execution.StrictSandboxExecutor(cgroup_root=tmp_path)
    monkeypatch.setattr(Path, 'write_text', Mock(side_effect=OSError('memory denied')))
    with pytest.raises(OSError, match='memory denied'): executor._create_cgroup(execution.ExecutionPolicy())
    assert not list(tmp_path.glob('formalspecgen-*'))


@pytest.mark.parametrize('events,cleanup,status,compliance', [
    ({'oom': 1}, True, 'MEMORY_LIMIT_EXCEEDED', 'ENFORCED'),
    ({'max': 1}, True, 'MEMORY_LIMIT_EXCEEDED', 'ENFORCED'),
    ({'pids_max': 1}, True, 'PROCESS_LIMIT_EXCEEDED', 'ENFORCED'),
    ({}, False, 'RESOURCE_CLEANUP_FAILED', 'NOT_ENFORCED'),
])
def test_successful_child_exit_does_not_hide_resource_failure(tmp_path, events, cleanup, status, compliance):
    group = Mock(); group.events.return_value = events; group.close.return_value = cleanup
    executor = execution.StrictSandboxExecutor()
    result = executor._run_bounded([sys.executable, '-c', 'print("done")'], _request(tmp_path), group)
    assert result.status == status and result.policy_compliance == compliance
    assert result.resource_events == events
    group.close.assert_called_once()


def test_failed_spawn_closes_allocated_cgroup(tmp_path):
    group = Mock()
    executor = execution.StrictSandboxExecutor(popen_factory=Mock(side_effect=OSError('spawn denied')))
    result = executor._run_bounded(['absent'], _request(tmp_path), group)
    assert result.status == 'TOOL_ERROR'
    group.close.assert_called_once()


def test_unit_termination_kills_cgroup_before_process_group(monkeypatch):
    group = Mock(); process = Mock(pid=123)
    kill = Mock(side_effect=OSError('gone'))
    monkeypatch.setattr(execution.os, 'killpg', kill)
    execution.StrictSandboxExecutor._terminate_unit(process, group)
    group.kill.assert_called_once(); process.kill.assert_called_once()


def test_snapshot_missing_file_fails_integrity_validation(tmp_path):
    snapshot = execution.SourceSnapshot.create(tmp_path / 'snapshot', {'source': b'bytes'})
    (snapshot.root / 'source').unlink()
    assert snapshot.validate() is False
