"""Real-tool acceptance tests for the production Linux execution profile.

These tests are deliberately separate from mocked unit coverage.  The provisioned CI
job sets ``FORMALSPECGEN_REQUIRE_SANDBOX_ACCEPTANCE=1`` and delegates a cgroup subtree;
when required, a missing isolation primitive is a test failure rather than a skip.
"""
from __future__ import annotations

import os
import hashlib
import shutil
import tempfile
from pathlib import Path

import pytest

from pipeline.execution import (
    ExecutionPolicy, ExecutionRequest, SourceSnapshot, StrictSandboxExecutor,
)
from pipeline.polyglot_runtime import collect_polyglot_runtime_evidence
from pipeline.isolated_tlc import TlcModelRequest, run_isolated_tlc
from pipeline.workflow_contracts import WorkflowContext


REQUIRED = os.environ.get("FORMALSPECGEN_REQUIRE_SANDBOX_ACCEPTANCE") == "1"
pytestmark = pytest.mark.skipif(
    not REQUIRED, reason="real sandbox acceptance requires a delegated cgroup v2 runner")


@pytest.fixture
def executor():
    bwrap = shutil.which("bwrap")
    prlimit = shutil.which("prlimit")
    cgroup_root = os.environ.get("FORMALSPECGEN_CGROUP_ROOT")
    assert bwrap, "Bubblewrap is required by the acceptance profile"
    assert prlimit, "prlimit is required by the acceptance profile"
    assert cgroup_root, "FORMALSPECGEN_CGROUP_ROOT must name a delegated cgroup v2 subtree"
    root = Path(cgroup_root)
    assert (root / "cgroup.controllers").is_file()
    assert os.access(root, os.W_OK), f"cgroup delegation is not writable: {root}"
    membership = Path("/proc/self/cgroup").read_text(encoding="utf-8")
    assert root.name in membership, \
        "acceptance process must start inside the delegated parent cgroup"
    return StrictSandboxExecutor(
        sandbox_binary=bwrap, prlimit_binary=prlimit, cgroup_root=root)


@pytest.mark.parametrize("valid", [True, False])
def test_tlc_captured_model_and_counterexample_in_real_sandbox(executor, tmp_path, valid):
    from pipeline import config

    jar = Path(config.TLC_JAR)
    assert jar.is_file(), "pinned TLC jar is required by the acceptance profile"
    tla = """---- MODULE Counter ----
EXTENDS Naturals
VARIABLE x
Init == x = 0
Next == x' = IF x = 0 THEN 1 ELSE 0
TypeOK == x \\in 0..BOUND
Spec == Init /\\ [][Next]_x
====
""".replace("BOUND", "1" if valid else "0")
    cfg = "SPECIFICATION Spec\nINVARIANT TypeOK\n"
    result = run_isolated_tlc(
        TlcModelRequest("Counter", tla, cfg),
        WorkflowContext.for_cli(("external_execution",), workspace_root=tmp_path),
        executor=executor)
    assert result["status"] == ("TLC_MODEL_CHECK_PASSED" if valid else "TLC_FAILED"), result
    assert result["request_satisfied"] is valid
    assert result["model_check_passed"] is valid
    assert result["claim"] == "NO_PROOF"
    assert result["version"]
    observations = result["execution_observations"]
    assert len(observations) == 2
    for observation in observations:
        assert observation["policy_compliance"] == "ENFORCED"
        assert observation["snapshot_manifest_sha256"] == result["snapshot_manifest_sha256"]
        assert list(observation["snapshot_files"]) == result["snapshot_manifest"]
        assert str(jar) not in observation["command"]
        assert "/input/tool/tla2tools.jar" in observation["command"]
        assert not observation["timed_out"] and not observation["output_truncated"]
    expected = {"Counter.tla": tla.encode(), "Counter.cfg": cfg.encode(),
                "tool/tla2tools.jar": jar.read_bytes()}
    assert {item["path"]: item["sha256"] for item in result["snapshot_manifest"]} == {
        name: hashlib.sha256(data).hexdigest() for name, data in expected.items()}
    if not valid:
        assert observations[1]["exit_code"] != 0
        assert "Invariant TypeOK is violated" in observations[1]["output"]


@pytest.mark.parametrize(("language", "compiler", "code", "test_code"), [
    ("c", "gcc", "int add(int a, int b) { return a + b; }",
     "int main(void) { return add(1, 2) != 3; }"),
    ("cpp", "g++", "class A { public: int add(int a, int b) { return a + b; } };",
     "int main() { A value; return value.add(1, 2) != 3; }"),
])
def test_instrumented_native_fixture_runs_in_real_sandbox(
        executor, monkeypatch, language, compiler, code, test_code):
    resolved = shutil.which(compiler)
    assert resolved, f"{compiler} is required by the acceptance profile"
    original = shutil.which
    monkeypatch.setattr(
        "pipeline.polyglot_runtime.shutil.which",
        lambda name: resolved if name in {compiler, "cc"} else original(name))
    result = collect_polyglot_runtime_evidence(
        code, language, test_code=test_code, executor=executor)
    assert result["status"] == "NO_RUNTIME_FAILURE_FOUND", result["log"]
    assert result["claim"] == "RUNTIME_SAMPLE"
    assert result["execution_policy_compliance"] == "ENFORCED"
    assert result["execution"]["status"] == "COMPLETED"


def test_javac_runs_without_virtual_address_space_limit(executor):
    javac = shutil.which("javac")
    assert javac, "javac is required by the acceptance profile"
    with tempfile.TemporaryDirectory(prefix="formalspecgen-acceptance-") as directory:
        root = Path(directory)
        javac_path = Path(javac).resolve()
        snapshot = SourceSnapshot.create(
            root / "snapshot", {"Probe.java": "public class Probe {}\n"})
        observation = executor.execute(ExecutionRequest(
            tool="javac-acceptance",
            command=(str(javac_path), "-d", "/work", "/input/Probe.java"),
            snapshot=snapshot, workspace=root / "workspace",
            policy=ExecutionPolicy(max_memory_bytes=1024 * 1024 * 1024),
            readonly_paths=(javac_path.parent,)))
    assert observation.status == "COMPLETED", observation.output or observation.message
    assert observation.policy_compliance == "ENFORCED"
    assert not any(argument.startswith("--as=") for argument in observation.command)


def test_temporary_storage_budget_is_enforced(executor):
    with tempfile.TemporaryDirectory(prefix="formalspecgen-acceptance-") as directory:
        root = Path(directory)
        snapshot = SourceSnapshot.create(root / "snapshot", {"empty": b""})
        observation = executor.execute(ExecutionRequest(
            tool="temporary-storage-acceptance",
            command=("/bin/sh", "-c",
                     "dd if=/dev/zero of=/tmp/blob bs=1048576 count=4"),
            snapshot=snapshot, workspace=root / "workspace",
            policy=ExecutionPolicy(max_temporary_bytes=1024 * 1024)))
    assert observation.status == "WRITABLE_STORAGE_LIMIT_EXCEEDED", observation.output
    assert observation.policy_compliance == "ENFORCED"
