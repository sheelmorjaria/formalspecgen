# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Installed-wheel integrity: no source-checkout resource fallbacks allowed."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from pipeline import config


def test_resource_path_supports_standard_virtualenv_data_layout(tmp_path, monkeypatch):
    package_root = tmp_path / "site-packages"
    prefix = tmp_path / "venv"
    resource = prefix / "security" / "cwe_manifest.json"
    resource.parent.mkdir(parents=True)
    resource.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(config, "ROOT", package_root)
    monkeypatch.setattr(config.sys, "prefix", str(prefix))
    assert config.resource_path("security", "cwe_manifest.json") == resource


@pytest.fixture(scope="module")
def installed_wheel(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("installed-wheel")
    project = Path(__file__).resolve().parents[1]
    wheels = tmp_path / "wheels"
    target = tmp_path / "installed"
    empty = tmp_path / "empty"
    wheels.mkdir(); target.mkdir(); empty.mkdir()
    built = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(project), "--no-deps",
         "--no-build-isolation", "--no-index", "--wheel-dir", str(wheels)],
        capture_output=True, text=True, timeout=120)
    assert built.returncode == 0, (built.stdout + built.stderr)[-4000:]
    wheel = next(wheels.glob("formalspecgen-*.whl"))
    installed = subprocess.run(
        [sys.executable, "-m", "pip", "install", str(wheel), "--no-deps", "--no-index",
         "--target", str(target)], capture_output=True, text=True, timeout=120)
    assert installed.returncode == 0, (installed.stdout + installed.stderr)[-4000:]

    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith(("COVERAGE_", "COV_CORE_", "FORMALSPECGEN_")):
            environment.pop(name)
    environment["PYTHONPATH"] = str(target)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return target, empty, environment


def test_wheel_runs_from_empty_directory_with_runtime_data(installed_wheel):
    target, empty, environment = installed_wheel

    script = r'''
import json
from pathlib import Path
import mcp_server
from pipeline import config
from pipeline.agentic import AgentGoal
from pipeline.cwe_registry import entries
from pipeline.doctor import inspect_environment
from pipeline.scaffold_domain import load_spec

root = Path(config.ROOT)
elevator = load_spec(root / "domains/elevator_controller.yaml")
domain = json.loads((root / "domains/v2/inventory.json").read_text(encoding="utf-8"))
report = inspect_environment(runner=lambda command, **kwargs: __import__("subprocess").CompletedProcess(command, 0, "tool 1.0", ""),
                             which=lambda name: "/bin/true")
assert len(entries()) > 0
assert elevator.domain_name == "ElevatorController"
assert domain["domain_name"]
assert report["domains"]
assert (root / "security/cwe_manifest.json").is_file()
assert (root / "ci/rust-deps/Cargo.lock").is_file()
assert callable(mcp_server.create_server)
assert AgentGoal.__name__ == "AgentGoal"
import tree_sitter, tree_sitter_java, tree_sitter_rust, tree_sitter_c, tree_sitter_cpp
print(json.dumps({"root": str(root), "domain": domain["domain_name"],
                  "elevator": elevator.domain_name, "cwes": len(entries())}))
'''
    checked = subprocess.run([sys.executable, "-c", script], cwd=empty,
                             env=environment, capture_output=True, text=True, timeout=30)
    assert checked.returncode == 0, (checked.stdout + checked.stderr)[-4000:]
    result = json.loads(checked.stdout.strip().splitlines()[-1])
    assert Path(result["root"]).resolve() == target.resolve()
    assert result["cwes"] > 0
    doctor = subprocess.run(
        [sys.executable, "-m", "pipeline.cli", "doctor", "--json", "-"],
        cwd=empty, env=environment, capture_output=True, text=True, timeout=30)
    assert doctor.returncode == 0, (doctor.stdout + doctor.stderr)[-4000:]
    envelope = json.loads(doctor.stdout)
    assert envelope["schema"] == "formalspecgen-cli-result-v1"
    assert envelope["operation_satisfied"] is True
    doctor_report = envelope["result"]
    assert doctor_report["claim"] == "NO_PROOF"
    assert doctor_report["domains"]


# Executed by a separate interpreter with only the installed wheel on PYTHONPATH.
# Dependencies come from the provisioned test environment; this is not a fresh
# dependency-resolution or real-backend qualification.
_EVIDENCE_SCRIPT = r'''
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

target = Path(os.environ["PYTHONPATH"]).resolve()
guard = """
import sys
from pathlib import Path
import mcp_server
import pipeline.cli
import pipeline.cli_output
import pipeline.evidence_consumer
import pipeline.lifecycle
import formalspec_core
root = Path(__import__('os').environ['PYTHONPATH']).resolve()
for name, module in tuple(sys.modules.items()):
    if name == 'mcp_server' or name.split('.')[0] in ('pipeline', 'formalspec_core'):
        location = getattr(module, '__file__', None)
        if location:
            assert Path(location).resolve().is_relative_to(root), (name, location)
"""
exec(guard)
from pipeline.lifecycle import RunLedger, PipelineState, EvidenceClaim

def fixture(name):
    ledger = RunLedger(Path.cwd() / name)
    ledger.record(PipelineState.PROOF, "FAIL", claim=EvidenceClaim.NO_PROOF,
                  evidence={"diagnostic": "synthetic installed-wheel fixture"})
    return ledger.commit({"final_status": "FAIL", "claim": "NO_PROOF"})

manifest = fixture("valid")
tampered = fixture("tampered")
(tampered.parent / "001-proof.json").write_text("changed", encoding="utf-8")
digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
cases = [
    ({"manifest": str(manifest), "expected_sha256": digest}, True),
    ({"manifest": str(manifest), "operation": "explain"}, True),
    ({"manifest": str(manifest), "operation": "diff",
      "comparison_manifest": str(manifest)}, True),
    ({"manifest": str(manifest), "expected_sha256": "0" * 64}, False),
    ({"manifest": str(tampered)}, False),
    ({"manifest": str(Path.cwd() / "missing.json")}, False),
]

def snapshot():
    return {str(p.relative_to(Path.cwd())): p.read_bytes()
            for p in Path.cwd().rglob("*") if p.is_file()}

before = snapshot()
local = []
for arguments, satisfied in cases:
    command = [str(target / "bin/formalspecgen"), "evidence",
               arguments.get("operation", "validate"), arguments["manifest"], "--json", "-"]
    for key in ("expected_sha256", "comparison_manifest"):
        if key in arguments:
            command += ["--" + key.replace("_", "-"), arguments[key]]
    process = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert (process.returncode == 0) == satisfied, (command, process.stderr)
    envelope = json.loads(process.stdout)
    assert envelope["schema"] == "formalspecgen-cli-result-v1"
    assert envelope["operation_satisfied"] is satisfied
    result = envelope["result"]
    assert result["request_satisfied"] is satisfied
    assert result["claim"] == "NO_PROOF"
    local.append(result)
assert local[0]["integrity"]["status"] == "VALID"
assert local[1]["explanation"]["recorded_claim"] == "NO_PROOF"
assert local[3]["code"] == "MANIFEST_DIGEST_MISMATCH"
assert local[4]["status"] == "EVIDENCE_INVALID"

async def transport():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    parameters = StdioServerParameters(command=sys.executable,
        args=["-c", guard + "\nmcp_server.create_server().run()"],
        cwd=str(Path.cwd()), env=dict(os.environ))
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            discovered = await session.list_tools()
            tool = next(tool for tool in discovered.tools if tool.name == "inspect_evidence")
            assert set(tool.inputSchema["properties"]) == {
                "manifest", "operation", "expected_sha256", "comparison_manifest",
                "comparison_expected_sha256", "source"}
            for (arguments, satisfied), expected in zip(cases, local):
                response = await session.call_tool("inspect_evidence", arguments)
                assert not response.isError
                actual = response.structuredContent
                assert actual["request_satisfied"] is satisfied
                assert {k: v for k, v in actual.items() if k != "mcp_admission"} == expected
            denied = await session.call_tool("inspect_evidence", {
                "manifest": str(Path.cwd().parent / "outside.json")})
            assert not denied.isError
            assert denied.structuredContent["code"] == "PATH_OUTSIDE_WORKSPACE"
            assert not denied.structuredContent["request_satisfied"]

remote = sys.argv[1] == "mcp"
if remote:
    asyncio.run(asyncio.wait_for(transport(), timeout=45))
assert before == snapshot(), "Read-only inspection changed its workspace"
print(json.dumps({"installed_root": str(target), "cli_calls": len(cases),
                  "mcp_calls": len(cases) + 1 if remote else 0, "read_only": True}))
'''


@pytest.mark.parametrize("interface", ["cli", "mcp"])
def test_installed_evidence_interfaces(installed_wheel, tmp_path, interface):
    if interface == "mcp" and os.environ.get("FORMALSPECGEN_REQUIRE_INSTALLED_MCP_ACCEPTANCE") != "1":
        pytest.skip("set FORMALSPECGEN_REQUIRE_INSTALLED_MCP_ACCEPTANCE=1 for real installed MCP")
    target, _, environment = installed_wheel
    checked = subprocess.run(
        [sys.executable, "-c", _EVIDENCE_SCRIPT, interface], cwd=tmp_path,
        env=environment, capture_output=True, text=True, timeout=120)
    assert checked.returncode == 0, (checked.stdout + checked.stderr)[-6000:]
    result = json.loads(checked.stdout)
    assert result == {"installed_root": str(target.resolve()), "cli_calls": 6,
                      "mcp_calls": 7 if interface == "mcp" else 0, "read_only": True}
