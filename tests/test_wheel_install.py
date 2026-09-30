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
import pipeline.capability_discovery
import pipeline.agentic.run_reader
import pipeline.operator_configuration
import pipeline.worker_queries
import pipeline.bisimulation_workflow
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

Path("Legacy.java").write_text("class Legacy { public int go() { return 1; } }")
Path("Modern.java").write_text("class Idle { public int go() { return 1; } }")
Path("mapping.json").write_text('{"0":"Idle"}')
before = snapshot()
import tempfile
from pipeline.agentic.contracts import AgentGoal
from pipeline.agentic.state_store import AgentRunStore
run_directory = tempfile.TemporaryDirectory(prefix="installed-run-read-")
run_store = AgentRunStore(Path(run_directory.name))
run_store.create(AgentGoal("read-001", "Synthetic run fixture", "a" * 40,
                          "Probe.java", "b" * 64), "installed-reader")
os.environ["FORMALSPECGEN_AGENT_STATE_ROOT"] = run_directory.name
os.environ["FORMALSPECGEN_AGENT_PRINCIPAL"] = "installed-reader"
from pipeline.a2a_coordination import TaskStore
worker_policy = run_store.root / "worker-policy.json"
worker_policy.write_text(json.dumps({"schema": "formalspecgen-a2a-policy-v1", "authorities": [], "workers": []}))
worker_store = TaskStore(run_store.root / "workers")
worker_store.create({"work_item_id": "work-001", "principal_id": "installed-reader", "state": "completed",
                     "request_sha256": "a" * 64, "acceptance": {"status": "pending", "claim": "NO_PROOF"},
                     "worker_result": {"patch_sha256": "b" * 64, "artifacts": [
                         {"artifact_id": "patch", "sha256": "c" * 64, "uri": "https://invalid.example/patch"}]}})
os.environ["FORMALSPECGEN_A2A_POLICY"] = str(worker_policy)
os.environ["FORMALSPECGEN_A2A_STATE_ROOT"] = str(worker_store.root)
os.environ["FORMALSPECGEN_A2A_PRINCIPAL"] = "installed-reader"
def run_snapshot():
    return {str(p.relative_to(run_store.root)): p.read_bytes()
            for p in run_store.root.rglob("*") if p.is_file()}
run_before = run_snapshot()
read_process = subprocess.run([str(target / "bin/formalspecgen"), "run", "show", "read-001",
    "--json", "-"], capture_output=True, text=True, timeout=30)
assert read_process.returncode == 0, read_process.stderr
read_envelope = json.loads(read_process.stdout)
assert read_envelope["operation_satisfied"] and read_envelope["result"]["claim"] == "NO_PROOF"
read_result = read_envelope["result"]["run_result"]
assert read_result["status"] == "PLANNED" and not read_result["request_satisfied"]
worker_process = subprocess.run([str(target / "bin/formalspecgen"), "worker", "artifacts", "work-001",
    "--json", "-"], capture_output=True, text=True, timeout=30)
assert worker_process.returncode == 0, worker_process.stderr
worker_result = json.loads(worker_process.stdout)["result"]["worker_result"]
assert worker_result["acceptance"]["status"] == "pending" and not worker_result["implementation_accepted"]
assert not worker_result["artifact_bytes_validated"] and not worker_result["artifact_retrieval_performed"]
preflight_process = subprocess.run([str(target / "bin/formalspecgen"), "verify-bisimulation",
    "Legacy.java", "Modern.java", "mapping.json", "--json", "-"], capture_output=True, text=True, timeout=30)
assert preflight_process.returncode == 0, preflight_process.stderr
preflight_result = json.loads(preflight_process.stdout)["result"]
assert preflight_result["request_satisfied"] and preflight_result["claim"] == "NO_PROOF"
assert not preflight_result["behavior_equivalence_proved"]
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

capability_process = subprocess.run([str(target / "bin/formalspecgen"), "capabilities", "verify",
    "--json", "-"], capture_output=True, text=True, timeout=30)
assert capability_process.returncode == 0, capability_process.stderr
capability_result = json.loads(capability_process.stdout)["result"]
assert capability_result["request_satisfied"] and capability_result["claim"] == "NO_PROOF"
assert capability_result["capabilities"][0]["name"] == "verify_code"
assert capability_result["readiness"] == "NOT_ASSESSED" and not capability_result["invocation_authorized"]

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
            capability_response = await session.call_tool("describe_capabilities", {"name": "verify"})
            assert not capability_response.isError
            assert {k: v for k, v in capability_response.structuredContent.items()
                    if k != "mcp_admission"} == capability_result
            run_response = await session.call_tool("get_agent_run", {"run_id": "read-001"})
            assert not run_response.isError
            assert {k: v for k, v in run_response.structuredContent.items()
                    if k != "mcp_admission"} == read_result
            worker_response = await session.call_tool("get_work_artifacts", {"work_item_id": "work-001"})
            assert not worker_response.isError
            assert {k: v for k, v in worker_response.structuredContent.items()
                    if k != "mcp_admission"} == worker_result
            preflight_response = await session.call_tool("verify_bisimulation", {
                "baseline": "Legacy.java", "refactored": "Modern.java", "mapping": "mapping.json"})
            assert not preflight_response.isError
            def semantic(value):
                return {k: v for k, v in value.items() if k not in {"workflow_result", "mcp_admission"}}
            assert semantic(preflight_response.structuredContent) == semantic(preflight_result)
            assert preflight_response.structuredContent["workflow_result"]["request"] == preflight_result["workflow_result"]["request"]

remote = sys.argv[1] == "mcp"
if remote:
    asyncio.run(asyncio.wait_for(transport(), timeout=45))
assert before == snapshot(), "Read-only inspection changed its workspace"
assert run_before == run_snapshot(), "Run query changed durable state"
run_directory.cleanup()
print(json.dumps({"installed_root": str(target), "cli_calls": len(cases) + 4,
                  "mcp_calls": len(cases) + 5 if remote else 0, "read_only": True}))
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
    assert result == {"installed_root": str(target.resolve()), "cli_calls": 10,
                      "mcp_calls": 11 if interface == "mcp" else 0, "read_only": True}


@pytest.mark.parametrize("interface", ["cli", "mcp"])
def test_installed_project_interfaces(installed_wheel, tmp_path, interface):
    if interface == "mcp" and os.environ.get("FORMALSPECGEN_REQUIRE_INSTALLED_MCP_ACCEPTANCE") != "1":
        pytest.skip("requires installed MCP acceptance")
    target, _, environment = installed_wheel
    script = r'''
import asyncio, hashlib, json, os, subprocess, sys
from pathlib import Path
root = Path(os.environ["PYTHONPATH"]).resolve()
guard = """
import sys
from pathlib import Path
import mcp_server
import pipeline.project_planning
import pipeline.cli
root = Path(__import__('os').environ['PYTHONPATH']).resolve()
for name, module in tuple(sys.modules.items()):
    if name == 'mcp_server' or name.split('.')[0] in ('pipeline', 'formalspec_core'):
        location = getattr(module, '__file__', None)
        if location:
            assert Path(location).resolve().is_relative_to(root), (name, location)
"""
exec(guard)
Path("src").mkdir()
Path("lib").mkdir()
Path("src/S.java").write_text("class S {}\n")
Path("lib/S.java").write_text("class S {} // dependency\n")
document = {"schema": "formalspecgen-project-v1", "targets": [
    {"name": "app", "sources": ["src/S.java"], "depends_on": ["base"], "workflows": [
        {"capability": "verify_code", "profile": "java-openjml-verification"}]},
    {"name": "base", "sources": ["lib/S.java"], "workflows": [
        {"capability": "inspect_code", "profile": "java-readonly-inspection"}]}]}
Path("project.json").write_text(json.dumps(document))
missing_input = json.loads(json.dumps(document))
missing_input["targets"][0]["sources"] = ["missing.java"]
Path("missing-input.json").write_text(json.dumps(missing_input))
document["targets"][0]["workflows"][0]["profile"] = "unavailable"
Path("blocked.json").write_text(json.dumps(document))
Path("invalid.json").write_text('{"schema":1,"schema":2}')
Path("oversize.json").write_bytes(b" " * (4 * 1024**2 + 1))
Path("linked.json").symlink_to("project.json")
cases = [
    ({"manifest": "project.json"}, "PROJECT_VALIDATED"),
    ({"manifest": "project.json", "operation": "plan"}, "PROJECT_PLANNED"),
    ({"manifest": "project.json", "operation": "plan", "target": "base"}, "PROJECT_PLANNED"),
    ({"manifest": "blocked.json", "operation": "plan"}, "PROJECT_BLOCKED"),
    ({"manifest": "invalid.json"}, "PROJECT_INVALID"),
    ({"manifest": "missing.json"}, "PROJECT_INVALID"),
    ({"manifest": "../outside.json"}, "PROJECT_INVALID"),
    ({"manifest": "oversize.json"}, "PROJECT_INVALID"),
    ({"manifest": "linked.json"}, "PROJECT_INVALID"),
    ({"manifest": "project.json", "operation": "impact", "changed_paths": ["lib/S.java"]}, "PROJECT_IMPACT_ANALYZED"),
    ({"manifest": "project.json", "operation": "impact", "changed_paths": ["project.json"]}, "PROJECT_IMPACT_ANALYZED"),
    ({"manifest": "project.json", "operation": "impact", "changed_paths": ["unknown.java"]}, "PROJECT_BLOCKED"),
]
cases += [({"manifest": "project.json", "operation": "impact", **arguments}, "PROJECT_INVALID")
          for arguments in ({}, {"target": "base", "changed_paths": ["lib/S.java"]},
              {"changed_paths": ["../outside"]}, {"changed_paths": ["lib/S.java", "lib/./S.java"]},
              {"changed_paths": [f"file-{i}.java" for i in range(129)]},
              {"operation": "plan", "changed_paths": ["lib/S.java"]})]
cases.append(({"manifest": "missing-input.json", "operation": "impact",
               "changed_paths": ["missing.java"]}, "PROJECT_INVALID"))
def snapshot():
    return {str(p): ("symlink", os.readlink(p)) if p.is_symlink() else
            ("file", hashlib.sha256(p.read_bytes()).hexdigest()) if p.is_file() else ("directory",)
            for p in Path.cwd().rglob("*")}
before = snapshot()
local = []
bindings = 0
for arguments, status in cases:
    command = [str(root / "bin/formalspecgen"), "project", arguments.get("operation", "validate"),
               arguments["manifest"], "--json", "-"]
    if "target" in arguments:
        command += ["--target", arguments["target"]]
    for path in arguments.get("changed_paths", []):
        command += ["--changed", path]
    process = subprocess.run(command, capture_output=True, text=True, timeout=30)
    satisfied = status in {"PROJECT_VALIDATED", "PROJECT_PLANNED", "PROJECT_IMPACT_ANALYZED"}
    assert process.returncode == (0 if satisfied else 1), (arguments, process.stderr)
    envelope = json.loads(process.stdout)
    assert envelope["schema"] == "formalspecgen-cli-result-v1"
    assert envelope["operation_satisfied"] is satisfied
    result = envelope["result"]
    assert result["status"] == status and result["request_satisfied"] is satisfied
    if result.get("code") == "INVALID_REQUEST":
        assert result["claim"] == "NO_PROOF" and not result["request_satisfied"]
        assert not {"inputs", "impact", "steps"} & result.keys()
        local.append(result)
        continue
    assert result["claim"] == "NO_PROOF" and not result["invocation_authorized"]
    assert result["readiness"] == result["assurance"] == result["contract_approval"] == "NOT_ASSESSED"
    if "registry_sha256" in result:
        preview = result["effect_preview"]
        assert not preview["invocation_authorized"]
        assert preview["invocation_effects"] == preview["provider_disclosure"] == "NOT_ASSESSED"
        assert all(preview[key] == result[key] for key in ("manifest_sha256", "registry_sha256", "policy_version"))
        resolved = [step for step in preview["steps"] if step["resolved"]]
        assert preview["resolution_complete"] == (len(resolved) == len(preview["steps"]))
        assert preview["effect_ceiling_union"] == sorted({effect for step in resolved for effect in step["effect_ceiling"]})
        for step in preview["steps"]:
            if not step["resolved"]:
                assert all(step[key] is None for key in ("effect_ceiling", "provider_options", "output_scope"))
    for item in result["inputs"]:
        content = Path(item["path"]).read_bytes()
        assert item["size"] == len(content) and item["sha256"] == hashlib.sha256(content).hexdigest()
        bindings += 1
    if "inputs_sha256" in result:
        canonical = json.dumps(result["inputs"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        assert result["inputs_sha256"] == hashlib.sha256(canonical).hexdigest()
    local.append(result)
assert local[1]["targets"] == ["base", "app"] and len(local[1]["steps"]) == 2
assert local[2]["targets"] == ["base"] and local[2]["unselected_targets"] == ["app"]
assert any(f["blocking"] for f in local[3]["findings"])
assert local[9]["impact"]["affected_targets"] == local[10]["impact"]["affected_targets"] == ["base", "app"]
assert local[11]["impact"]["unmapped_changes"] == ["unknown.java"]
assert not local[9]["impact"]["evidence_reuse_authorized"]
assert all(result["code"] == "INVALID_REQUEST" for result in local[12:-1])
assert local[9]["impact"]["input_capture_complete"] is True
assert local[-1]["impact"]["affected_targets"] == ["app"]
assert local[-1]["impact"]["input_capture_complete"] is False
assert not local[-1]["request_satisfied"] and "inputs_sha256" not in local[-1]
assert not local[-1]["impact"]["evidence_reuse_authorized"]
for result in local:
    if result.get("code") == "INVALID_REQUEST":
        continue
    assert set(result["target_inputs"]) == set(result["targets"])
    assert set(result["target_fingerprints"]) == {
        name for name, binding in result["target_inputs"].items() if binding["capture_complete"]}
    for name, fingerprint in result["target_fingerprints"].items():
        binding = fingerprint["binding"]
        encoded = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        assert fingerprint["sha256"] == hashlib.sha256(encoded).hexdigest()
        assert fingerprint["evidence_reuse_authorized"] is False
        assert binding["target"] == name and binding["registry_sha256"] == result["registry_sha256"]
        assert binding["sources"] == result["target_inputs"][name]["sources"]
        assert binding["contracts"] == result["target_inputs"][name]["contracts"]
        assert all(dep["sha256"] == result["target_fingerprints"][dep["target"]]["sha256"]
                   for dep in binding["dependencies"])
    for name, target_binding in result["target_inputs"].items():
        assert target_binding["capture_complete"] is not (result is local[-1] and name == "app")
        for field in ("sources", "contracts"):
            expected = [{key: item[key] for key in ("path", "size", "sha256")}
                        for item in result["inputs"] if f"{name}:{field}" in item["roles"]]
            assert target_binding[field] == expected

async def transport():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    parameters = StdioServerParameters(command=sys.executable,
        args=["-c", guard + "\nmcp_server.create_server().run()"], cwd=str(Path.cwd()), env=dict(os.environ))
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tool = next(t for t in (await session.list_tools()).tools if t.name == "inspect_project")
            assert set(tool.inputSchema["properties"]) == {"manifest", "operation", "target", "changed_paths"}
            for (arguments, _), expected in zip(cases, local):
                response = await session.call_tool("inspect_project", arguments)
                assert not response.isError
                actual = response.structuredContent
                if expected.get("code") == "INVALID_REQUEST":
                    assert "mcp_admission" not in actual
                else:
                    assert actual["mcp_admission"]["granted_effects"] == ["workspace_read"]
                assert {k: v for k, v in actual.items() if k != "mcp_admission"} == expected

remote = sys.argv[1] == "mcp"
if remote:
    asyncio.run(asyncio.wait_for(transport(), timeout=45))
assert snapshot() == before, "Project inspection changed its workspace"
print(json.dumps({"cli_calls": len(cases), "mcp_calls": len(cases) if remote else 0,
                  "input_bindings": bindings, "installed_root": str(root), "read_only": True}))
'''
    checked = subprocess.run([sys.executable, "-c", script, interface], cwd=tmp_path,
        env=environment, capture_output=True, text=True, timeout=120)
    assert checked.returncode == 0, (checked.stdout + checked.stderr)[-6000:]
    assert json.loads(checked.stdout) == {
        "cli_calls": 19, "mcp_calls": 19 if interface == "mcp" else 0,
        "input_bindings": 23, "installed_root": str(target.resolve()), "read_only": True}


@pytest.mark.parametrize("interface", ["cli", "mcp"])
def test_installed_contract_interfaces(installed_wheel, tmp_path, interface):
    if interface == "mcp" and os.environ.get("FORMALSPECGEN_REQUIRE_INSTALLED_MCP_ACCEPTANCE") != "1":
        pytest.skip("requires installed MCP acceptance")
    target, _, environment = installed_wheel
    script = r'''
import asyncio, hashlib, json, os, subprocess, sys
from pathlib import Path
root = Path(os.environ["PYTHONPATH"]).resolve()
guard = """
import sys
from pathlib import Path
import mcp_server
import pipeline.cli
import pipeline.contract_inspection
import pipeline.java_contracts
import pipeline.jml_io
import pipeline.bounded_inputs
root = Path(__import__('os').environ['PYTHONPATH']).resolve()
for name, module in tuple(sys.modules.items()):
    if name == 'mcp_server' or name.split('.')[0] in ('pipeline', 'formalspec_core'):
        location = getattr(module, '__file__', None)
        if location:
            assert Path(location).resolve().is_relative_to(root), (name, location)
"""
exec(guard)
source = "public class Account {\n //@ requires true;\n //@ ensures \\result >= 0;\n public int balance() { return 1; }\n}\n"
fixtures = {
    "Account.java": source, "Account.jml": source,
    "Body.java": source.replace("return 1", "return 2"),
    "Clause.java": source.replace(">= 0", ">= 1"),
    "Trust.java": source.replace("return 1;", "\n//@ assume true;\nreturn 1;"),
    "Mixed.java": "public class Account {\n public Account() {}\n protected void reset() {}\n //@ requires true;\n //@ ensures \\result >= 0;\n public int balance() { return 1; }\n}",
    "NoClauses.java": "public class Account { public void reset() {} }",
    "Empty.java": "public class Account {}",
    "Syntax.java": "public class {", "Oversized.java": " " * (1024 * 1024 + 1),
}
for name, content in fixtures.items():
    Path(name).write_text(content)
Path("Linked.java").symlink_to("Account.java")
cases = [
    ("extract-java", {"source": "Account.java"}, "CONTRACT_EXTRACTED"),
    ("extract-jml", {"source": "Account.jml"}, "CONTRACT_EXTRACTED"),
    ("body", {"source": "Account.java", "operation": "diff", "candidate": "Body.java"}, "CONTRACT_COMPARED"),
    ("clause", {"source": "Account.java", "operation": "diff", "candidate": "Clause.java"}, "CONTRACT_COMPARED"),
    ("trust", {"source": "Account.java", "operation": "diff", "candidate": "Trust.java"}, "CONTRACT_COMPARED"),
    ("mixed", {"source": "Mixed.java"}, "CONTRACT_EXTRACTED"),
    ("no-clauses", {"source": "NoClauses.java"}, "CONTRACT_EXTRACTED"),
    ("empty", {"source": "Empty.java"}, "CONTRACT_EXTRACTED"),
    ("missing", {"source": "Missing.java"}, "CONTRACT_INVALID"),
    ("missing-candidate", {"source": "Account.java", "operation": "diff", "candidate": "Missing.java"}, "CONTRACT_INVALID"),
    ("syntax", {"source": "Syntax.java"}, "CONTRACT_UNSUPPORTED"),
    ("limit", {"source": "Oversized.java"}, "CONTRACT_INVALID"),
    ("symlink", {"source": "Linked.java"}, "CONTRACT_INVALID"),
    ("denied", {"source": "../Outside.java"}, "CONTRACT_INVALID"),
    ("invalid", {"source": "Account.java", "operation": "diff"}, "CONTRACT_INVALID"),
    ("unsupported", {"source": "file.c"}, "CONTRACT_INVALID"),
]
def snapshot():
    return {str(p.relative_to(Path.cwd())): ("symlink", os.readlink(p)) if p.is_symlink()
            else ("file", hashlib.sha256(p.read_bytes()).hexdigest()) if p.is_file() else ("directory",)
            for p in Path.cwd().rglob("*")}
before = snapshot()
local, bindings = [], 0
for variant, arguments, status in cases:
    command = [str(root / "bin/formalspecgen"), "contract", arguments.get("operation", "extract"),
               arguments["source"], "--json", "-"]
    if "candidate" in arguments:
        command += ["--candidate", arguments["candidate"]]
    process = subprocess.run(command, capture_output=True, text=True, timeout=30)
    satisfied = status in ("CONTRACT_EXTRACTED", "CONTRACT_COMPARED")
    assert process.returncode == (0 if satisfied else 1), (variant, process.stderr)
    envelope = json.loads(process.stdout)
    assert envelope["schema"] == "formalspecgen-cli-result-v1"
    assert envelope["operation_satisfied"] is satisfied
    result = envelope["result"]
    assert result["status"] == status and result["request_satisfied"] is satisfied
    assert result["claim"] == "NO_PROOF"
    local.append(result)
    if variant in ("invalid", "unsupported"):
        assert result["code"] == "INVALID_REQUEST"
        continue
    assert result["review_status"] == "NOT_ASSESSED"
    assert not result["semantic_equivalence_proved"] and not result["behavior_equivalence_proved"]
    def resolve(pointer):
        value = result
        for token in pointer[1:].split("/"):
            value = value[token.replace("~1", "/").replace("~0", "~")]
        return value
    for item in result["inputs"].values():
        content = Path(item["path"]).read_bytes()
        assert item["sha256"] == hashlib.sha256(content).hexdigest() and item["size"] == len(content)
        bindings += 1
    for role, inventory in result["clause_inventory"].items():
        assert inventory["adequacy"] == inventory["effective_contracts"] == "NOT_ASSESSED"
        assert resolve(inventory["input_pointer"]) == result["inputs"][role]
        assert inventory["member_count"] == len(inventory["members"])
        assert inventory["members_without_explicit_clauses"] == sum(m["clause_count"] == 0 for m in inventory["members"])
        for member in inventory["members"]:
            assert len(resolve(member["clauses_pointer"])) == member["clause_count"] == sum(member["keywords"].values())
    if variant in ("mixed", "no-clauses", "empty"):
        inventory = result["clause_inventory"]["source"]
        expected = {"mixed": (3, 2), "no-clauses": (1, 1), "empty": (0, 0)}[variant]
        assert (inventory["member_count"], inventory["members_without_explicit_clauses"]) == expected
    if status == "CONTRACT_COMPARED":
        comparison = result["comparison"]
        assert comparison["surface_equal"] is (variant == "body")
        changes = comparison["review_changes"]
        if variant == "body":
            assert changes == []
        else:
            category = "CONTRACT_CLAUSES" if variant == "clause" else "PROOF_TRUST"
            assert category in {item["category"] for item in changes}
        for change in changes:
            for role in ("source", "candidate"):
                reference = change[role]
                assert resolve(reference["input_pointer"]) == result["inputs"][role]
                if reference["present"]:
                    assert resolve(reference["surface_pointer"]) == reference["value"]
                else:
                    assert reference["surface_pointer"] is None and reference["value"] is None
    if variant == "missing-candidate":
        assert set(result["clause_inventory"]) == {"source"} and "comparison" not in result
    if variant == "syntax":
        assert result["clause_inventory"] == {}

async def transport():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    parameters = StdioServerParameters(command=sys.executable,
        args=["-c", guard + "\nmcp_server.create_server().run()"], cwd=str(Path.cwd()), env=dict(os.environ))
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tool = next(t for t in (await session.list_tools()).tools if t.name == "inspect_contract")
            assert set(tool.inputSchema["properties"]) == {"source", "operation", "candidate"}
            for (_, arguments, _), expected in zip(cases, local):
                response = await session.call_tool("inspect_contract", arguments)
                assert not response.isError
                actual = response.structuredContent
                if expected.get("code") == "INVALID_REQUEST":
                    assert "mcp_admission" not in actual
                else:
                    assert actual["mcp_admission"]["granted_effects"] == ["workspace_read"]
                assert {k: v for k, v in actual.items() if k != "mcp_admission"} == expected
remote = sys.argv[1] == "mcp"
if remote:
    asyncio.run(asyncio.wait_for(transport(), timeout=45))
assert snapshot() == before, "Installed contract inspection changed its workspace"
print(json.dumps({"cli_calls": len(cases), "mcp_calls": len(cases) if remote else 0,
                  "input_bindings": bindings, "installed_root": str(root), "read_only": True}))
'''
    checked = subprocess.run([sys.executable, "-c", script, interface], cwd=tmp_path,
        env=environment, capture_output=True, text=True, timeout=120)
    assert checked.returncode == 0, (checked.stdout + checked.stderr)[-6000:]
    assert json.loads(checked.stdout) == {
        "cli_calls": 16, "mcp_calls": 16 if interface == "mcp" else 0,
        "input_bindings": 13, "installed_root": str(target.resolve()), "read_only": True}


@pytest.mark.parametrize("interface", ["cli", "mcp"])
def test_installed_security_template_interfaces(installed_wheel, tmp_path, interface):
    if interface == "mcp" and os.environ.get("FORMALSPECGEN_REQUIRE_INSTALLED_MCP_ACCEPTANCE") != "1":
        pytest.skip("requires installed MCP acceptance")
    target, _, environment = installed_wheel
    script = r'''
import asyncio, hashlib, json, os, subprocess, sys
from pathlib import Path
import mcp_server
import pipeline.security_template_workflow as workflow
root = Path(os.environ["PYTHONPATH"]).resolve()
assert Path(workflow.__file__).resolve().is_relative_to(root)
assert Path(mcp_server.__file__).resolve().is_relative_to(root)
Path("Target.java").write_text("class Target { public int get(int[] a, int i) { return a[i]; } }")
Path("report.json").write_text('[{"cwe":"CWE-125"}]')
before = {name: Path(name).read_bytes() for name in ("Target.java", "report.json")}
process = subprocess.run([str(root / "bin/formalspecgen"), "security-exploit", "report.json",
    "Target.java", "--json", "-"], capture_output=True, text=True, timeout=30)
assert process.returncode == 0, process.stderr
local = json.loads(process.stdout)["result"]
def validate(result):
    assert result["request_satisfied"] and result["claim"] == "NO_PROOF"
    assert not result["executed"] and not result["exploit_proven"]
    for entry in result["generated"]:
        assert hashlib.sha256(Path(entry["file"]).read_bytes()).hexdigest() == entry["sha256"]
        assert entry["file"] == result["publication"]["artifacts"][entry["publication_key"]]["path"]
validate(local)
async def transport():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    parameters = StdioServerParameters(command=sys.executable, args=["-c",
        "import mcp_server; mcp_server.create_server().run()"], cwd=str(Path.cwd()), env=dict(os.environ))
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            assert "security_exploit" in {tool.name for tool in (await session.list_tools()).tools}
            response = await session.call_tool("security_exploit", {
                "report_path":"report.json", "target":"Target.java", "result_export":"-"})
            assert not response.isError
            remote = response.structuredContent
            validate(remote)
            assert remote["workflow_result"]["request"] == local["workflow_result"]["request"]
            assert remote["input_manifest"] == local["input_manifest"]
            assert [e["sha256"] for e in remote["generated"]] == [e["sha256"] for e in local["generated"]]
if sys.argv[1] == "mcp":
    asyncio.run(asyncio.wait_for(transport(), timeout=45))
assert before == {name: Path(name).read_bytes() for name in before}
print("installed review-only templates passed")
'''
    checked = subprocess.run([sys.executable, "-c", script, interface], cwd=tmp_path,
        env=environment, capture_output=True, text=True, timeout=120)
    assert checked.returncode == 0, (checked.stdout + checked.stderr)[-6000:]
    assert "installed review-only templates passed" in checked.stdout
