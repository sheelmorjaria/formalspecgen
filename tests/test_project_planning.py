"""Project metadata never grants workflow execution or approval authority."""
import copy
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server
from pipeline import cli
from pipeline.mcp_policy import MCPPolicyViolation, authorize_mcp_invocation
from pipeline.project_planning import ProjectWorkflowRequest, inspect_project
from pipeline.workflow_contracts import WorkflowContext


def project_document():
    return {"schema": "formalspecgen-project-v1", "targets": [
        {"name": "app", "sources": ["src/S.java"], "contracts": ["contracts/S.jml"],
         "depends_on": ["base"], "workflows": [{"capability": "verify_code", "profile": "java-openjml-verification"}]},
        {"name": "base", "sources": ["lib/S.java"], "workflows": [
            {"capability": "inspect_code", "profile": "java-readonly-inspection"}]}],
        "policy": {"output_root": "results", "budgets": {"max_execution_seconds": 30},
                   "required_assurance": "DEDUCTIVE_PROOF"}}


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name, value in {"src/S.java": "class S {}", "lib/S.java": "class S {} // library",
                        "contracts/S.jml": "class S {}", "project.json": json.dumps(project_document())}.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
    return tmp_path


def run(root, operation="plan", target=None, **limits):
    return inspect_project(ProjectWorkflowRequest("project.json", operation, target),
        WorkflowContext.for_cli(("workspace_read",), workspace_root=root, resource_budget=limits))


@pytest.mark.parametrize("operation,target", [("validate", None), ("plan", None), ("plan", "app"),
                                             ("validate", "base"), ("plan", "base")])
def test_equivalent_interfaces_and_captured_identities(project, capsys, operation, target):
    args = ["project", operation, "project.json", "--json"] + (["--target", target] if target else [])
    assert cli.dispatch(cli.build_parser().parse_args(args), cli.TerminalUI(), None, {}) == 0
    local = json.loads(capsys.readouterr().out)["result"]
    remote = mcp_server.inspect_project("project.json", operation, target)
    assert local == {k: v for k, v in remote.items() if k != "mcp_admission"}
    assert local["claim"] == "NO_PROOF" and not local["invocation_authorized"]
    assert local["assurance"] == local["readiness"] == local["contract_approval"] == "NOT_ASSESSED"
    assert local["targets"] == (["base"] if target == "base" else ["base", "app"])
    assert len(local["steps"]) == (len(local["targets"]) if operation == "plan" else 0)
    assert local["unselected_targets"] == (["app"] if target == "base" else [])
    for item in local["inputs"]:
        content = (project / item["path"]).read_bytes()
        assert item["sha256"] == hashlib.sha256(content).hexdigest() and item["size"] == len(content)
    assert local["inputs_sha256"] == hashlib.sha256(json.dumps(local["inputs"],
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert remote["mcp_admission"]["granted_effects"] == ["workspace_read"]
    assert set(local["target_inputs"]) == set(local["targets"])
    inventory = {item["path"]: item for item in local["inputs"]}
    for name, bindings in local["target_inputs"].items():
        assert bindings["capture_complete"]
        for field in ("sources", "contracts"):
            expected = [{key: item[key] for key in ("path", "size", "sha256")}
                        for item in inventory.values() if f"{name}:{field}" in item["roles"]]
            assert bindings[field] == expected


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(schema="unknown"),
    lambda d: d.update(approved=True),
    lambda d: d.update(targets=[]),
    lambda d: d["targets"].append(copy.deepcopy(d["targets"][0])),
    lambda d: d["targets"][0].update(depends_on=["missing"]),
    lambda d: d["targets"][1].update(depends_on=["app"]),
    lambda d: d["targets"][0].update(sources=["../S.java"]),
    lambda d: d["targets"][0].update(sources=["/S.java"]),
    lambda d: d["targets"][0].update(sources=["src/S.java", "src/./S.java"]),
    lambda d: d["targets"][0].update(workflows=[{"capability": "verify_code", "profile": "x", "approved": True}]),
    lambda d: d["policy"].update(provider_key="do-not-accept-secrets"),
    lambda d: d["policy"].update(budgets={"max_input_bytes": True}),
    lambda d: d["policy"].update(budgets={"max_input_bytes": -1}),
    lambda d: d["policy"].update(output_root="../outside"),
])
def test_invalid_declarations_fail_closed(project, mutation):
    document = project_document()
    mutation(document)
    (project / "project.json").write_text(json.dumps(document))
    result = run(project)
    assert result["status"] == "PROJECT_INVALID" and not result["request_satisfied"]
    assert not result["invocation_authorized"]


@pytest.mark.parametrize("capability,profile", [("unknown", "x"), ("implement_code", "x"),
                                              ("sign_artifact", "x"), ("verify_code", "unknown")])
def test_unadmitted_steps_are_visible_blockers(project, capability, profile):
    document = project_document()
    document["targets"][0]["workflows"] = [{"capability": capability, "profile": profile}]
    (project / "project.json").write_text(json.dumps(document))
    result = run(project)
    assert result["status"] == "PROJECT_BLOCKED" and not result["request_satisfied"]
    assert any(f["code"] == "PROFILE_UNAVAILABLE" and f["blocking"] for f in result["findings"])
    assert not result["steps"][-1]["profile_available"]
    assert len(result["inputs"]) == 4


@pytest.mark.parametrize("limits", [{"max_input_bytes": 10}, {"max_input_files": 2},
    {"max_targets": 1}, {"max_steps": 1}, {"max_path_depth": 1}, {"max_input_bytes": 0}])
def test_aggregate_limits(project, limits):
    assert not run(project, **limits)["request_satisfied"]


def test_exact_limit_and_once_capture(project, monkeypatch):
    size = sum(p.stat().st_size for p in project.rglob("*") if p.is_file())
    assert run(project, max_input_bytes=size, max_input_files=4)["request_satisfied"]
    assert not run(project, max_input_bytes=size - 1)["request_satisfied"]
    from pipeline import project_planning
    original = project_planning.capture
    calls = []
    def capture(*args):
        calls.append(args[0])
        result = original(*args)
        if args[0] == "project.json":
            (project / "project.json").write_text("replaced after capture")
        return result
    monkeypatch.setattr(project_planning, "capture", capture)
    result = run(project)
    assert result["request_satisfied"] and len(calls) == 4
    assert result["manifest_sha256"] != hashlib.sha256((project / "project.json").read_bytes()).hexdigest()


@pytest.mark.parametrize("kind", ["symlink-file", "symlink-directory", "fifo", "missing"])
def test_unsafe_inputs(project, kind):
    source = project / "src/S.java"
    source.unlink()
    if kind == "symlink-file":
        source.symlink_to(project / "lib/S.java")
    elif kind == "symlink-directory":
        source.parent.rmdir()
        source.parent.symlink_to(project / "lib", target_is_directory=True)
    elif kind == "fifo":
        os.mkfifo(source)
    assert not run(project)["request_satisfied"]


def test_no_effects_or_policy_escalation(project):
    before = {p.relative_to(project).as_posix(): p.read_bytes() for p in project.rglob("*") if p.is_file()}
    with patch("subprocess.run", side_effect=AssertionError("no tool probe")), \
         patch("subprocess.Popen", side_effect=AssertionError("no execution")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no provider")), \
         patch("pipeline.mcp_artifacts.publish_new_artifacts", side_effect=AssertionError("no publication")):
        assert mcp_server.inspect_project("project.json", "plan")["request_satisfied"]
    assert before == {p.relative_to(project).as_posix(): p.read_bytes() for p in project.rglob("*") if p.is_file()}
    denied = authorize_mcp_invocation("inspect_project", mode="plan", language="metadata",
                                     backend="builtin-project", effects=("workspace_read", "external_execution"))
    assert not denied.admitted
    with patch("pipeline.project_planning.capture", side_effect=AssertionError("denied before read")):
        with pytest.raises(MCPPolicyViolation):
            inspect_project(ProjectWorkflowRequest("project.json"), WorkflowContext.for_cli(()))
    with patch("mcp_server.authorize_mcp_invocation", return_value=denied), \
         patch("pipeline.project_planning.inspect_project") as service:
        assert not mcp_server.inspect_project("project.json")["request_satisfied"]
        service.assert_not_called()


@pytest.mark.parametrize("raw", ['{"schema":1,"schema":2}', '{"schema":NaN}', '[1]', '{}', '{'])
def test_strict_json(project, raw):
    (project / "project.json").write_text(raw)
    assert not run(project)["request_satisfied"]


def test_selected_dependencies_and_nested_manifest(project):
    (project / "src/S.java").unlink()
    assert run(project, target="base")["request_satisfied"]
    assert not run(project, target="unknown")["request_satisfied"]
    (project / "lib/project.json").write_text(json.dumps({"schema": "formalspecgen-project-v1", "targets": [
        {"name": "lib", "sources": ["S.java"], "workflows": [
            {"capability": "inspect_code", "profile": "java-readonly-inspection"}]}]}))
    result = inspect_project(ProjectWorkflowRequest("lib/project.json"), WorkflowContext.for_cli(("workspace_read",)))
    assert result["request_satisfied"]
    assert {p["path"] for p in result["inputs"]} == {"lib/project.json", "lib/S.java"}
    assert result["target_inputs"]["lib"]["sources"][0]["path"] == "lib/S.java"


def test_repeated_inputs_share_one_capture_and_non_ascii_identity(project):
    document = project_document()
    (project / "lib/S.java").rename(project / "lib/é.java")
    document["targets"][1]["sources"] = ["lib/é.java"]
    document["targets"][0]["contracts"] = ["lib/é.java"]
    (project / "project.json").write_text(json.dumps(document))
    result = run(project, max_input_files=3)
    assert result["request_satisfied"] and len(result["inputs"]) == 3
    shared = next(item for item in result["inputs"] if item["path"] == "lib/é.java")
    assert shared["roles"] == ["base:sources", "app:contracts"]
    assert result["target_inputs"]["base"]["sources"] == result["target_inputs"]["app"]["contracts"]
    assert result["inputs_sha256"] == hashlib.sha256(json.dumps(result["inputs"], sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


@pytest.mark.parametrize("arguments", [["project", "execute", "project.json"],
    ["project", "plan", "project.json", "--json", "output.json"]])
def test_cli_rejects_execution_and_export(arguments):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(arguments)


def test_target_binding_uses_captured_bytes_and_preserves_completed_dependencies(project, monkeypatch):
    from pipeline import project_planning
    original = project_planning.capture
    captured = (project / "lib/S.java").read_bytes()
    calls = []
    def capture(name, *args):
        content = original(name, *args)
        calls.append(name)
        if content == captured:
            (project / "lib/S.java").write_text("changed after capture")
        return content
    monkeypatch.setattr(project_planning, "capture", capture)
    (project / "contracts/S.jml").unlink()
    result = run(project)
    assert result["status"] == "PROJECT_INVALID" and not result["request_satisfied"]
    assert result["target_inputs"]["base"]["capture_complete"]
    assert result["target_inputs"]["base"]["sources"][0]["sha256"] == hashlib.sha256(captured).hexdigest()
    assert not result["target_inputs"]["app"]["capture_complete"]
    assert result["target_inputs"]["app"]["sources"][0]["path"] == "src/S.java"
    assert result["target_inputs"]["app"]["contracts"] == []
    assert calls.count("S.java") == 2  # distinct lib/ and src/ inputs, each read once


def test_target_bindings_preserve_declared_order_for_shared_sources(project):
    document = project_document()
    document["targets"][0]["sources"] = ["src/S.java", "lib/S.java"]
    (project / "project.json").write_text(json.dumps(document))
    result = run(project)
    assert result["request_satisfied"]
    bindings = result["target_inputs"]
    assert [item["path"] for item in bindings["app"]["sources"]] == ["src/S.java", "lib/S.java"]
    assert bindings["base"]["sources"][0] == bindings["app"]["sources"][1]


@pytest.mark.parametrize("arguments", [{"manifest": ""}, {"manifest": None},
    {"manifest": "x", "operation": []}, {"manifest": "x", "target": "../x"}])
def test_invalid_requests(arguments):
    assert mcp_server.inspect_project(**arguments)["code"] == "INVALID_REQUEST"


def test_real_project_transport():
    if not (os.environ.get("FORMALSPECGEN_REQUIRE_PROJECT_TRANSPORT") == "1"
            or os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") == "1"):
        pytest.skip("explicit project transport acceptance")
    from scripts.mcp_acceptance_adapters import collect_transport_observation
    result = collect_transport_observation("project")
    assert result["workspace_unchanged"]
    assert len(result["cli_comparisons"]) == 9


def test_completion_requires_installed_project_transport():
    import yaml

    root = Path(__file__).resolve().parents[1]
    plan = json.loads((root / "mcpdocs/mcp_parity_plan.json").read_text())
    project = next(item for item in plan["commands"] if item["cli_command"] == "project")
    contract = project["completion_contract"]
    variants = {"installed-wheel", "installed-cli", "installed-mcp"}
    assert variants <= set(contract["required_variants"])
    case = next(case for case in contract["acceptance_cases"] if case["test"] ==
                "tests/test_wheel_install.py::test_installed_project_interfaces")
    assert case["kind"] == "mcp_transport" and variants <= set(case["variants"])
    workflow = yaml.safe_load((root / ".github/workflows/tests.yml").read_text())
    step = next(step for step in workflow["jobs"]["sandbox-acceptance"]["steps"]
                if step.get("name") == "Produce provisioned MCP workflow acceptance evidence")
    assert step["env"]["FORMALSPECGEN_REQUIRE_INSTALLED_MCP_ACCEPTANCE"] == "1"
    assert "--command project" in step["run"]
