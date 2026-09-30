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


@pytest.mark.parametrize("operation", ["validate", "plan", "impact"])
def test_effect_preview_is_descriptive_and_interface_equivalent(project, capsys, operation):
    document = project_document()
    document["targets"][0]["workflows"].append({"capability": "document_code", "profile": "java-provider-assisted-documentation"})
    (project / "project.json").write_text(json.dumps(document))
    before = {p: p.read_bytes() for p in project.rglob("*") if p.is_file()}
    extra = {"changed_paths": ["src/S.java"]} if operation == "impact" else {}
    args = ["project", operation, "project.json", "--json", "-"]
    if extra:
        args += ["--changed", "src/S.java"]
    with patch("subprocess.run", side_effect=AssertionError("no probe")), \
         patch("subprocess.Popen", side_effect=AssertionError("no execution")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no disclosure")), \
         patch("pipeline.mcp_artifacts.publish_new_artifacts", side_effect=AssertionError("no publication")):
        remote = mcp_server.inspect_project("project.json", operation, **extra)
        assert cli.dispatch(cli.build_parser().parse_args(args), cli.TerminalUI(), None, {}) == 0
    local = json.loads(capsys.readouterr().out)["result"]
    assert local == {key: value for key, value in remote.items() if key != "mcp_admission"}
    assert local["request_satisfied"] and local["claim"] == "NO_PROOF"
    preview = local["effect_preview"]
    assert preview["resolution_complete"] and not preview["invocation_authorized"]
    assert preview["invocation_effects"] == preview["provider_disclosure"] == "NOT_ASSESSED"
    assert preview["effect_ceiling_union"] == ["evidence_publication", "external_execution", "provider_access", "workspace_read", "workspace_write_new"]
    assert preview["provider_options_union"] == ["glm", "ollama", "openai"]
    assert preview["output_scopes"] == ["designated-new-artifacts", "immutable-evidence-only", "none"]
    assert [(s["target"], s["workflow_index"]) for s in preview["steps"]] == [("base", 0), ("app", 0), ("app", 1)]
    for key in ("manifest_sha256", "registry_sha256", "policy_version"):
        assert preview[key] == local[key]
    for step in preview["steps"]:
        profile = local["target_fingerprints"][step["target"]]["binding"]["workflows"][step["workflow_index"]]["profile_definition"]
        assert step["effect_ceiling"] == profile["effects"]
        assert step["provider_options"] == profile["providers"]
        assert step["output_scope"] == profile["output_scope"]
    assert remote["mcp_admission"]["granted_effects"] == ["workspace_read"]
    assert before == {p: p.read_bytes() for p in project.rglob("*") if p.is_file()}


@pytest.mark.parametrize("failure", ["unknown", "unadmitted", "all-unresolved", "missing-source", "invalid-graph", "selected"])
def test_effect_preview_preserves_unknown_and_incomplete_scope(project, failure):
    document = project_document()
    if failure in {"unknown", "all-unresolved", "unadmitted"}:
        document["targets"][0]["workflows"] = [{"capability": "implement_code" if failure == "unadmitted" else "unknown", "profile": "unavailable"}]
        if failure == "all-unresolved":
            document["targets"][1]["workflows"] = document["targets"][0]["workflows"]
    elif failure == "missing-source":
        document["targets"][0]["sources"] = ["missing.java"]
    elif failure == "invalid-graph":
        document["targets"][0]["depends_on"] = ["missing"]
    else:
        document["targets"][0]["workflows"] = [{"capability": "document_code", "profile": "java-provider-assisted-documentation"}]
    (project / "project.json").write_text(json.dumps(document))
    result = run(project, target="base" if failure == "selected" else None)
    if failure == "invalid-graph":
        assert "effect_preview" not in result and not result["request_satisfied"]
        return
    preview = result["effect_preview"]
    assert not preview["invocation_authorized"]
    if failure == "selected":
        assert result["request_satisfied"] and preview["resolution_complete"]
        assert len(preview["steps"]) == 1 and preview["steps"][0]["target"] == "base"
        assert preview["effect_ceiling_union"] == ["workspace_read"] and preview["provider_options_union"] == []
    elif failure == "missing-source":
        assert result["status"] == "PROJECT_INVALID" and not result["request_satisfied"]
        assert preview["resolution_complete"] and len(preview["steps"]) == 2
        assert not result["target_inputs"]["app"]["capture_complete"]
    else:
        assert result["status"] == "PROJECT_BLOCKED" and not preview["resolution_complete"]
        unresolved = [step for step in preview["steps"] if not step["resolved"]]
        assert len(unresolved) == (2 if failure == "all-unresolved" else 1)
        assert all(step[key] is None for step in unresolved for key in ("effect_ceiling", "provider_options", "output_scope"))
        assert preview["effect_ceiling_union"] == ([] if failure == "all-unresolved" else ["workspace_read"])


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


def assert_target_fingerprints(result):
    expected = {name for name, item in result["target_inputs"].items() if item["capture_complete"]}
    assert set(result["target_fingerprints"]) == expected
    for name, fingerprint in result["target_fingerprints"].items():
        binding = fingerprint["binding"]
        assert fingerprint["sha256"] == hashlib.sha256(json.dumps(binding, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        assert fingerprint["scope"] == "declared-inputs-and-registry-metadata-only"
        assert fingerprint["evidence_reuse_authorized"] is False
        assert binding["target"] == name
        assert binding["schema"] == "formalspecgen-project-target-binding-v1"
        assert binding["requested_policy"] == result["requested_policy"]
        assert binding["registry_sha256"] == result["registry_sha256"]
        assert binding["policy_version"] == result["policy_version"]
        for field in ("sources", "contracts"):
            assert binding[field] == result["target_inputs"][name][field]
        assert all(dep["sha256"] == result["target_fingerprints"][dep["target"]]["sha256"]
                   for dep in binding["dependencies"])
        assert all(not step["invocation_authorized"] for step in binding["workflows"])


def test_target_fingerprints_are_inspectable_and_selection_independent(project, capsys):
    original = run(project)
    assert_target_fingerprints(original)
    for operation in ("validate", "plan", "impact"):
        kwargs = {"changed_paths": ["lib/S.java"]} if operation == "impact" else {"target": "app"}
        remote = mcp_server.inspect_project("project.json", operation, **kwargs)
        assert_target_fingerprints(remote)
        assert remote["target_fingerprints"] == original["target_fingerprints"]
        args = ["project", operation, "project.json", "--json"]
        args += ["--changed", "lib/S.java"] if operation == "impact" else ["--target", "app"]
        assert cli.dispatch(cli.build_parser().parse_args(args), cli.TerminalUI(), None, {}) == 0
        assert json.loads(capsys.readouterr().out)["result"] == {
            k: v for k, v in remote.items() if k != "mcp_admission"}
    selected = run(project, target="base")
    assert selected["target_fingerprints"]["base"] == original["target_fingerprints"]["base"]
    document = json.loads((project / "project.json").read_bytes())
    (project / "project.json").write_text(json.dumps(document, indent=4, sort_keys=True))
    assert run(project)["target_fingerprints"] == original["target_fingerprints"]


@pytest.mark.parametrize("change,affected", [
    ("base-source", {"base", "app"}), ("app-source", {"app"}), ("contract", {"app"}),
    ("unrelated", {"other"}), ("policy", {"base", "app", "other"}),
    ("workflow", {"app"}), ("dependency", {"app"}), ("registry", {"base", "app", "other"})])
def test_target_fingerprint_changes_follow_declared_bindings(project, monkeypatch, change, affected):
    from pipeline import project_planning
    document = project_document()
    document["targets"].append({"name": "other", "sources": ["Other.java"],
        "workflows": [{"capability": "inspect_code", "profile": "java-readonly-inspection"}]})
    (project / "Other.java").write_text("class Other {}")
    manifest = project / "project.json"
    manifest.write_text(json.dumps(document))
    before = run(project)
    if change in {"base-source", "app-source", "contract", "unrelated"}:
        path = {"base-source": "lib/S.java", "app-source": "src/S.java",
                "contract": "contracts/S.jml", "unrelated": "Other.java"}[change]
        (project / path).write_text("changed captured bytes")
    elif change == "policy":
        document["policy"]["required_assurance"] = "BOUNDED_PROOF"
    elif change == "workflow":
        document["targets"][0]["workflows"][0]["profile"] = "unavailable"
    elif change == "dependency":
        document["targets"][0]["depends_on"] = ["base", "other"]
    else:
        discover = project_planning.discover_capabilities
        def changed_registry(*args):
            result = discover(*args)
            result["registry_sha256"] = "0" * 64
            return result
        monkeypatch.setattr(project_planning, "discover_capabilities", changed_registry)
    manifest.write_text(json.dumps(document))
    after = run(project)
    assert_target_fingerprints(after)
    assert {name for name in before["target_fingerprints"] if before["target_fingerprints"][name]["sha256"]
            != after["target_fingerprints"][name]["sha256"]} == affected
    assert after["claim"] == "NO_PROOF" and not after["invocation_authorized"]
    assert after["request_satisfied"] is (change != "workflow")


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
    assert_target_fingerprints(result)
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


@pytest.mark.parametrize("changed,affected,status", [
    (["lib/S.java"], ["base", "app"], "PROJECT_IMPACT_ANALYZED"),
    (["contracts/S.jml"], ["app"], "PROJECT_IMPACT_ANALYZED"),
    (["src/S.java", "contracts/S.jml"], ["app"], "PROJECT_IMPACT_ANALYZED"),
    (["project.json"], ["base", "app"], "PROJECT_IMPACT_ANALYZED"),
    (["unknown.java"], [], "PROJECT_BLOCKED"),
    (["lib/S.java", "unknown.java"], ["base", "app"], "PROJECT_BLOCKED"),
])
def test_impact_cli_mcp_equivalence(project, capsys, changed, affected, status):
    args = ["project", "impact", "project.json", "--json"]
    for path in changed:
        args += ["--changed", path]
    with patch("subprocess.run", side_effect=AssertionError("no git or verifier")), \
         patch("subprocess.Popen", side_effect=AssertionError("no execution")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no provider")):
        code = cli.dispatch(cli.build_parser().parse_args(args), cli.TerminalUI(), None, {})
        local = json.loads(capsys.readouterr().out)["result"]
        remote = mcp_server.inspect_project("project.json", "impact", changed_paths=changed)
    assert local == {k: v for k, v in remote.items() if k != "mcp_admission"}
    assert local["status"] == status and code == (1 if status == "PROJECT_BLOCKED" else 0)
    assert local["impact"]["affected_targets"] == affected
    assert local["impact"]["input_capture_complete"] is True
    assert local["impact"]["unmapped_changes"] == (["unknown.java"] if "unknown.java" in changed else [])
    assert not local["impact"]["evidence_reuse_authorized"] and not local["invocation_authorized"]
    assert local["claim"] == "NO_PROOF" and local["steps"] == []
    assert remote["mcp_admission"]["granted_effects"] == ["workspace_read"]


def test_impact_transitive_diamond_and_nested_manifest(project):
    document = project_document()
    base = document["targets"][1]
    document["targets"].extend([
        {**base, "name": "middle", "sources": ["src/S.java"], "depends_on": ["base"]},
        {**base, "name": "unrelated", "sources": ["contracts/S.jml"]}])
    document["targets"][0]["depends_on"] = ["middle", "base"]
    (project / "project.json").write_text(json.dumps(document))
    context = WorkflowContext.for_cli(("workspace_read",), workspace_root=project)
    result = inspect_project(ProjectWorkflowRequest("project.json", "impact", changed_paths=["lib/S.java"]), context)
    assert result["impact"]["affected_targets"] == ["base", "middle", "app"]
    assert result["impact"]["not_identified_as_affected"] == ["unrelated"]
    assert result["impact"]["reasons"]["app"] == [
        {"kind": "dependency", "target": "middle"}, {"kind": "dependency", "target": "base"}]
    nested = {"schema": document["schema"], "targets": [{**base, "sources": ["S.java"]}]}
    (project / "lib/project.json").write_text(json.dumps(nested))
    for path, reason in [("S.java", "sources"), ("project.json", "manifest")]:
        result = inspect_project(ProjectWorkflowRequest("lib/project.json", "impact", changed_paths=[path]), context)
        assert result["request_satisfied"]
        assert result["impact"]["reasons"]["base"] == [{"kind": reason, "path": path}]
        assert result["target_inputs"]["base"]["sources"][0]["path"] == "lib/S.java"


@pytest.mark.parametrize("arguments", [
    {"operation": "impact"}, {"operation": "impact", "changed_paths": []},
    {"changed_paths": ["src/S.java"]},
    {"operation": "impact", "target": "base", "changed_paths": ["src/S.java"]},
    *({"operation": "impact", "changed_paths": paths} for paths in (
        "src/S.java", [None], ["../outside"], ["/absolute"], ["x", "./x"], ["x"] * 129)),
])
def test_invalid_impact_requests(arguments):
    with pytest.raises(ValueError):
        ProjectWorkflowRequest("project.json", **arguments)


@pytest.mark.parametrize("arguments", [
    {}, {"target": "base", "changed_paths": ["lib/S.java"]},
    {"changed_paths": ["../outside"]}, {"changed_paths": ["lib/S.java", "lib/./S.java"]},
    {"changed_paths": [f"file-{i}.java" for i in range(129)]},
    {"operation": "plan", "changed_paths": ["lib/S.java"]},
])
def test_invalid_impact_adapters_stop_before_dispatch(project, capsys, arguments):
    request = {"manifest": "project.json", "operation": "impact", **arguments}
    argv = ["project", request["operation"], "project.json", "--json"]
    if "target" in request:
        argv += ["--target", request["target"]]
    for path in request.get("changed_paths", []):
        argv += ["--changed", path]
    with patch("pipeline.project_planning.inspect_project", side_effect=AssertionError("no service dispatch")), \
         patch("mcp_server.authorize_mcp_invocation", side_effect=AssertionError("no admission")):
        remote = mcp_server.inspect_project(**request)
        assert cli.dispatch(cli.build_parser().parse_args(argv), cli.TerminalUI(), None, {}) == 1
    assert json.loads(capsys.readouterr().out)["result"] == remote
    assert remote["code"] == "INVALID_REQUEST" and not remote["request_satisfied"]


def test_impact_does_not_read_changed_paths_and_preserves_capture_failures(project):
    context = WorkflowContext.for_cli(("workspace_read",), workspace_root=project)
    (project / "unknown").symlink_to("/etc/passwd")
    result = inspect_project(ProjectWorkflowRequest("project.json", "impact", changed_paths=["unknown"]), context)
    assert result["status"] == "PROJECT_BLOCKED"
    assert "unknown" not in {item["path"] for item in result["inputs"]}
    (project / "src/S.java").unlink()
    result = inspect_project(ProjectWorkflowRequest("project.json", "impact", changed_paths=["src/S.java"]), context)
    assert result["status"] == "PROJECT_INVALID" and not result["request_satisfied"]
    assert result["impact"]["affected_targets"] == ["app"]
    assert result["impact"]["input_capture_complete"] is False
    assert not result["target_inputs"]["app"]["capture_complete"]


@pytest.mark.parametrize("path,affected", [("lib/S.java", ["base", "app"]),
                                          ("src/S.java", ["app"]), ("contracts/S.jml", ["app"])])
@pytest.mark.parametrize("failure", ["missing", "symlink"])
def test_impact_retains_declarations_on_capture_failure(project, capsys, path, affected, failure):
    source = project / path
    source.unlink()
    if failure == "symlink":
        source.symlink_to(project / "project.json")
    with patch("subprocess.run", side_effect=AssertionError("no execution")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no provider")):
        remote = mcp_server.inspect_project("project.json", "impact", changed_paths=[path, "unknown.java"])
        args = ["project", "impact", "project.json", "--changed", path, "--changed", "unknown.java", "--json"]
        assert cli.dispatch(cli.build_parser().parse_args(args), cli.TerminalUI(), None, {}) == 1
    local = json.loads(capsys.readouterr().out)["result"]
    assert local == {k: v for k, v in remote.items() if k != "mcp_admission"}
    assert local["status"] == "PROJECT_INVALID" and not local["request_satisfied"]
    assert_target_fingerprints(local)
    assert local["impact"]["affected_targets"] == affected
    assert local["impact"]["input_capture_complete"] is False
    assert local["impact"]["unmapped_changes"] == ["unknown.java"]
    assert any(f["code"] == "UNMAPPED_CHANGES" and f["blocking"] for f in local["findings"])
    assert path not in {item["path"] for item in local["inputs"]}
    assert "inputs_sha256" not in local
    assert local["claim"] == "NO_PROOF" and not local["invocation_authorized"]
    assert not local["impact"]["evidence_reuse_authorized"]
    assert local["manifest_sha256"] == hashlib.sha256((project / "project.json").read_bytes()).hexdigest()
    if path != "lib/S.java":
        assert local["target_inputs"]["base"]["capture_complete"]


def test_impact_capture_budget_and_invalid_graph_are_distinct(project):
    request = ProjectWorkflowRequest("project.json", "impact", changed_paths=["lib/S.java"])
    context = WorkflowContext.for_cli(("workspace_read",), workspace_root=project,
                                     resource_budget={"max_input_files": 1})
    result = inspect_project(request, context)
    assert result["code"] == "INPUT_LIMIT_EXCEEDED" and not result["request_satisfied"]
    assert result["impact"]["affected_targets"] == ["base", "app"]
    assert not result["impact"]["input_capture_complete"]
    document = project_document()
    document["targets"][1]["depends_on"] = ["app"]
    (project / "project.json").write_text(json.dumps(document))
    result = inspect_project(request, context)
    assert result["status"] == "PROJECT_INVALID" and "impact" not in result
    assert len(result["inputs"]) == 1


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
    assert len(result["cli_comparisons"]) == 28
    assert {"impact-transitive", "reject-missing-changes", "reject-selected-target",
            "impact-missing-source", "impact-missing-contract", "impact-linked-source",
            "fingerprint-input-change", "fingerprint-policy-change", "effect-provider", "effect-selected", "effect-unresolved",
            "reject-traversal", "reject-duplicate", "reject-excessive", "reject-plan-changes"} <= set(result["variants"])


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
