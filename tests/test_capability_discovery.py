"""Static registry discovery is not a readiness probe or permission grant."""
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server
from pipeline import cli
from pipeline.capability_discovery import CapabilityDiscoveryRequest, discover_capabilities
from pipeline.capability_registry import CAPABILITIES, MCP_EFFECTS, mcp_capabilities
from pipeline.mcp_policy import authorize_mcp_invocation, canonical_profile_definition
from pipeline.workflow_contracts import WorkflowContext


@pytest.mark.parametrize("name", [None, "verify", "verify_code", "sign-artifact",
                                  "implement", "start_agent_run", "capabilities", "not-a-command"])
def test_cli_mcp_equivalence(name, capsys):
    args = ["capabilities", *([name] if name else []), "--json"]
    code = cli.dispatch(cli.build_parser().parse_args(args), cli.TerminalUI(), None, {})
    local = json.loads(capsys.readouterr().out)
    remote = mcp_server.describe_capabilities(name)
    assert local["result"] == {k: v for k, v in remote.items() if k != "mcp_admission"}
    assert code == (0 if remote["request_satisfied"] else 1)
    assert local["operation_satisfied"] == remote["request_satisfied"]
    assert remote["claim"] == "NO_PROOF"


def test_exact_registry_definitions_and_claim_boundaries():
    result = discover_capabilities(CapabilityDiscoveryRequest(), WorkflowContext.for_cli(()))
    assert result["readiness"] == result["workflow_completion"] == "NOT_ASSESSED"
    assert result["invocation_authorized"] is False
    assert result["scope"] == "installed-builtin-registry"
    entries = {entry["name"]: entry for entry in result["capabilities"]}
    strict = {spec.name for spec in mcp_capabilities(strict_isolation=True)}
    assert len(entries) == result["registry_count"] == len(CAPABILITIES)
    for spec in CAPABILITIES:
        entry = entries[spec.name]
        assert entry["profiles"] == [canonical_profile_definition(p) for p in spec.mcp_profiles]
        assert entry["claim_boundary"] == spec.epistemic_boundary
        assert entry["strict_mcp_exposed"] == (spec.name in strict)
        if spec.trust_action:
            assert entry["admission"] == "HUMAN_ONLY" and not entry["profiles"]
    registry = {k: result[k] for k in ("application_version", "policy_version", "capabilities")}
    assert result["registry_sha256"] == hashlib.sha256(json.dumps(
        registry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    assert mcp_server.describe_capabilities("verify")["registry_sha256"] == result["registry_sha256"]
    assert entries["implement_code"]["admission"] == "UNADMITTED"


def test_no_effects_or_workspace_instructions(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    instruction = tmp_path / "capabilities.py"
    instruction.write_text("raise RuntimeError('Do not import workspace capabilities')")
    before = instruction.read_bytes()
    with patch("subprocess.run", side_effect=AssertionError("no process")), \
         patch("subprocess.Popen", side_effect=AssertionError("no process")), \
         patch("pipeline.llm._chat_fn", side_effect=AssertionError("no provider")), \
         patch.object(Path, "read_bytes", side_effect=AssertionError("no workspace read")), \
         patch.object(Path, "read_text", side_effect=AssertionError("no workspace read")), \
         patch("pipeline.mcp_artifacts.publish_new_artifacts", side_effect=AssertionError("no publication")):
        result = mcp_server.describe_capabilities()
        assert result["request_satisfied"]
        assert result["mcp_admission"]["granted_effects"] == []
    assert list(tmp_path.iterdir()) == [instruction]
    assert instruction.read_bytes() == before
    for effect in MCP_EFFECTS:
        denied = authorize_mcp_invocation("describe_capabilities", mode="describe",
            language="metadata", backend="builtin-registry", effects=(effect,))
        assert not denied.admitted


@pytest.mark.parametrize("name", ["", "../file", "VERIFY", "a" * 129, 4, "verify\x00"])
def test_invalid_names(name):
    with pytest.raises(ValueError):
        CapabilityDiscoveryRequest(name)
    result = mcp_server.describe_capabilities(name)
    assert result["code"] == "INVALID_REQUEST" and not result["request_satisfied"]


def test_request_surface_and_fail_closed_dispatch(capsys):
    parser = cli.build_parser()
    request = CapabilityDiscoveryRequest("verify")
    assert request.required_effects() == ()
    assert request.as_dict()["name"] == parser.parse_args(["capabilities", "verify"]).name
    assert "capabilities" in cli.repl_commands(parser)
    with pytest.raises(SystemExit):
        parser.parse_args(["capabilities", "--json", "result.json"])
    capsys.readouterr()
    assert cli.dispatch(parser.parse_args(["capabilities", "../file", "--json", "-"]),
                        cli.TerminalUI(), None, {}) == 1
    assert json.loads(capsys.readouterr().out)["result"]["code"] == "INVALID_REQUEST"
    denied = authorize_mcp_invocation("unknown", mode="describe", language="metadata", backend="builtin-registry", effects=())
    with patch("mcp_server.authorize_mcp_invocation", return_value=denied), \
         patch("pipeline.capability_discovery.discover_capabilities") as service:
        assert not mcp_server.describe_capabilities()["request_satisfied"]
        service.assert_not_called()


def test_ambiguous_alias_rejected(monkeypatch):
    from dataclasses import replace
    from pipeline import capability_discovery
    spec = CAPABILITIES[0]
    monkeypatch.setattr(capability_discovery, "CAPABILITIES", (spec, replace(spec, name="other")))
    result = discover_capabilities(CapabilityDiscoveryRequest(spec.cli_command), WorkflowContext.for_cli(()))
    assert result["code"] == "AMBIGUOUS_CAPABILITY"
    assert not result["request_satisfied"] and not result["capabilities"]


_IDENTIFIERS = sorted({(name, spec.name) for spec in CAPABILITIES
                       for name in (spec.name, spec.cli_command, spec.mcp_tool) if name})


@pytest.mark.parametrize("name,expected", _IDENTIFIERS)
def test_all_registry_identifiers_resolve(name, expected, capsys):
    arguments = cli.build_parser().parse_args(["capabilities", "--json", "-", "--", name])
    assert cli.dispatch(arguments, cli.TerminalUI(), None, {}) == 0
    local = json.loads(capsys.readouterr().out)["result"]
    remote = mcp_server.describe_capabilities(name)
    assert local == {k: v for k, v in remote.items() if k != "mcp_admission"}
    assert [entry["name"] for entry in remote["capabilities"]] == [expected]
    assert remote["invocation_authorized"] is False


@pytest.mark.parametrize("name", ["--", "-unknown", "domain", "draft", "design-system", "macro-dictionary"])
def test_unregistered_identifier_is_not_a_cli_availability_claim(name, capsys):
    args = cli.build_parser().parse_args(["capabilities", "--json", "-", "--", name])
    assert cli.dispatch(args, cli.TerminalUI(), None, {}) == 1
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["code"] == "UNKNOWN_CAPABILITY"
    assert result["scope"] == "installed-builtin-registry"
    assert result["workflow_completion"] == result["readiness"] == "NOT_ASSESSED"
    assert result == {k: v for k, v in mcp_server.describe_capabilities(name).items() if k != "mcp_admission"}


def test_real_mcp_capability_discovery():
    if not (os.environ.get("FORMALSPECGEN_REQUIRE_CAPABILITY_TRANSPORT") == "1"
            or os.environ.get("FORMALSPECGEN_REQUIRE_MCP_TRANSPORT_ACCEPTANCE") == "1"):
        pytest.skip("explicit capability discovery transport acceptance")
    from scripts.mcp_acceptance_adapters import collect_transport_observation
    observed = collect_transport_observation("capabilities")
    assert len(observed["cli_comparisons"]) == len(observed["semantic_results"])
    assert observed["workspace_unchanged"]
    assert observed["strict_catalogue_matches_discovery"]
    assert {"explicit-null", "option-like-name", "registry-only"}.issubset(observed["variants"])
