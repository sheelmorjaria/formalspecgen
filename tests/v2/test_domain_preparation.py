# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Bounded input/model preparation, deliberately without backend acceptance."""
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path

import pytest
import yaml

from pipeline import domain_validation_preparation as prep
from pipeline.domain_v2_promotion import candidate_sha256, load_candidate
from pipeline.domain_v2_tla import render_v2_tla
from pipeline.mcp_policy import MCPPolicyViolation
from pipeline.workflow_contracts import WorkflowContext


def value():
    return {"domain_name": "Toggle", "module_name": "toggle",
        "state_variables": [{"kind": "bool", "name": "bit", "initial": False}],
        "operations": [{"name": "flip", "return_type": "void", "failure_semantics": "unavailable",
            "guards": [], "frame": ["bit"], "effects": [{"id": "toggle", "target": "bit",
                "value": {"kind": "not", "expression": {"kind": "field", "name": "bit"}}}]}],
        "tlc_invariants": [{"id": "Trivial", "expression": {"kind": "boolean", "value": True}}]}


def context(root, **limits):
    return WorkflowContext.for_cli(("workspace_read",), workspace_root=root, resource_budget=limits)


@pytest.mark.parametrize("encoding", ["yaml", "json"])
def test_capture_preserves_semantic_hash_and_exact_renderer_bytes(tmp_path, encoding):
    source = tmp_path / ("candidate." + encoding)
    source.write_text(yaml.safe_dump(value()) if encoding == "yaml" else json.dumps(value()))
    expected = load_candidate(source)
    prepared = prep.prepare_domain_candidate(prep.DomainPreparationRequest(source.name), context(tmp_path))
    assert prepared.source_bytes == source.read_bytes()
    assert prepared.candidate_sha256 == candidate_sha256(expected)
    assert json.loads(prepared.candidate_json) == expected.model_dump(mode="json")
    assert (prepared.model.tla, prepared.model.cfg) == render_v2_tla(expected)
    summary = prepared.summary()
    assert summary["claim"] == "NO_PROOF" and not summary["validation_performed"]
    assert summary["review_status"] == "unreviewed"
    assert summary["preparation_limits"] == prep.DOMAIN_PREPARATION_LIMITS
    assert summary["source"] == {"path": source.name, "size": source.stat().st_size,
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    assert all("path" not in identity for identity in summary["generated_models"].values())
    for suffix, text in (("tla", prepared.model.tla), ("cfg", prepared.model.cfg)):
        assert summary["generated_models"]["Toggle." + suffix] == {
            "size": len(text.encode()), "sha256": hashlib.sha256(text.encode()).hexdigest()}
    with pytest.raises(FrozenInstanceError):
        prepared.candidate_json = "{}"
    with pytest.raises(FrozenInstanceError):
        prepared.model.tla = "changed"


def test_path_mutation_after_capture_never_changes_parsed_or_rendered_object(tmp_path, monkeypatch):
    source = tmp_path / "candidate.yaml"
    original = yaml.safe_dump(value()).encode()
    source.write_bytes(original)
    parse = prep._parse_candidate
    calls = []
    def changed_path(content, limits):
        calls.append(content)
        source.write_text("replaced: after capture")
        return parse(content, limits)
    monkeypatch.setattr(prep, "_parse_candidate", changed_path)
    prepared = prep.prepare_domain_candidate(prep.DomainPreparationRequest(source.name), context(tmp_path))
    assert calls == [original] and prepared.source_bytes == original
    assert prepared.model.module_name == "Toggle"


@pytest.mark.parametrize("content,match", [
    ("a: 1\na: 2", "duplicate"), ('{"a":1,"a":2}', "duplicate"),
    ("a: &x [1]\nb: *x", "aliases"), ("a: &x [*x]", "aliases"),
    ("a: {<<: {b: 1}}", "tag"), ("a: !!python/object:builtins.object {}", "tag"),
    ("a: .nan", "tag"), ("a: .inf", "tag"), ("a: 1.5", "tag"),
    ("a: 2026-10-02", "tag"), ("a: !!binary YWJj", "tag"),
    ("1: x", "keys must be strings"), ("[]: x", "keys must be strings"),
    ("---\na: 1\n---\nb: 2", "parsing failed"), ("a: [", "parsing failed"),
    ("[]", "must be an object"), ("", "must be an object"),
    ("a: " + "9" * 65, "integer allowance"),
    ('a: "' + "9" * 65 + '"', "integer allowance"),
])
def test_unsupported_yaml_rejected_before_schema(tmp_path, monkeypatch, content, match):
    source = tmp_path / "candidate.yaml"
    source.write_text(content)
    def forbidden(*_, **__):
        pytest.fail("unsafe YAML reached typed validation")
    monkeypatch.setattr(prep.DomainSpecV2, "model_validate", forbidden)
    with pytest.raises(ValueError, match=match):
        prep.prepare_domain_candidate(prep.DomainPreparationRequest(source.name), context(tmp_path))


@pytest.mark.parametrize("budget,content,match", [
    ({"max_yaml_nodes": 2}, "a: 1", "node allowance"),
    ({"max_yaml_depth": 2}, "a: [[1]]", "depth allowance"),
    ({"max_scalar_chars": 3}, "a: abcd", "scalar allowance"),
    ({"max_integer_chars": 2}, "a: 123", "integer allowance"),
])
def test_parser_limits_precede_object_construction(budget, content, match):
    with pytest.raises(ValueError, match=match):
        prep._parse_candidate(content.encode(), prep.DOMAIN_PREPARATION_LIMITS | budget)
    assert prep._parse_candidate(b"a: 12", prep.DOMAIN_PREPARATION_LIMITS |
        {"max_yaml_nodes": 3, "max_yaml_depth": 2, "max_integer_chars": 2}) == {"a": 12}


def test_missing_read_authority_and_exhausted_capture_never_parse(tmp_path, monkeypatch):
    source = tmp_path / "candidate.yaml"
    source.write_text("abcd")
    request = prep.DomainPreparationRequest(source.name)
    def forbidden(*_, **__):
        pytest.fail("unauthorized or excessive source reached parser")
    monkeypatch.setattr(prep, "_parse_candidate", forbidden)
    with pytest.raises(MCPPolicyViolation):
        prep.prepare_domain_candidate(request, WorkflowContext.for_cli((), workspace_root=tmp_path))
    with pytest.raises(ValueError, match="byte allowance"):
        prep.prepare_domain_candidate(request, context(tmp_path, max_input_bytes=3))
    with pytest.raises(ValueError, match="positive integer"):
        prep.prepare_domain_candidate(request, context(tmp_path, max_input_files=0))
    with pytest.raises(ValueError, match="positive integer"):
        prep.prepare_domain_candidate(request, context(tmp_path, max_yaml_nodes=True))


@pytest.mark.parametrize("kind", ["missing", "outside", "parent", "symlink", "directory-link", "fifo"])
def test_unsafe_input_paths_fail_closed(tmp_path, kind):
    source = tmp_path / "source.yaml"
    source.write_text(yaml.safe_dump(value()))
    requested = "missing.yaml"
    if kind == "outside":
        requested = str(tmp_path.parent / "outside.yaml")
    elif kind == "parent":
        requested = "../outside.yaml"
    elif kind == "symlink":
        (tmp_path / "link.yaml").symlink_to(source)
        requested = "link.yaml"
    elif kind == "directory-link":
        (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
        requested = "link/source.yaml"
    elif kind == "fifo":
        os.mkfifo(tmp_path / "pipe.yaml")
        requested = "pipe.yaml"
    with pytest.raises((OSError, ValueError)):
        prep.prepare_domain_candidate(prep.DomainPreparationRequest(requested), context(tmp_path))


def test_input_byte_limit_exact_and_path_depth(tmp_path):
    source = tmp_path / "candidate.yaml"
    source.write_text(yaml.safe_dump(value()))
    prepared = prep.prepare_domain_candidate(prep.DomainPreparationRequest(source.name),
        context(tmp_path, max_input_bytes=source.stat().st_size))
    assert prepared.source_bytes == source.read_bytes()
    assert prepared.summary()["preparation_limits"]["max_input_bytes"] == source.stat().st_size
    with pytest.raises(ValueError, match="path depth"):
        prep.prepare_domain_candidate(prep.DomainPreparationRequest("a/b.yaml"),
                                      context(tmp_path, max_path_depth=1))


def test_context_cannot_raise_installed_limits(tmp_path, monkeypatch):
    source = tmp_path / "candidate.yaml"
    source.write_bytes(b"x" * (prep.DOMAIN_PREPARATION_LIMITS["max_input_bytes"] + 1))
    def forbidden(*_):
        pytest.fail("raised caller limit permitted excessive input")
    monkeypatch.setattr(prep, "_parse_candidate", forbidden)
    with pytest.raises(ValueError, match="byte allowance"):
        prep.prepare_domain_candidate(prep.DomainPreparationRequest(source.name),
            context(tmp_path, **{key: ceiling * 2 for key, ceiling in prep.DOMAIN_PREPARATION_LIMITS.items()}))


def test_module_name_and_renderer_boundary_fail_before_prepared_result(tmp_path):
    source = tmp_path / "candidate.yaml"
    candidate = value()
    candidate["domain_name"] = "A" * 129
    source.write_text(yaml.safe_dump(candidate))
    with pytest.raises(ValueError, match="unsafe TLA"):
        prep.prepare_domain_candidate(prep.DomainPreparationRequest(source.name), context(tmp_path))
    candidate = value()
    candidate["operations"][0].update(return_type="boolean", failure_semantics="exception",
        exception_type="Failure", exception_trigger={"kind": "boolean", "value": True})
    source.write_text(yaml.safe_dump(candidate))
    with pytest.raises(ValueError, match="exception-result"):
        prep.prepare_domain_candidate(prep.DomainPreparationRequest(source.name), context(tmp_path))


def test_complete_lock_protocol_keeps_existing_rendering(tmp_path):
    candidate = value()
    candidate["actors"] = 2
    candidate["state_variables"].append({"kind": "int", "name": "mutex", "bound": [0, 2], "initial": 0})
    candidate["concurrency"] = {"mode": "lock_protocol", "lock_variable": "mutex",
        "lock_states": ["FREE", "A", "B"], "unlocked_value": 0,
        "actor_lock_values": [1, 2], "linearization_points": {"flip": "effect_commit"}}
    source = tmp_path / "lock.yaml"
    source.write_text(yaml.safe_dump(candidate))
    prepared = prep.prepare_domain_candidate(prep.DomainPreparationRequest(source.name), context(tmp_path))
    assert (prepared.model.tla, prepared.model.cfg) == render_v2_tla(load_candidate(source))
    assert "flipLinearize" in prepared.model.tla


def test_render_expansion_checked_before_allocation_and_actual_bytes_afterwards(tmp_path, monkeypatch):
    source = tmp_path / "candidate.yaml"
    source.write_text(yaml.safe_dump(value()))
    def forbidden(*_):
        pytest.fail("oversized estimated render reached renderer")
    monkeypatch.setattr(prep, "render_v2_tla", forbidden)
    with pytest.raises(ValueError, match="rendering expansion"):
        prep.prepare_domain_candidate(prep.DomainPreparationRequest(source.name),
                                      context(tmp_path, max_generated_bytes=1))
    monkeypatch.setattr(prep, "render_v2_tla", lambda _: ("x" * (2 * 1024**2), "cfg"))
    with pytest.raises(ValueError, match="generated candidate model allowance"):
        prep.prepare_domain_candidate(prep.DomainPreparationRequest(source.name), context(tmp_path))


@pytest.mark.parametrize("name", ["rest_api_resource", "iot_sensor"])
def test_existing_reference_candidates_keep_canonical_identity_and_model(name):
    root = Path("domains/examples/v2").resolve()
    source = root / (name + ".v2.yaml")
    expected = load_candidate(source)
    prepared = prep.prepare_domain_candidate(prep.DomainPreparationRequest(source.name), context(root))
    assert prepared.candidate_sha256 == candidate_sha256(expected)
    assert (prepared.model.tla, prepared.model.cfg) == render_v2_tla(expected)


def test_preparation_does_not_run_traversal_tools_or_publish(tmp_path, monkeypatch):
    source = tmp_path / "candidate.yaml"
    invalid_invariant = value()
    invalid_invariant["tlc_invariants"][0]["expression"]["value"] = False
    source.write_text(yaml.safe_dump(invalid_invariant))
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    def forbidden(*_, **__):
        pytest.fail("preparation attempted an unauthorized later stage")
    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("pipeline.execution.StrictSandboxExecutor.execute", forbidden)
    monkeypatch.setattr("pipeline.llm._post_chat", forbidden)
    monkeypatch.setattr("pipeline.domain_v2_model.validate_transitions_and_invariants", forbidden)
    monkeypatch.setattr("pipeline.mcp_artifacts.publish_new_artifacts", forbidden)
    prepared = prep.prepare_domain_candidate(prep.DomainPreparationRequest(source.name), context(tmp_path))
    assert prepared.summary()["claim"] == "NO_PROOF"
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_relative_paths_use_authorized_workspace_not_process_directory(tmp_path, monkeypatch):
    workspace, elsewhere = tmp_path / "workspace", tmp_path / "elsewhere"
    workspace.mkdir()
    elsewhere.mkdir()
    (workspace / "candidate.yaml").write_text(yaml.safe_dump(value()))
    (elsewhere / "candidate.yaml").write_text("not: the candidate")
    monkeypatch.chdir(elsewhere)
    prepared = prep.prepare_domain_candidate(prep.DomainPreparationRequest("candidate.yaml"), context(workspace))
    assert prepared.model.module_name == "Toggle"


@pytest.mark.parametrize("path", ["", None, 3, "bad\0path"])
def test_request_path_is_typed(path):
    with pytest.raises(ValueError, match="nonempty path"):
        prep.DomainPreparationRequest(path)
