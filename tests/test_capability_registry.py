# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import inspect
import argparse

import pytest

import mcp_server
from pipeline import cli
from pipeline.capability_registry import (CAPABILITIES, add_cli_parser, capability,
                                          mcp_capabilities)


def test_registry_names_and_bindings_are_unique():
    names = [item.name for item in CAPABILITIES]
    tools = [item.mcp_tool for item in mcp_capabilities()]
    assert len(names) == len(set(names))
    assert len(tools) == len(set(tools))
    assert all(callable(getattr(mcp_server, name, None)) for name in tools)


def test_verify_kernel_schema_drives_cli_and_matches_mcp():
    spec = capability("verify_kernel")
    parser = cli.build_parser()
    args = parser.parse_args([
        spec.cli_command, "kernel", "--profile", "arm.json",
        "--manifest", "monolith.json"])
    assert args.kernel_dir == "kernel"
    assert args.profile == ["arm.json"]
    assert args.manifest == "monolith.json"
    parameters = inspect.signature(mcp_server.verify_kernel).parameters
    assert {"kernel_dir", "profile", "manifest"} <= set(parameters)


def test_human_trust_actions_are_never_mcp_capabilities():
    exposed = {item.name for item in mcp_capabilities()}
    trust_actions = {item.name for item in CAPABILITIES if item.trust_action}
    assert trust_actions == {"promote_domain", "sign_artifact", "manage_trust"}
    assert exposed.isdisjoint(trust_actions)


def test_registry_rejects_unknown_and_non_generated_cli_capabilities():
    with pytest.raises(KeyError):
        capability("missing")
    parsers = argparse.ArgumentParser().add_subparsers()
    with pytest.raises(ValueError):
        add_cli_parser(parsers, "doctor")
