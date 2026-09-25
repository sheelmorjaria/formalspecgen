# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
import argparse

import pytest

import mcp_server
from pipeline import cli
from pipeline.capability_registry import (
    CAPABILITIES,
    _capability,
    add_cli_parser,
    capability,
    mcp_capabilities,
)


def test_registry_names_and_bindings_are_unique():
    names = [item.name for item in CAPABILITIES]
    tools = [item.mcp_tool for item in mcp_capabilities()]
    assert len(names) == len(set(names))
    assert len(tools) == len(set(tools))
    assert all(callable(getattr(mcp_server, name, None)) for name in tools)


def test_human_trust_actions_are_never_mcp_capabilities():
    exposed = {item.name for item in mcp_capabilities()}
    trust_actions = {item.name for item in CAPABILITIES if item.trust_action}
    assert trust_actions == {"promote_domain", "sign_artifact", "manage_trust"}
    assert exposed.isdisjoint(trust_actions)


def test_registry_rejects_unknown_mcp_isolation_profile():
    with pytest.raises(ValueError, match="unknown MCP isolation profile"):
        _capability({
            "name": "unsafe",
            "description": "unsafe",
            "mcp_isolation": "best-effort",
        })


def test_registry_retains_only_the_generic_vfs_milestone():
    assert len(CAPABILITIES) == 47
    assert {item.name for item in CAPABILITIES if item.milestone is not None} == {
        "m55_vfs"
    }


def test_registry_rejects_unknown_and_non_generated_cli_capabilities():
    with pytest.raises(KeyError):
        capability("missing")
    parsers = argparse.ArgumentParser().add_subparsers()
    with pytest.raises(ValueError):
        add_cli_parser(parsers, "doctor")
