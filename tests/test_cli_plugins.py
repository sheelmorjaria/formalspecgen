import argparse
from pathlib import Path

import pytest

from pipeline.cli import (
    ArgumentDeclaration,
    CLI_COMMAND_PLUGIN_ABI,
    CommandDeclaration,
    CommandPlugin,
    SessionStore,
    TerminalUI,
    build_parser,
    dispatch,
)


def _handler(args: argparse.Namespace) -> int:
    return 0 if args.project_root == "." else 1


def _plugin(**overrides) -> CommandPlugin:
    declaration = CommandDeclaration(
        capability_name="external_check",
        command_name="external-check",
        handler_id="external.commands:check",
        handler=_handler,
        arguments=(ArgumentDeclaration(("--project-root",), {"default": "."}),),
        **overrides,
    )
    return CommandPlugin(
        abi_id=CLI_COMMAND_PLUGIN_ABI,
        plugin_id="external.commands.v1",
        declarations=(declaration,),
    )


def test_external_command_plugin_registers_without_product_dependency():
    parser = build_parser((_plugin(),))
    args = parser.parse_args(["external-check"])
    assert args.project_root == "."
    assert dispatch(
        args, TerminalUI(), SessionStore(Path(".")), {}) == 0
    assert args._plugin_handler_id == "external.commands:check"
    assert args._plugin_id == "external.commands.v1"


def test_plugin_abi_and_command_collisions_fail_closed():
    bad_abi = CommandPlugin(
        abi_id="unsupported.v1",
        plugin_id="external.commands.v1",
        declarations=_plugin().declarations,
    )
    with pytest.raises(ValueError, match="unsupported command plugin ABI"):
        build_parser((bad_abi,))

    duplicate = CommandPlugin(
        abi_id=CLI_COMMAND_PLUGIN_ABI,
        plugin_id="external.commands.v1",
        declarations=(
            CommandDeclaration(
                capability_name="doctor_override",
                command_name="doctor",
                handler_id="external.commands:doctor",
                handler=_handler,
            ),
        ),
    )
    with pytest.raises(ValueError, match="duplicate CLI command"):
        build_parser((duplicate,))


def test_human_only_plugin_command_cannot_be_mcp_exposed():
    with pytest.raises(ValueError, match="cannot be MCP-exposed"):
        build_parser((_plugin(human_only=True, mcp_exposed=True),))
