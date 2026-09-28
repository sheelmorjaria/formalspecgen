# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""CLI presentation only: machine stdout is not a new verification claim."""
from __future__ import annotations

from contextlib import contextmanager, redirect_stdout
from contextvars import ContextVar
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable

from .mcp_artifacts import MCPArtifactError, publish_new_artifacts
from .workflow_contracts import WorkflowContext


CLI_RESULT_SCHEMA = "formalspecgen-cli-result-v1"
MAX_JSON_EXPORT_BYTES = 8 * 1024 * 1024


class CLIOutputError(RuntimeError):
    """A requested result could not be rendered or published."""


@dataclass
class _MachineResult:
    payload: Any = None
    recorded: bool = False


_machine_result: ContextVar[_MachineResult | None] = ContextVar("cli_result", default=None)


def result_export_path(destination: str | None) -> str | None:
    """The stdout marker is a presentation option, never a workflow path."""
    return None if destination == "-" else destination


def write_json(value: Any, destination: str | None, console) -> None:
    state = _machine_result.get()
    if state is not None and destination in {None, "-"}:
        if state.recorded:
            raise CLIOutputError("command produced more than one machine result")
        state.payload, state.recorded = value, True
        return
    try:
        text = json.dumps(value, indent=2, ensure_ascii=False, default=str, allow_nan=False) + "\n"
        if destination == "-":
            sys.stdout.write(text)
        elif destination:
            # Keep lexical components for the no-symlink/no-replace publisher.
            path = Path(destination).expanduser().absolute()
            context = WorkflowContext.for_cli(("workspace_write_new",), workspace_root=path.parent)
            publish_new_artifacts(
                path.parent, {path.name: text}, context.authority,
                max_total_bytes=MAX_JSON_EXPORT_BYTES)
            console.print(f"Evidence written to {path}", markup=False)
        else:
            console.print(text.rstrip("\n"), markup=False, highlight=False, soft_wrap=True)
    except (OSError, ValueError, TypeError, RecursionError, MCPArtifactError) as exc:
        raise CLIOutputError(f"Result publication failed: {exc}") from exc


@contextmanager
def _diagnostics_to_stderr():
    """Also redirect inherited subprocess stdout, not just Python print().

    Used only for synchronous CLI dispatch, never by MCP application services.
    """
    sys.stdout.flush()
    saved_fd = os.dup(1)
    try:
        os.dup2(2, 1)
        with redirect_stdout(sys.stderr):
            yield
    finally:
        sys.stderr.flush()
        os.dup2(saved_fd, 1)
        os.close(saved_fd)


def run_machine_command(command: str, invoke: Callable[[], int]) -> int:
    """Emit one versioned response; preserve the underlying result unchanged."""
    stdout = sys.stdout
    state = _MachineResult()
    token = _machine_result.set(state)
    error = None
    try:
        with _diagnostics_to_stderr():
            try:
                code = invoke()
            except (CLIOutputError, OSError, ValueError, RuntimeError) as exc:
                code = 1
                error = {"code": "CLI_OPERATION_FAILED", "message": str(exc)}
        if not state.recorded:
            code = code or 1
            error = error or {"code": "CLI_RESULT_UNAVAILABLE",
                              "message": "Command ended without a structured result; see stderr."}
        elif code == 0 and isinstance(state.payload, dict) and \
                state.payload.get("request_satisfied") is False:
            code = 1
            error = {"code": "CLI_RESULT_CONTRADICTION",
                     "message": "The command returned zero but its result says the request was not satisfied."}
        envelope = {
            "schema": CLI_RESULT_SCHEMA, "command": command,
            "exit_code": code, "operation_satisfied": code == 0,
            "result": state.payload, "error": error,
        }
        try:
            encoded = json.dumps(envelope, ensure_ascii=False, default=str, allow_nan=False)
        except (ValueError, TypeError, RecursionError) as exc:
            code = 1
            encoded = json.dumps({
                "schema": CLI_RESULT_SCHEMA, "command": command,
                "exit_code": code, "operation_satisfied": False, "result": None,
                "error": {"code": "CLI_RESULT_INVALID", "message": str(exc)},
            })
        stdout.write(encoded + "\n")
        stdout.flush()
        return code
    finally:
        _machine_result.reset(token)
