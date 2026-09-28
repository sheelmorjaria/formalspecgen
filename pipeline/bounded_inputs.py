# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Shared descriptor-based regular-file capture under an authorized root."""
from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import stat
from .workflow_contracts import WorkflowContext


class BoundedInputError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


@dataclass
class CaptureBudget:
    remaining_bytes: int
    remaining_files: int


def input_path(value: str, context: WorkflowContext) -> tuple[Path, Path]:
    context.require("workspace_read")
    supplied = Path(value).expanduser()
    path = supplied if supplied.is_absolute() else context.workspace_root / supplied
    try:
        relative = path.relative_to(context.workspace_root)
    except ValueError as exc:
        raise BoundedInputError("PATH_OUTSIDE_WORKSPACE", "input must be inside the authorized root") from exc
    if ".." in relative.parts or not relative.parts:
        raise BoundedInputError("PATH_OUTSIDE_WORKSPACE", "unsafe input path")
    if len(relative.parts) > context.resource_budget.get("max_path_depth", 32):
        raise BoundedInputError("INPUT_LIMIT_EXCEEDED", "input path depth exceeded")
    return path, relative


@contextmanager
def input_directory(relative: Path, context: WorkflowContext):
    directory_fd = os.open(context.workspace_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in relative.parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child
        yield directory_fd
    finally:
        os.close(directory_fd)


def capture(name: str, directory_fd: int, context: WorkflowContext, budget: CaptureBudget) -> bytes:
    context.require("workspace_read")
    if budget.remaining_files <= 0:
        raise BoundedInputError("INPUT_LIMIT_EXCEEDED", "aggregate file allowance exceeded")
    budget.remaining_files -= 1
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise BoundedInputError("INVALID_INPUT", "inputs must be regular files")
        content = handle.read(budget.remaining_bytes + 1)
    if len(content) > budget.remaining_bytes:
        raise BoundedInputError("INPUT_LIMIT_EXCEEDED", "aggregate byte allowance exceeded")
    budget.remaining_bytes -= len(content)
    return content
