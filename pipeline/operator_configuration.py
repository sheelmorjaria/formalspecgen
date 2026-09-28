# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Configuration supplied by the operator, never by a workflow request."""
import os
from pathlib import Path


def operator_controlled_path(variable: str, *, require_file: bool = False) -> Path:
    raw = os.environ.get(variable)
    if not raw:
        raise ValueError(f"{variable} is not configured")
    supplied = Path(raw).expanduser()
    if not supplied.is_absolute():
        raise ValueError(f"{variable} must be an absolute operator-controlled path")
    if supplied.is_symlink():
        raise ValueError(f"{variable} must not be a symlink")
    path = supplied.resolve()
    workspace = Path.cwd().resolve()
    if path == workspace or workspace in path.parents:
        raise ValueError(f"{variable} must be outside the agent workspace")
    if require_file:
        if not path.is_file():
            raise ValueError(f"{variable} must identify a regular file")
        if path.stat().st_mode & 0o022:
            raise ValueError(f"{variable} must not be group- or world-writable")
    elif path.exists() and (not path.is_dir() or path.stat().st_mode & 0o022):
        raise ValueError(f"{variable} must be a protected directory when it already exists")
    return path
