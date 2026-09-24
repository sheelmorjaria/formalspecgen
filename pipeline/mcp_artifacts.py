# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Bounded MCP reads and no-replace publication under designated roots."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path, PurePosixPath
from typing import Mapping

from .mcp_policy import MCPAdmission, require_mcp_effect


class MCPArtifactError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def read_bounded_text(
        path: Path, admission: MCPAdmission, *, max_bytes: int) -> str:
    """Read one admitted UTF-8 source without accepting an oversized prefix."""
    require_mcp_effect(admission, "workspace_read")
    try:
        with path.open("rb") as handle:
            content = handle.read(max_bytes + 1)
    except OSError as exc:
        raise MCPArtifactError("input_unavailable", str(exc)) from exc
    if len(content) > max_bytes:
        raise MCPArtifactError(
            "INPUT_LIMIT_EXCEEDED",
            f"source exceeds the MCP input limit of {max_bytes} bytes")
    try:
        return content.decode("utf-8")
    except UnicodeError as exc:
        raise MCPArtifactError("input_unavailable", "source is not valid UTF-8") from exc


def publish_new_artifacts(
        output_root: Path, artifacts: Mapping[str, str | bytes],
        admission: MCPAdmission, *, max_total_bytes: int) -> dict[str, dict]:
    """Publish new files with hard-link no-replace semantics.

    Existing artifacts and symlinked path components are rejected. Files are
    staged on the destination filesystem, synchronized, and then linked into
    place so publication cannot replace an existing name.
    """
    require_mcp_effect(admission, "workspace_write_new")
    encoded: dict[PurePosixPath, bytes] = {}
    total = 0
    for name, value in artifacts.items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", f"unsafe output path: {name}")
        content = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        total += len(content)
        encoded[relative] = content
    if total > max_total_bytes:
        raise MCPArtifactError(
            "RESULT_LIMIT_EXCEEDED",
            f"artifacts exceed the MCP result limit of {max_total_bytes} bytes")

    _mkdir_without_symlinks(output_root)
    staging = Path(tempfile.mkdtemp(prefix=".mcp-stage-", dir=output_root))
    staged: dict[PurePosixPath, Path] = {}
    published: dict[str, dict] = {}
    created: list[Path] = []
    try:
        ordered = sorted(encoded.items(), key=lambda item: str(item[0]))
        for index, (relative, content) in enumerate(ordered):
            path = staging / f"{index:04d}.artifact"
            with path.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            staged[relative] = path

        destinations = {}
        for relative in staged:
            destination = output_root.joinpath(*relative.parts)
            _mkdir_without_symlinks(destination.parent, root=output_root)
            _reject_symlink_components(output_root, destination)
            if destination.exists() or destination.is_symlink():
                raise MCPArtifactError(
                    "OUTPUT_ALREADY_EXISTS", f"refusing to replace {relative}")
            destinations[relative] = destination

        for relative, staged_path in staged.items():
            destination = destinations[relative]
            try:
                os.link(staged_path, destination)
            except FileExistsError as exc:
                raise MCPArtifactError(
                    "OUTPUT_ALREADY_EXISTS", f"refusing to replace {relative}") from exc
            created.append(destination)
            _fsync_directory(destination.parent)
            content = encoded[relative]
            published[relative.as_posix()] = {
                "path": str(destination),
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        result = published
        created.clear()
        return result
    finally:
        for path in reversed(created):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        for path in staged.values():
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        try:
            staging.rmdir()
        except OSError:
            pass


def _mkdir_without_symlinks(path: Path, *, root: Path | None = None) -> None:
    path = path.absolute()
    boundary = root.absolute() if root is not None else path
    if root is not None and path != boundary and boundary not in path.parents:
        raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "output escapes designated root")
    chain = []
    current = path
    while not current.exists() and current != current.parent:
        chain.append(current)
        current = current.parent
    if current.is_symlink():
        raise MCPArtifactError("OUTPUT_SYMLINK_REJECTED", f"symlinked output path: {current}")
    for directory in reversed(chain):
        try:
            directory.mkdir()
        except FileExistsError:
            pass
        if directory.is_symlink() or not directory.is_dir():
            raise MCPArtifactError(
                "OUTPUT_SYMLINK_REJECTED", f"unsafe output directory: {directory}")
    if root is not None:
        _reject_symlink_components(boundary, path)


def _reject_symlink_components(root: Path, path: Path) -> None:
    root = root.absolute()
    path = path.absolute()
    if path != root and root not in path.parents:
        raise MCPArtifactError("OUTPUT_SCOPE_VIOLATION", "output escapes designated root")
    current = root
    if current.is_symlink():
        raise MCPArtifactError("OUTPUT_SYMLINK_REJECTED", f"symlinked output root: {root}")
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise MCPArtifactError(
                "OUTPUT_SYMLINK_REJECTED", f"symlinked output path: {current}")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
