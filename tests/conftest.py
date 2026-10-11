# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Explicit synthetic runtime fixture for identity contract tests only."""
import pytest


@pytest.fixture
def domain_identity_java(tmp_path, monkeypatch):
    root = tmp_path / "fixture-jdk"
    for name in ("bin/java", "release", "lib/modules", "lib/server/libjvm.so"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(("synthetic fixture; no execution: " + name).encode())
    binary = root / "bin/java"; binary.chmod(0o700)
    monkeypatch.setattr("pipeline.config.JAVA_BIN", str(binary))
    return binary
