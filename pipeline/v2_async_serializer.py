# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Deterministic Tokio transport façade with explicitly downgraded evidence."""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
from pathlib import Path

from .domain_v2_promotion import ReviewedDomainSpecV2


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def render_tokio_scaffold(reviewed: ReviewedDomainSpecV2) -> str:
    if reviewed.execution_model != "async_message_passing":
        raise ValueError("Tokio lowering requires async_message_passing metadata")
    variants = [operation.name for operation in reviewed.operations]
    lines = [
        "use std::num::NonZeroUsize;",
        "use tokio::sync::mpsc;", "",
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]", "pub enum Message {",
        *[f"    {variant}," for variant in variants], "}", "",
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]", "pub enum AsyncSendError {",
        "    ChannelClosed,", "}", "",
        f"pub struct {reviewed.domain_name}AsyncHandle {{",
        "    sender: mpsc::Sender<Message>,", "}", "",
        f"impl {reviewed.domain_name}AsyncHandle {{",
        "    /// Creates a bounded Tokio channel without permitting zero capacity.",
        "    pub fn channel(capacity: NonZeroUsize) -> (Self, mpsc::Receiver<Message>) {",
        "        let (sender, receiver) = mpsc::channel(capacity.get());",
        "        (Self { sender }, receiver)", "    }",
    ]
    for operation in reviewed.operations:
        lines.extend(["", f"    /// Enqueues reviewed message `{operation.name}`.",
            f"    pub async fn send_{_snake(operation.name)}(&self) "
            "-> Result<(), AsyncSendError> {",
            f"        self.sender.send(Message::{operation.name}).await",
            "            .map_err(|_| AsyncSendError::ChannelClosed)", "    }"])
    lines.extend(["}", ""])
    return "\n".join(lines)


def check_tokio_scaffold(code: str, timeout: int = 60) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); (root / "src").mkdir()
        (root / "Cargo.toml").write_text(
            '[package]\nname="formalspecgen-ci-rust-deps"\nversion="0.0.0"\n'
            'edition="2021"\n\n[dependencies]\nrayon="=1.11.0"\n'
            'tokio={version="=1.49.0",features=["sync"]}\n',
            encoding="utf-8")
        lockfile = Path(__file__).resolve().parents[1] / "ci" / "rust-deps" / "Cargo.lock"
        if lockfile.is_file():
            (root / "Cargo.lock").write_text(lockfile.read_text(encoding="utf-8"), encoding="utf-8")
        (root / "src" / "lib.rs").write_text(code, encoding="utf-8")
        environment = dict(os.environ); environment["RUSTFLAGS"] = "-D warnings"
        offline = os.environ.get("FORMALSPECGEN_CARGO_OFFLINE", "1") != "0"
        command = ["cargo", "check", "--locked", "--quiet"]
        if offline:
            command.insert(3, "--offline")
        try:
            process = subprocess.run(command, cwd=root,
                capture_output=True, text=True, timeout=timeout, env=environment)
        except FileNotFoundError:
            return {"status": "TOOL_MISSING", "exit_code": 127}
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "exit_code": 124}
    output = ((process.stdout or "") + (process.stderr or "")).strip()
    return {"status": "TOKIO_CHECKED" if process.returncode == 0 else "TOKIO_CHECK_FAILED",
            "exit_code": process.returncode, "output": output[-8000:],
            "dependency": "tokio=1.49.0", "offline": offline}


def async_static_gate(reviewed: ReviewedDomainSpecV2, code: str, *, native_checked: bool) -> dict:
    if reviewed.execution_model != "async_message_passing":
        return _fail("missing_async_execution_model")
    if not native_checked:
        return _fail("native_not_checked")
    if code != render_tokio_scaffold(reviewed):
        return _fail("noncanonical_async_surface")
    return {"status": "VERIFIED", "claim": "STATIC_CHECK",
            "claims": ["BOUNDED_ARCHITECTURE_EVIDENCE", "STATIC_CHECK"],
            "scope": "bounded_atomic_handler_model_plus_tokio_transport_static_check",
            "source_refinement_proved": False, "async_linearizability_proved": False,
            "distributed_delivery_proved": False,
            "source_sha256": hashlib.sha256(code.encode()).hexdigest()}


def _fail(code: str) -> dict:
    return {"status": "FAIL", "claim": "NO_PROOF", "code": code,
            "source_refinement_proved": False, "async_linearizability_proved": False,
            "distributed_delivery_proved": False}
