# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M22 (Feature 4): trust management — the authorized-key registry and the
sign-artifact / manage-trust commands over the existing GPG signature core."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pipeline import trust


def _gpg_show_keys(key_id: str):
    """A fake `gpg --show-keys --with-colons` runner yielding one pub line."""
    def run(command, **_kwargs):
        assert "--show-keys" in command
        return SimpleNamespace(returncode=0,
                               stdout=f"pub:-:2048:1:{key_id}:\n",
                               stderr="")
    return run


def test_manage_trust_add_key_records_the_key_id(tmp_path):
    """Test 1.1: adding alice.pub extracts her key id into trusted_keys.json."""
    public = tmp_path / "alice.pub"
    public.write_text("---- dummy public key ----", encoding="utf-8")
    registry = tmp_path / "trusted_keys.json"
    with patch.object(trust.subprocess, "run", _gpg_show_keys("ALICEKEY42")):
        result = trust.add_trusted_key(public, registry)
    assert result["status"] == "KEY_TRUSTED"
    assert result["key_id"] == "ALICEKEY42"
    stored = json.loads(registry.read_text(encoding="utf-8"))
    assert stored["keys"] == [{"key_id": "ALICEKEY42", "source": "alice.pub"}]
    # adding the same key twice is idempotent
    with patch.object(trust.subprocess, "run", _gpg_show_keys("ALICEKEY42")):
        trust.add_trusted_key(public, registry)
    stored = json.loads(registry.read_text(encoding="utf-8"))
    assert len(stored["keys"]) == 1


def test_manage_trust_remove_and_list(tmp_path):
    registry = tmp_path / "trusted_keys.json"
    registry.write_text(json.dumps(
        {"keys": [{"key_id": "A", "source": "a.pub"},
                  {"key_id": "B", "source": "b.pub"}]}), encoding="utf-8")
    assert trust.remove_trusted_key("A", registry)["status"] == "KEY_REMOVED"
    assert [item["key_id"] for item in trust.list_trusted_keys(registry)] == ["B"]
    assert trust.remove_trusted_key("MISSING", registry)["status"] == "KEY_NOT_FOUND"


def test_authorized_keys_merge_env_and_registry(tmp_path):
    registry = tmp_path / "trusted_keys.json"
    registry.write_text(json.dumps(
        {"keys": [{"key_id": "FROMFILE", "source": "f.pub"}]}), encoding="utf-8")
    with patch.dict(trust.os.environ, {"AUTHORIZED_REVIEWER_KEYS": "FROMENV, OTHER"}):
        merged = trust.authorized_keys(registry)
    assert merged == {"FROMENV", "OTHER", "FROMFILE"}
    # with neither source configured the policy is not enforced (None)
    with patch.dict(trust.os.environ, {"AUTHORIZED_REVIEWER_KEYS": ""}):
        assert trust.authorized_keys(tmp_path / "absent.json") is None
    # but a configured registry alone still enforces
    assert trust.authorized_keys(registry) == {"FROMFILE"}


def test_sign_artifact_command_creates_detached_signature(tmp_path):
    """Test 2.1: sign-artifact bank.json --key alice writes bank.json.sig."""
    artifact = tmp_path / "bank.json"
    artifact.write_text('{"domain": "bank"}', encoding="utf-8")
    seen = []
    def run(command, **_kwargs):
        seen.append(command)
        # the real gpg writes the detached signature; emulate it
        output = command[command.index("--output") + 1]
        Path(output).write_bytes(b"mock signature")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    from pipeline.cli import command_sign_artifact
    import argparse
    args = argparse.Namespace(artifact=str(artifact), key="alice")
    with patch("pipeline.domain_v2_promotion.subprocess.run", run):
        code = command_sign_artifact(args, _SilentUI())
    assert code == 0
    assert seen[0][:3] == ["gpg", "--batch", "--yes"]
    assert "--local-user" in seen[0] and "alice" in seen[0]
    assert "--detach-sign" in seen[0]
    assert (tmp_path / "bank.json.sig").exists()      # gpg is mocked: create it


class _SilentUI:
    class console:
        @staticmethod
        def print(*_a, **_k): pass


def test_manage_trust_command_adds_and_lists(tmp_path):
    public = tmp_path / "alice.pub"
    public.write_text("key", encoding="utf-8")
    import argparse
    from pipeline.cli import command_manage_trust
    args = argparse.Namespace(add_key=str(public), remove_key=None, list_keys=False,
                               registry=str(tmp_path / "trusted_keys.json"))
    with patch.object(trust.subprocess, "run", _gpg_show_keys("ALICEKEY42")):
        code = command_manage_trust(args, _SilentUI())
    assert code == 0
    listing = trust.list_trusted_keys(tmp_path / "trusted_keys.json")
    assert [item["key_id"] for item in listing] == ["ALICEKEY42"]


def test_signature_gate_reads_the_registry(tmp_path, monkeypatch):
    """Test 3.1 shape: with REQUIRE_SIGNATURES on, the authorized set used by
    the unified-system gate comes from the registry (merged with env)."""
    from pipeline.unified_system_runner import _signature_gate_keys
    registry = tmp_path / "trusted_keys.json"
    registry.write_text(json.dumps(
        {"keys": [{"key_id": "REGKEY", "source": "r.pub"}]}), encoding="utf-8")
    monkeypatch.setenv("FORMALSPECGEN_REQUIRE_SIGNATURES", "1")
    monkeypatch.setenv("AUTHORIZED_REVIEWER_KEYS", "")
    assert _signature_gate_keys(registry) == {"REGKEY"}


def test_public_key_id_fails_closed_on_bad_keys():
    """Unreadable or key-less files refuse with explicit errors."""
    import pytest
    bad = "/nonexistent.pub"
    with pytest.raises(ValueError, match="cannot read public key"):
        trust.public_key_id(bad, runner=lambda *_a, **_k: SimpleNamespace(
            returncode=2, stdout="", stderr="no data"))
    with pytest.raises(ValueError, match="no primary key id"):
        trust.public_key_id("whatever.pub", runner=lambda *_a, **_k: SimpleNamespace(
            returncode=0, stdout="uid:::someone:\n", stderr=""))


def test_cli_trust_and_sign_fail_closed_paths(tmp_path):
    """Signing failures and remove/list flows cover the handler branches."""
    import argparse
    from pipeline.cli import command_sign_artifact, command_manage_trust
    # sign failure: gpg errors become exit 2
    args = argparse.Namespace(artifact=str(tmp_path / "nope.json"), key="k")
    with patch("pipeline.domain_v2_promotion.subprocess.run",
               side_effect=OSError("no gpg")):
        assert command_sign_artifact(args, _SilentUI()) == 2
    # remove an existing key, then list-only invocation
    registry = tmp_path / "t.json"
    trust._save(registry, {"keys": [{"key_id": "X", "source": "x.pub"}]})
    args = argparse.Namespace(add_key=None, remove_key="X", list_keys=False,
                              registry=str(registry))
    assert command_manage_trust(args, _SilentUI()) == 0
    assert trust.list_trusted_keys(registry) == []
    args = argparse.Namespace(add_key=None, remove_key=None, list_keys=True,
                              registry=str(registry))
    assert command_manage_trust(args, _SilentUI()) == 0
    # unreadable key file fails closed
    args = argparse.Namespace(add_key="/nonexistent.pub", remove_key=None,
                              list_keys=False, registry=str(registry))
    assert command_manage_trust(args, _SilentUI()) == 2
