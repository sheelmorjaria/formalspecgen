# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Authorized-reviewer key registry for the detached-signature trust gate.

The signature VERIFICATION core (``domain_v2_promotion.sign_artifact`` /
``verify_artifact_signature``) predates this module; what it lacked was a
managed key policy: this registry is the durable, file-backed source of the
authorized key set, merged with the legacy ``AUTHORIZED_REVIEWER_KEYS``
environment variable so existing deployments keep working unchanged.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

DEFAULT_REGISTRY = Path("trusted_keys.json")


def public_key_id(public_key: str | Path, *, runner=None) -> str:
    """Extract the primary key id from an exported public-key file."""
    if runner is None:                  # resolved at call time for patchability
        runner = subprocess.run
    result = runner(["gpg", "--show-keys", "--with-colons", str(public_key)],
                    capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError(f"cannot read public key {public_key}: "
                         f"{(result.stderr or '')[:200]}")
    for line in (result.stdout or "").splitlines():
        if line.startswith("pub:"):
            fields = line.split(":")
            if len(fields) > 4 and fields[4]:
                return fields[4]
    raise ValueError(f"no primary key id found in {public_key}")


def _load(registry: Path) -> dict:
    try:
        value = json.loads(registry.read_text(encoding="utf-8"))
        return value if isinstance(value.get("keys"), list) else {"keys": []}
    except (OSError, ValueError):
        return {"keys": []}


def _save(registry: Path, data: dict) -> None:
    registry.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")


def add_trusted_key(public_key: str | Path,
                    registry: str | Path = DEFAULT_REGISTRY) -> dict:
    """Trust a reviewer's public key; duplicate key ids are idempotent."""
    key_id = public_key_id(public_key)
    path = Path(registry)
    data = _load(path)
    if any(item.get("key_id") == key_id for item in data["keys"]):
        return {"status": "KEY_ALREADY_TRUSTED", "key_id": key_id,
                "registry": str(path)}
    data["keys"].append({"key_id": key_id, "source": Path(public_key).name})
    _save(path, data)
    return {"status": "KEY_TRUSTED", "key_id": key_id, "registry": str(path)}


def remove_trusted_key(key_id: str,
                       registry: str | Path = DEFAULT_REGISTRY) -> dict:
    path = Path(registry)
    data = _load(path)
    remaining = [item for item in data["keys"] if item.get("key_id") != key_id]
    if len(remaining) == len(data["keys"]):
        return {"status": "KEY_NOT_FOUND", "key_id": key_id, "registry": str(path)}
    _save(path, {"keys": remaining})
    return {"status": "KEY_REMOVED", "key_id": key_id, "registry": str(path)}


def list_trusted_keys(registry: str | Path = DEFAULT_REGISTRY) -> list[dict]:
    return _load(Path(registry))["keys"]


def authorized_keys(registry: str | Path = DEFAULT_REGISTRY) -> set[str] | None:
    """The merged authorized key set, or None when no policy is configured.

    ``None`` means the signature must still verify, but ANY key may sign —
    exactly the pre-registry behavior. A non-empty result restricts
    verification to the listed reviewer keys.
    """
    from_env = {item.strip() for item in
                os.getenv("AUTHORIZED_REVIEWER_KEYS", "").split(",")
                if item.strip()}
    from_file = {item["key_id"] for item in list_trusted_keys(registry)
                 if item.get("key_id")}
    merged = from_env | from_file
    return merged or None
