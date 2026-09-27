#!/usr/bin/env python3
# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Provision disposable reviewer/signer identities for mandatory CI acceptance."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


def _run(*command: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, text=True, **kwargs)


def _identity(home: Path, label: str, email: str) -> str:
    home.mkdir(mode=0o700)
    _run(
        "gpg", "--homedir", str(home), "--batch", "--passphrase", "",
        "--quick-generate-key", f"{label} <{email}>", "ed25519", "sign", "1d")
    listing = _run(
        "gpg", "--homedir", str(home), "--batch", "--with-colons",
        "--list-secret-keys", stdout=subprocess.PIPE).stdout
    return next(
        line.split(":")[9] for line in listing.splitlines()
        if line.startswith("fpr:"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--github-env", type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    reviewer_home = root / "reviewer-secret"
    signer_home = root / "signer-secret"
    public_home = root / "public-keys"
    public_home.mkdir(mode=0o700)
    approval_root = root / "approval-state"
    approval_root.mkdir(mode=0o700)
    reviewer = _identity(
        reviewer_home, "FormalSpecGen CI Reviewer", "reviewer@example.invalid")
    signer = _identity(
        signer_home, "FormalSpecGen CI Signer", "signer@example.invalid")
    for home, identity in ((reviewer_home, reviewer), (signer_home, signer)):
        exported = _run(
            "gpg", "--homedir", str(home), "--batch", "--armor", "--export",
            identity, stdout=subprocess.PIPE).stdout
        _run(
            "gpg", "--homedir", str(public_home), "--batch", "--import",
            input=exported)
    registry = root / "trusted-reviewers.json"
    registry.write_text(json.dumps({
        "keys": [{"key_id": reviewer, "source": "ci-reviewer"}],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    registry.chmod(0o600)
    signer_program = root / "protected-signer"
    signer_program.write_text(
        "#!/bin/sh\n"
        f"export FORMALSPECGEN_SIGNER_GNUPGHOME={shlex.quote(str(signer_home))}\n"
        f"export FORMALSPECGEN_APPROVAL_GNUPGHOME={shlex.quote(str(public_home))}\n"
        f"export FORMALSPECGEN_APPROVAL_TRUST_REGISTRY={shlex.quote(str(registry))}\n"
        f"export FORMALSPECGEN_SIGNING_KEY={shlex.quote(signer)}\n"
        f"exec {shlex.quote(sys.executable)} -m pipeline.protected_signer \"$@\"\n",
        encoding="utf-8")
    signer_program.chmod(0o700)
    values = {
        "FORMALSPECGEN_APPROVAL_ROOT": approval_root,
        "FORMALSPECGEN_APPROVAL_GNUPGHOME": public_home,
        "FORMALSPECGEN_APPROVAL_TRUST_REGISTRY": registry,
        "FORMALSPECGEN_APPROVAL_SIGNER": signer_program,
        "FORMALSPECGEN_SIGNING_IDENTITY": signer,
        "FORMALSPECGEN_REVIEWER_IDENTITY": reviewer,
        "FORMALSPECGEN_ACCEPTANCE_REVIEWER_GNUPGHOME": reviewer_home,
        "FORMALSPECGEN_ACCEPTANCE_REVIEWER_KEY": reviewer,
    }
    destination = args.github_env or (
        Path(os.environ["GITHUB_ENV"]) if os.environ.get("GITHUB_ENV") else None)
    if destination is not None:
        with destination.open("a", encoding="utf-8") as handle:
            for name, value in values.items():
                handle.write(f"{name}={value}\n")
    print(json.dumps({
        "status": "PROVISIONED", "root": str(root),
        "reviewer": reviewer, "signer": signer,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
