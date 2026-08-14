# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Hash-bound human promotion for validated V2 domain candidates.

Promotion establishes deterministic integrity and explicit human acceptance of an exact
candidate.  It does not authenticate the reviewer or provide non-repudiation.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import Field

from .domain_v2 import DomainSpecV2
from .domain_v2_evidence import canonical_sha256
from .domain_v2_publication import EvidenceEnvelope, write_json_atomic


class ReviewedDomainSpecV2(DomainSpecV2):
    review_status: Literal["reviewed"] = "reviewed"
    accepted_candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    accepted_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def candidate_sha256(candidate: DomainSpecV2) -> str:
    """Hash the semantic candidate, independent of YAML formatting and key order."""
    return canonical_sha256(candidate.model_dump(mode="json"))


def load_candidate(path: str | Path) -> DomainSpecV2:
    candidate_path = Path(path)
    text = candidate_path.read_text(encoding="utf-8")
    if candidate_path.suffix.lower() == ".json":
        value = json.loads(text)
    else:
        import yaml
        value = yaml.safe_load(text)
    return DomainSpecV2.model_validate(value)


def load_validation_envelope(path: str | Path) -> EvidenceEnvelope:
    return EvidenceEnvelope.model_validate_json(Path(path).read_text(encoding="utf-8"))


def sign_artifact(path: str | Path, signing_key: str, *, suffix: str = ".sig") -> Path:
    """Create a detached GPG signature for an emitted evidence artifact."""
    artifact = Path(path)
    signature = Path(str(artifact) + suffix)
    try:
        subprocess.run(["gpg", "--batch", "--yes", "--local-user", signing_key,
                        "--detach-sign", "--output", str(signature), str(artifact)],
                       check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        signature.unlink(missing_ok=True)
        raise ValueError("CRITICAL: artifact signature generation failed") from exc
    return signature


def verify_artifact_signature(path: str | Path, signature: str | Path,
                              authorized_keys: set[str] | None = None) -> dict:
    """Verify a detached signature and optionally enforce an authorized key set."""
    artifact, sig = Path(path), Path(signature)
    if not artifact.exists() or not sig.exists():
        return {"status": "SIGNATURE_MISSING", "claim": "NO_PROOF"}
    result = subprocess.run(["gpg", "--status-fd", "1", "--verify", str(sig), str(artifact)],
                            capture_output=True, text=True)
    if result.returncode != 0:
        return {"status": "SIGNATURE_INVALID", "claim": "NO_PROOF",
                "output": result.stderr[-2000:]}
    goodsig = next((line for line in result.stdout.splitlines() if line.startswith("[GNUPG:] GOODSIG ")), "")
    key_id = goodsig.split(maxsplit=2)[2].split(maxsplit=1)[0] if goodsig else ""
    if authorized_keys is not None and key_id not in authorized_keys:
        return {"status": "UNAUTHORIZED_REVIEWER", "claim": "NO_PROOF", "key_id": key_id}
    return {"status": "SIGNATURE_VERIFIED", "claim": "CRYPTOGRAPHIC_SIGNATURE_VERIFIED",
            "key_id": key_id}


def promote_validated_candidate(
    candidate_path: str | Path,
    validation_path: str | Path,
    destination: str | Path,
    *,
    accept_candidate_sha256: str,
    signing_key: str | None = None,
) -> ReviewedDomainSpecV2:
    """Promote only the exact candidate bound to intact VALIDATED evidence."""
    candidate = load_candidate(candidate_path)
    if candidate.review_status != "unreviewed":
        raise ValueError("only an unreviewed V2 candidate may be promoted")

    actual_hash = candidate_sha256(candidate)
    if accept_candidate_sha256 != actual_hash:
        raise ValueError("CRITICAL: candidate hash mismatch")

    envelope = load_validation_envelope(validation_path)
    if envelope.evidence.candidate_sha256 != actual_hash:
        raise ValueError("validation evidence does not bind the current candidate")

    reviewed = ReviewedDomainSpecV2.model_validate({
        **candidate.model_dump(mode="json"),
        "review_status": "reviewed",
        "accepted_candidate_sha256": actual_hash,
        "accepted_evidence_sha256": envelope.evidence_sha256,
    })
    write_json_atomic(destination, reviewed.model_dump(mode="json"))
    if signing_key:
        sign_artifact(destination, signing_key, suffix=".promotion.sig")
    return reviewed


def promote_domain(name: str, *, accept_candidate_sha256: str,
                   project_root: str | Path = ".",
                   replace_reviewed: bool = False,
                   signing_key: str | None = None) -> ReviewedDomainSpecV2:
    """Promote a named CLI-layout V2 candidate into the separate V2 registry."""
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", name):
        raise ValueError("V2 domain name must be a safe module identifier")
    root = Path(project_root).resolve()
    destination = root / "domains" / "v2" / f"{name}.json"
    if destination.exists() and not replace_reviewed:
        raise FileExistsError(f"reviewed V2 domain {name!r} already exists")
    return promote_validated_candidate(
        root / "domains" / "candidates" / f"{name}.v2.yaml",
        root / "domains" / "candidates" / f"{name}.v2.validation.json",
        destination,
        accept_candidate_sha256=accept_candidate_sha256,
        signing_key=signing_key,
    )
