# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M53: the Kani refinement lane — proving the IMAGE's Rust refines
the witnesses' invariants.

The boot image's verified core (Ring, Mpsc) lives in
boot/src/witness.rs; the Kani proof crate includes THAT FILE BY PATH
(proofs/src/lib.rs: #[path = "../../src/witness.rs"]), so the harnesses
prove the identical code the aarch64 image runs — not a copy. Kani
then verifies, over bounded nondeterministic operation sequences, the
SAME invariants ESBMC proved for the C witnesses:

- SPSC (M36): head - tail <= CAP and tail <= head, always;
- backpressure: posted + dropped == attempts (no silent loss);
- MPSC (M50): per-lane <= LANE_CAP, total <= CAP, and the ledger
  identities (posted == sum of lane heads, consumed == sum of tails).

Honest scope: bounded proofs within the unwind bound — the same
epistemic class as the ESBMC lanes. Kani models volatile ops as plain
memory accesses in a single-threaded harness; the CONCURRENT
interleaving claims remain ESBMC's. The MMU/syscall/exception glue of
the image stays unproved — this lane closes the TRANSLATION gap for
the two concurrency-critical data structures, nothing more.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

_KANI = shutil.which("kani") or shutil.which("cargo-kani")
KANI_AVAILABLE = _KANI is not None or (
    Path.home() / ".cargo/bin/kani").exists()

_PROOF = re.compile(r"#\[kani::proof\]")
_WITNESS_LINK = '#[path = "../../src/witness.rs"]'
_SUCCESS = re.compile(
    r"(\d+) successfully verified harnesses, (\d+) failures?, "
    r"(\d+) total")
_FAILED_HARNESS = re.compile(r"Verification failed for - (\S+)")


def _fail(code: str, message: str, **extra) -> dict:
    return {"status": "RUST_REFINEMENT_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message, **extra}


def verify_rust_refinement(proofs_dir: str | Path) -> dict:
    """Run cargo kani over the proof crate that includes the image's
    witness.rs BY PATH — every harness must verify."""
    proofs = Path(proofs_dir)
    if not proofs.is_dir():
        return _fail("proofs_dir_missing", str(proofs))
    harness_file = proofs / "src" / "lib.rs"
    if not (proofs / "Cargo.toml").is_file() \
            or not harness_file.is_file():
        return _fail("proof_crate_missing",
                     "expected Cargo.toml and src/lib.rs — the proof "
                     "crate IS the lane's subject")
    text = harness_file.read_text(encoding="utf-8")
    if _WITNESS_LINK not in text:
        return _fail(
            "WITNESS_LINK_MISSING",
            "the harness does not #[path]-include ../../src/witness.rs "
            "— a proof over a COPY is a proof of nothing: the lane "
            "refuses any harness not bound to the image's own code")
    harnesses = [m.start() for m in _PROOF.finditer(text)]
    if not harnesses:
        return _fail("harnesses_missing",
                     "no #[kani::proof] functions — an empty proof "
                     "crate proves nothing (vacuous), the gate refuses")
    # only now the availability gate (the c846ef5 ordering discipline)
    if not KANI_AVAILABLE:
        return _fail("kani_unavailable",
                     "kani binary not found (cargo install --locked "
                     "kani-verifier)")
    try:
        run = subprocess.run(
            ["cargo", "kani"], cwd=str(proofs),
            capture_output=True, text=True, timeout=600)
    except (subprocess.TimeoutExpired, TimeoutError):
        return _fail("kani_timeout",
                     "cargo kani did not finish within 600s")
    except OSError as exc:
        return _fail("kani_crashed", str(exc))
    output = (run.stdout or "") + (run.stderr or "")
    if run.returncode != 0 and "successfully verified" not in output:
        return _fail("build_failed", output[-400:])
    failed = _FAILED_HARNESS.findall(output)
    if failed:
        return _fail(
            "HARNESS_FAILED",
            f"harness(es) {failed} failed verification — the Rust "
            "witness code VIOLATES an invariant the C witness proved; "
            "the refinement is contradicted", harnesses_failed=failed,
            output_tail=output[-400:])
    success = _SUCCESS.search(output)
    if not success or success.group(2) != "0":
        return _fail("kani_verification_failed", output[-400:])
    verified = int(success.group(1))
    if verified < len(harnesses):
        return _fail("kani_verification_failed",
                     f"{len(harnesses)} proof functions but only "
                     f"{verified} harnesses verified — a harness was "
                     "silently dropped", output_tail=output[-400:])
    return {
        "status": "RUST_WITNESS_REFINEMENT_PROVED",
        "claim": "RUST_WITNESS_REFINEMENT_PROVED",
        "judge": "kani",
        "scope": "bounded_nondet_operation_sequences",
        "harnesses_verified": verified,
        "witness_source": "boot/src/witness.rs (path-included, not a copy)",
        "memory_model": "single_threaded_volatile_as_plain",
        "note": "Kani proved the image's own Ring/Mpsc satisfy the "
                "witness invariants (capacity bounds, backpressure "
                "accounting, ledger identities) over bounded "
                "nondeterministic operation sequences; concurrent "
                "interleaving remains ESBMC's claim, and the image's "
                "MMU/syscall glue remains unproved",
    }
