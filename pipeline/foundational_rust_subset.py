"""M76.3 foundational-semantics package gate.

This module validates and, when available, checks the Rocq model obligations.
It deliberately cannot mint Rust/model functional refinement until a trusted
Rust-subset translation and correspondence proof is supplied.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fail(code: str, message: str = "") -> dict:
    return {"status": "FOUNDATIONAL_RUST_SUBSET_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def verify_foundational_rust_subset(path: str | Path) -> dict:
    path = Path(path)
    try:
        raw = path.read_bytes()
        artifact = json.loads(raw)
        source_path = (path.parent / artifact["rust_source"]).resolve()
        model_path = (path.parent / artifact["v2_model"]).resolve()
        proof_path = (path.parent / artifact["rocq_obligations"]).resolve()
        source_raw = source_path.read_bytes()
        model_raw = model_path.read_bytes()
        proof_raw = proof_path.read_bytes()
        source = source_raw.decode("utf-8")
        proof = proof_raw.decode("utf-8")
    except (OSError, ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        return _fail("M76_3_ARTIFACT_INVALID", str(exc))
    bindings = ((source_raw, "rust_source_sha256"),
                (model_raw, "v2_model_sha256"),
                (proof_raw, "rocq_obligations_sha256"))
    if any(_sha(data) != artifact.get(field) for data, field in bindings):
        return _fail("M76_3_HASH_BINDING_MISMATCH")
    expected_subset = {
        "integer_type": "i32_bounded",
        "booleans": True,
        "fixed_arrays": True,
        "mutable_struct_methods": True,
        "conditionals": True,
        "checked_index_cast": "i32_to_usize_under_invariant",
        "heap_allocation": False,
        "loops": False,
        "recursion": False,
        "unsafe_rust": False,
        "concurrency": False,
        "panics": False,
    }
    if artifact.get("accepted_subset") != expected_subset:
        return _fail("M76_3_SUBSET_DECLARATION_INVALID")
    forbidden_source = ("unsafe {", "unsafe fn", "Vec<", "Box<", "loop {",
                        "while ", "panic!", "unwrap(", "expect(")
    present = [token for token in forbidden_source if token in source]
    if present:
        return _fail("M76_3_SOURCE_OUTSIDE_ACCEPTED_SUBSET", ",".join(present))
    required_symbols = set(artifact.get("operations", ()))
    observed = {name for name in required_symbols
                if re.search(rf"\bfn\s+{re.escape(name)}\s*\(", source)}
    if observed != required_symbols:
        return _fail("M76_3_OPERATION_BINDING_MISSING",
                     ",".join(sorted(required_symbols - observed)))
    if re.search(r"\b(?:Admitted|admit|Axiom|Parameter)\b", proof):
        return _fail("M76_3_UNCHECKED_PROOF_ESCAPE")
    required_theorems = {
        "initial_preserves", "open_preserves", "close_preserves",
        "read_preserves", "write_preserves", "failure_stutter_preserves",
    }
    if not all(re.search(rf"\bTheorem\s+{name}\b", proof)
               for name in required_theorems):
        return _fail("M76_3_PROOF_OBLIGATION_MISSING")
    ceilings = ("rust_model_functional_refinement_proved",
                "rust_to_rocq_translation_proved", "unsafe_rust_semantics_proved",
                "compiler_refinement_chain_proved",
                "end_to_end_refinement_chain_established")
    if any(artifact.get(field) is not False for field in ceilings):
        return _fail("M76_3_EPISTEMIC_BOUNDARY_INVALID")
    coqc = shutil.which("coqc")
    evidence = {
        "artifact_sha256": _sha(raw), "rust_source_sha256": _sha(source_raw),
        "v2_model_sha256": _sha(model_raw), "rocq_obligations_sha256": _sha(proof_raw),
        "operations_bound": sorted(observed), "proof_obligations": sorted(required_theorems),
        **{field: False for field in ceilings},
    }
    if coqc is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "rocq_unavailable", "judge_pending": "Rocq", **evidence}
    try:
        with tempfile.TemporaryDirectory(prefix="formalspecgen-m76-3-") as directory:
            proof_copy = Path(directory) / "VfsSubset.v"
            proof_copy.write_bytes(proof_raw)
            run = subprocess.run([coqc, "-q", proof_copy.name], cwd=directory,
                                 capture_output=True, text=True, timeout=60)
            version = subprocess.run([coqc, "--version"], capture_output=True,
                                     text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _fail("M76_3_ROCQ_EXECUTION_FAILED", str(exc))
    if run.returncode or version.returncode:
        return _fail("M76_3_ROCQ_OBLIGATIONS_FAILED", run.stderr + version.stderr)
    return {
        "status": "FOUNDATIONAL_RUST_SUBSET_SEMANTICS_CHECKED",
        "claim": "NO_PROOF",
        "judge": "Rocq",
        "scope": "abstract_vfs_state_transition_obligations_only",
        "judge_pending": "RefinedRust_source_to_logic_translation",
        "rocq_version": version.stdout.strip(),
        **evidence,
    }
