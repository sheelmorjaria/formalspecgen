# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M76 steps 1-2: artifact spine plus bounded compiled refinement validation."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml


def _fail(code: str, message: str = "") -> dict:
    return {"status": "REFINEMENT_SPINE_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _erase_prusti_ghosts(source: str) -> str:
    output = []
    allowed = re.compile(r"^\s*#\[(?:requires|ensures|pure)\b")
    for line in source.splitlines(keepends=True):
        if line.strip() == "use prusti_contracts::*;":
            continue
        if allowed.match(line):
            continue
        output.append(line)
    return "".join(output)


def _rust_expr(expression: dict) -> str:
    kind = expression.get("kind")
    if kind == "field":
        return f"pre_{expression['name']}"
    if kind == "integer":
        return str(expression["value"])
    operators = {"lt": "<", "gt": ">", "add": "+", "sub": "-",
                 "eq": "==", "and": "&&", "or": "||"}
    if kind not in operators:
        raise ValueError(f"M76_EXPRESSION_UNSUPPORTED:{kind}")
    return (f"({_rust_expr(expression['left'])} {operators[kind]} "
            f"{_rust_expr(expression['right'])})")


def _render_bounded_harness(runtime: str, model: dict) -> tuple[str, int, int]:
    variables = model["state_variables"]
    names = [item["name"] for item in variables]
    if names != ["inode_count", "free_list_head", "open_handle_count",
                 "cached_bytes"]:
        raise ValueError("M76_STATE_LAYOUT_UNSUPPORTED")
    operation_blocks = []
    for index, operation in enumerate(model["operations"], start=1):
        guards = " && ".join(_rust_expr(item["expression"])
                             for item in operation["guards"]) or "true"
        expected = {name: f"pre_{name}" for name in names}
        for effect in operation["effects"]:
            expected[effect["target"]] = _rust_expr(effect["value"])
        comparisons = " || ".join(
            [f"result != expected_result"] +
            [f"actual.{name} != if expected_result {{ {value} }} else {{ pre_{name} }}"
             for name, value in expected.items()])
        operation_blocks.append(f"""
        {{
            let mut actual = VfsBounded {{ inode_count: pre_inode_count,
                free_list_head: pre_free_list_head,
                open_handle_count: pre_open_handle_count,
                cached_bytes: pre_cached_bytes, slots: [false; 4] }};
            let expected_result = {guards};
            let result = actual.{operation['name']}();
            if {comparisons} {{ std::process::exit({index}); }}
            transitions += 1;
        }}""")
    harness = runtime + """
fn main() {
    let fresh = VfsBounded::new();
    if fresh.inode_count != 0 || fresh.free_list_head != 4 ||
       fresh.open_handle_count != 0 || fresh.cached_bytes != 0 {
        std::process::exit(90);
    }
    let mut states: u32 = 0;
    let mut transitions: u32 = 0;
    for pre_inode_count in 0_i32..=4 {
      for pre_free_list_head in 0_i32..=4 {
       for pre_open_handle_count in 0_i32..=4 {
        for pre_cached_bytes in 0_i32..=16 {
         if pre_inode_count + pre_free_list_head != 4 ||
            pre_open_handle_count > pre_inode_count { continue; }
         states += 1;
""" + "\n".join(operation_blocks) + """
        }
       }
      }
    }
    println!("states={states} transitions={transitions}");
}
"""
    state_count = sum(1 for inode in range(5) for free in range(5)
                      for opened in range(5) for _cached in range(17)
                      if inode + free == 4 and opened <= inode)
    return harness, state_count, state_count * len(model["operations"])


def verify_refinement_spine(path: str | Path) -> dict:
    artifact_path = Path(path)
    try:
        raw = artifact_path.read_bytes()
        artifact = json.loads(raw)
        model_path = (artifact_path.parent / artifact["model"]).resolve()
        certificate_path = (artifact_path.parent /
                            artifact["refinement_certificate"]).resolve()
        source_path = (artifact_path.parent / artifact["rust_source"]).resolve()
        model_raw = model_path.read_bytes()
        certificate_raw = certificate_path.read_bytes()
        source_raw = source_path.read_bytes()
        model = json.loads(model_raw)
        certificate = yaml.safe_load(certificate_raw)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
        return _fail("REFINEMENT_SPINE_ARTIFACT_INVALID", str(exc))
    bindings = ((model_raw, "model_sha256"),
                (certificate_raw, "refinement_certificate_sha256"),
                (source_raw, "rust_source_sha256"))
    if any(_sha(data) != artifact.get(field) for data, field in bindings):
        return _fail("REFINEMENT_SPINE_HASH_MISMATCH")
    if certificate.get("status") != "VERIFIED" or \
            certificate.get("bindings", {}).get("implementation_sha256") != \
            artifact["rust_source_sha256"]:
        return _fail("SOURCE_MODEL_REFINEMENT_BINDING_MISSING")
    if artifact.get("ghost_erasure") != "prusti_attributes_only" or any(
            artifact.get(field) is not False for field in (
                "semantic_ir_refinement_proved", "verified_compiler_proved",
                "binary_semantics_proved",
                "end_to_end_refinement_chain_established")):
        return _fail("REFINEMENT_SPINE_EPISTEMIC_BOUNDARY_INVALID")
    operations = artifact.get("operations")
    model_operations = {item.get("name") for item in model.get("operations", [])}
    if not isinstance(operations, list) or set(operations) != \
            model_operations | {"new"}:
        return _fail("REFINEMENT_SPINE_OPERATION_SET_MISMATCH")
    source = source_raw.decode("utf-8")
    runtime = _erase_prusti_ghosts(source)
    if "prusti_contracts" in runtime or "#[requires" in runtime or \
            "#[ensures" in runtime or "#[pure" in runtime:
        return _fail("GHOST_ERASURE_INCOMPLETE")
    rustc = shutil.which("rustc")
    if rustc is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "rustc_unavailable", "judge_pending": "rustc"}
    with tempfile.TemporaryDirectory(prefix="m76-spine-") as directory:
        root = Path(directory)
        runtime_path = root / "lib.rs"
        runtime_path.write_text(runtime, encoding="utf-8")
        base = [rustc, "--crate-name", artifact["crate_name"],
                "--crate-type", "lib", "--edition", "2021", "-C", "opt-level=0"]
        try:
            ir_run = subprocess.run(base + ["--emit=llvm-ir", str(runtime_path),
                                            "-o", str(root / "spine.ll")],
                                    capture_output=True, text=True, timeout=60)
            obj_run = subprocess.run(base + ["--emit=obj", str(runtime_path),
                                             "-o", str(root / "spine.o")],
                                     capture_output=True, text=True, timeout=60)
            version = subprocess.run([rustc, "-Vv"], capture_output=True,
                                     text=True, timeout=10)
            harness, state_count, transition_count = _render_bounded_harness(
                runtime, model)
            harness_path = root / "main.rs"
            harness_path.write_text(harness, encoding="utf-8")
            harness_compile = subprocess.run(
                [rustc, "--edition", "2021", "-C", "opt-level=0",
                 str(harness_path), "-o", str(root / "spine-check")],
                capture_output=True, text=True, timeout=60)
            harness_run = subprocess.run([str(root / "spine-check")],
                                         capture_output=True, text=True,
                                         timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return _fail("REFINEMENT_SPINE_COMPILER_FAILED", str(exc))
        if ir_run.returncode or obj_run.returncode or version.returncode or \
                harness_compile.returncode or harness_run.returncode:
            return _fail("REFINEMENT_SPINE_COMPILER_FAILED",
                         ir_run.stderr + obj_run.stderr + version.stderr +
                         harness_compile.stderr + harness_run.stderr)
        ir_raw = (root / "spine.ll").read_bytes()
        object_raw = (root / "spine.o").read_bytes()
    ir_text = ir_raw.decode("utf-8", errors="replace")
    missing = [name for name in operations if name not in ir_text]
    if missing or not object_raw.startswith(b"\x7fELF"):
        return _fail("COMPILER_ARTIFACT_BINDING_MISSING", ", ".join(missing))
    declared = artifact.get("bounded_translation_validation", {})
    expected_output = f"states={state_count} transitions={transition_count}"
    if harness_run.stdout.strip() != expected_output or declared != {
            "valid_state_count": state_count,
            "operation_transition_count": transition_count,
            "constructor_checked": True}:
        return _fail("BOUNDED_TRANSLATION_VALIDATION_MISMATCH",
                     harness_run.stdout.strip())
    return {
        "status": "BOUNDED_COMPILED_REFINEMENT_VALIDATED",
        "claim": "BOUNDED_COMPILED_REFINEMENT_VALIDATED",
        "judge": "rustc+exhaustive_relational_harness",
        "scope": "vfs_promoted_model_to_host_object_artifact_identity",
        "artifact_sha256": _sha(raw), "model_sha256": _sha(model_raw),
        "refinement_certificate_sha256": _sha(certificate_raw),
        "rust_source_sha256": _sha(source_raw),
        "runtime_source_sha256": _sha(runtime.encode()),
        "llvm_ir_sha256": _sha(ir_raw), "object_sha256": _sha(object_raw),
        "compiler_provenance": version.stdout.strip(),
        "operations_observed_in_ir": sorted(operations),
        "valid_states_checked": state_count,
        "operation_transitions_checked": transition_count,
        "constructor_checked": True,
        "harness_sha256": _sha(harness.encode()),
        "semantic_ir_refinement_proved": False,
        "verified_compiler_proved": False, "binary_semantics_proved": False,
        "end_to_end_refinement_chain_established": False,
    }
