"""Deterministic canonical-domain drafting shared by the CLI and the MCP façade.

Each function lowers a reviewed V2 domain (or a reviewed V1 plugin domain for
Java) into a contract file plus a ``.canonical.json`` evidence sibling, and
returns ``{"evidence": ..., "code_file": ..., "evidence_file": ...}``. All
failure paths raise ``ValueError`` so callers (CLI exit code, MCP fail-closed
verdict) keep their own error discipline.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

_SAFE_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]*")


def _requested(domain: str) -> str:
    requested = domain.strip().lower()
    if not _SAFE_IDENTIFIER.fullmatch(requested):
        raise ValueError("canonical domain must be a safe module identifier")
    return requested


def _write_evidence(destination: Path, evidence: dict[str, Any]) -> Path:
    evidence_path = destination.with_suffix(destination.suffix + ".canonical.json")
    evidence_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8")
    return evidence_path


def canonical_draft_java(domain: str, requirement: str, *, domains_root: Path,
                         out_file: str | Path | None = None) -> dict[str, Any]:
    """Lower a reviewed domain into a Java/JML contract deterministically."""
    from .canonical_contracts import canonical_contract
    from .validate import check_stub
    from .v2_jml_serializer import render_reviewed_v2_file
    from .jml_io import class_name as java_class_name

    requested = _requested(domain)
    reviewed_path = domains_root / f"{requested}.json"
    reviewed_v2 = None
    if reviewed_path.exists():
        reviewed_v2, code = render_reviewed_v2_file(reviewed_path)
        canonical_domain = reviewed_v2.module_name
        assumptions = [
            "Generated deterministically from a hash-bound reviewed V2 domain.",
            "Operations model atomic method calls; concurrent linearizability is not proved.",
        ]
        default_destination = f"{reviewed_v2.domain_name}.java"
    else:
        canonical_domain, code, assumptions = canonical_contract(domain, requirement)
        default_destination = "TrafficLightController.java"
    checked, errors = check_stub(code)
    if not checked:
        raise ValueError("reviewed canonical contract failed OpenJML check: " +
                         "\n".join(errors))
    destination = Path(out_file or default_destination)
    generated_class = java_class_name(code)
    if generated_class is None or destination.name != f"{generated_class}.java":
        raise ValueError(
            f"canonical public class {generated_class or '<unknown>'} must be written "
            f"to {generated_class or '<ClassName>'}.java")
    destination.write_text(code, encoding="utf-8")
    evidence: dict[str, Any] = {
        "status": "CANONICAL_CONTRACT",
        "claim": "REVIEWED_TRANSFORMATION",
        "domain": canonical_domain,
        "requirement": requirement,
        "requirement_sha256": hashlib.sha256(requirement.encode()).hexdigest(),
        "contract_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "assumptions": assumptions,
        "openjml_check": "VERIFIED",
        "human_acceptance_required": True,
        "source_refinement_proved": False,
    }
    if reviewed_v2 is not None:
        evidence.update({
            "reviewed_v2_domain": str(reviewed_path.resolve()),
            "accepted_candidate_sha256": reviewed_v2.accepted_candidate_sha256,
            "accepted_evidence_sha256": reviewed_v2.accepted_evidence_sha256,
            "transformation": "DETERMINISTIC_V2_TO_JML",
        })
        if reviewed_v2.concurrency is not None:
            from .v2_lock_serializer import lock_discipline_gate
            discipline = lock_discipline_gate(reviewed_v2, code, "java")
            evidence.update({
                "claim": discipline["claim"],
                "lock_discipline": discipline,
                "lock_discipline_proved": discipline["lock_discipline_proved"],
                "concurrent_linearizability_proved": False,
            })
    return {"evidence": evidence, "code_file": str(destination),
            "evidence_file": str(_write_evidence(destination, evidence))}


def canonical_draft_rust(domain: str, requirement: str, *, domains_root: Path,
                         out_file: str | Path | None = None) -> dict[str, Any]:
    """Lower a reviewed V2 domain into a Rust/Prusti contract deterministically."""
    from .rust_support import check_rust_syntax, lint_rust
    from .v2_prusti_serializer import render_reviewed_v2_prusti_file

    requested = _requested(domain)
    reviewed_path = domains_root / f"{requested}.json"
    if not reviewed_path.exists():
        raise ValueError(
            f"canonical Rust drafting requires a reviewed V2 domain; "
            f"{reviewed_path} not found (generate and promote one first)")
    reviewed, code = render_reviewed_v2_prusti_file(reviewed_path)
    findings = lint_rust(code)
    if any(item.get("severity") == "error" for item in findings):
        raise ValueError("reviewed canonical contract failed Rust safety lint: " +
                         "; ".join(item.get("message", "") for item in findings
                                   if item.get("severity") == "error"))
    if reviewed.execution_model == "async_message_passing":
        from .v2_async_serializer import check_tokio_scaffold
        check = check_tokio_scaffold(code)
        expected_check = "TOKIO_CHECKED"
    else:
        check = check_rust_syntax(code)
        expected_check = "RUST_CHECKED"
    if check.get("status") != expected_check:
        raise ValueError("Rust check gate failed on the reviewed canonical "
                         f"contract: {check.get('output', '')[-500:]}")
    destination = Path(out_file or f"{reviewed.domain_name}.rs")
    destination.write_text(code, encoding="utf-8")
    evidence: dict[str, Any] = {
        "status": "CANONICAL_CONTRACT",
        "claim": "REVIEWED_TRANSFORMATION",
        "domain": reviewed.module_name,
        "requirement": requirement,
        "requirement_sha256": hashlib.sha256(requirement.encode()).hexdigest(),
        "contract_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "assumptions": ([
            "TLC proves only a bounded atomic message-handler architecture.",
            "Tokio transport is statically checked; async refinement and delivery are unproved.",
        ] if reviewed.execution_model == "async_message_passing" else [
            "Generated deterministically from a hash-bound reviewed V2 domain.",
            "All concrete state access is routed through one non-panicking Rust Mutex.",
            "This is structural lock discipline, not Prusti proof or linearizability evidence.",
        ] if reviewed.concurrency is not None else [
            "Generated deterministically from a hash-bound reviewed V2 domain.",
            "Prusti attributes encode the reviewed contracts; no LLM was involved.",
            "Bodies transcribe reviewed effects; concurrent linearizability is not proved.",
        ]),
        "rust_check": check["status"],
        "human_acceptance_required": True,
        "source_refinement_proved": False,
        "reviewed_v2_domain": str(reviewed_path.resolve()),
        "accepted_candidate_sha256": reviewed.accepted_candidate_sha256,
        "accepted_evidence_sha256": reviewed.accepted_evidence_sha256,
        "transformation": ("DETERMINISTIC_V2_TO_TOKIO_TRANSPORT"
                           if reviewed.execution_model == "async_message_passing" else
                           "DETERMINISTIC_V2_TO_RUST_MUTEX"
                           if reviewed.concurrency is not None else
                           "DETERMINISTIC_V2_TO_PRUSTI"),
        "lock_discipline_proved": reviewed.concurrency is not None,
        "concurrent_linearizability_proved": False,
        "async_linearizability_proved": False,
    }
    if reviewed.concurrency is not None:
        from .v2_lock_serializer import lock_discipline_gate
        discipline = lock_discipline_gate(reviewed, code, "rust")
        evidence.update({"claim": discipline["claim"],
                         "lock_discipline": discipline})
    return {"evidence": evidence, "code_file": str(destination),
            "evidence_file": str(_write_evidence(destination, evidence))}


def canonical_draft_c(domain: str, requirement: str, *, domains_root: Path,
                      out_file: str | Path | None = None) -> dict[str, Any]:
    """Lower a reviewed V2 domain into a C/ACSL contract deterministically."""
    from .c_support import check_c_syntax, lint_acsl
    from .v2_acsl_serializer import render_reviewed_v2_acsl_file

    requested = _requested(domain)
    reviewed_path = domains_root / f"{requested}.json"
    if not reviewed_path.exists():
        raise ValueError(
            f"canonical C drafting requires a reviewed V2 domain; "
            f"{reviewed_path} not found (generate and promote one first)")
    reviewed, code = render_reviewed_v2_acsl_file(reviewed_path)
    findings = lint_acsl(code)
    if any(item.get("severity") == "error" for item in findings):
        raise ValueError("reviewed canonical contract failed ACSL lint: " +
                         "; ".join(item.get("message", "") for item in findings
                                   if item.get("severity") == "error"))
    check = check_c_syntax(code)
    if check.get("status") != "C_CHECKED":
        raise ValueError("C check gate failed on the reviewed canonical "
                         f"contract: {check.get('output', '')[-500:]}")
    destination = Path(out_file or f"{reviewed.module_name}.c")
    destination.write_text(code, encoding="utf-8")
    evidence = {
        "status": "CANONICAL_CONTRACT",
        "claim": "REVIEWED_TRANSFORMATION",
        "domain": reviewed.module_name,
        "requirement": requirement,
        "requirement_sha256": hashlib.sha256(requirement.encode()).hexdigest(),
        "contract_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "assumptions": [
            "Generated deterministically from a hash-bound reviewed V2 domain.",
            "ACSL contracts encode the reviewed semantics; no LLM was involved.",
            "Bodies transcribe reviewed effects; concurrent linearizability is not proved.",
        ],
        "c_check": check["status"],
        "human_acceptance_required": True,
        "source_refinement_proved": False,
        "reviewed_v2_domain": str(reviewed_path.resolve()),
        "accepted_candidate_sha256": reviewed.accepted_candidate_sha256,
        "accepted_evidence_sha256": reviewed.accepted_evidence_sha256,
        "transformation": "DETERMINISTIC_V2_TO_ACSL",
    }
    return {"evidence": evidence, "code_file": str(destination),
            "evidence_file": str(_write_evidence(destination, evidence))}


def canonical_draft_cpp(domain: str, requirement: str, *, domains_root: Path,
                        out_file: str | Path | None = None) -> dict[str, Any]:
    """Lower a reviewed V2 domain into bounded C++ evidence deterministically."""
    from .v2_cpp_serializer import render_reviewed_v2_cpp_file
    from .cpp_support import check_cpp_syntax

    requested = _requested(domain)
    reviewed_path = domains_root / f"{requested}.json"
    if not reviewed_path.exists():
        raise ValueError(f"canonical C++ drafting requires a reviewed V2 domain; "
                         f"{reviewed_path} not found")
    reviewed, code = render_reviewed_v2_cpp_file(reviewed_path)
    check = check_cpp_syntax(code)
    if check.get("status") != "CPP_CHECKED":
        raise ValueError("C++ syntax gate failed: " + check.get("output", "")[-500:])
    destination = Path(out_file or f"{reviewed.domain_name}.cpp")
    destination.write_text(code, encoding="utf-8")
    evidence = {"status": "CANONICAL_CONTRACT", "claim": "BOUNDED_CPP_EVIDENCE",
                "domain": reviewed.module_name,
                "contract_sha256": hashlib.sha256(code.encode()).hexdigest(),
                "cpp_check": check, "unbounded_loop_proved": False,
                "source_refinement_proved": False, "human_acceptance_required": True}
    return {"evidence": evidence, "code_file": str(destination),
            "evidence_file": str(_write_evidence(destination, evidence))}


def canonical_draft(domain: str, *, lang: str = "java", out_file: str | Path | None = None,
                    project_root: str | Path = ".",
                    requirement: str = "") -> dict[str, Any]:
    """Dispatch a canonical draft for one language from one project root."""
    domains_root = Path(project_root).resolve() / "domains" / "v2"
    if lang == "java":
        return canonical_draft_java(domain, requirement, domains_root=domains_root,
                                    out_file=out_file)
    if lang == "rust":
        return canonical_draft_rust(domain, requirement, domains_root=domains_root,
                                    out_file=out_file)
    if lang == "c":
        return canonical_draft_c(domain, requirement, domains_root=domains_root,
                                 out_file=out_file)
    if lang == "cpp":
        return canonical_draft_cpp(domain, requirement, domains_root=domains_root,
                                   out_file=out_file)
    raise ValueError(f"unsupported canonical draft language: {lang}")
