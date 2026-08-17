"""UnifiedArchitecture decomposition and scoped composition runner."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from .staged_architecture import UnifiedArchitecture
from .domain_v2_promotion import ReviewedDomainSpecV2, verify_artifact_signature


def _sha(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _signature_gate_keys(registry: str | Path = "trusted_keys.json"):
    """The authorized key set for the signature gate: the managed registry
    merged with the legacy environment variable (None = any valid signer)."""
    from .trust import authorized_keys
    return authorized_keys(registry)


def load_bound_artifact(artifact_path: str | Path, evidence_path: str | Path):
    artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
    evidence = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
    if evidence.get("status") != "VERIFIED":
        raise ValueError("ARCHITECTURE_EVIDENCE_NOT_VERIFIED")
    return UnifiedArchitecture.model_validate(artifact), evidence, _sha(artifact)


def _domain_dict(domain):
    """Normalize a reviewed-domain model or JSON value for deterministic lowering."""
    if isinstance(domain, ReviewedDomainSpecV2):
        return domain.model_dump(mode="json")
    return domain


def _load_reviewed_domain(domain_name: str, domains_dir: Path):
    domains_dir = Path(domains_dir)
    path = domains_dir / f"{domain_name}.json"
    if not path.is_file():
        raise ValueError(f"REVIEWED_DOMAIN_NOT_FOUND: {domain_name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("review_status") != "reviewed":
        raise ValueError(f"DOMAIN_NOT_REVIEWED: {domain_name}")
    if os.getenv("FORMALSPECGEN_REQUIRE_SIGNATURES", "").lower() in {"1", "true", "yes"}:
        authorized = _signature_gate_keys()
        result = verify_artifact_signature(path, Path(str(path) + ".promotion.sig"), authorized)
        if result["status"] != "SIGNATURE_VERIFIED":
            raise ValueError(f"CRITICAL: Cryptographic signature verification failed: {result['status']}")
    try:
        reviewed = ReviewedDomainSpecV2.model_validate(value)
        return reviewed
    except Exception as exc:
        raise ValueError(f"INVALID_REVIEWED_DOMAIN: {domain_name}: {exc}") from exc


def lower_component(component, language: str = "java", domain=None, interface=None) -> str:
    if language != "java":
        raise ValueError("UNSUPPORTED_UNIFIED_LOWERING_LANGUAGE")
    if component.type == "adapter":
        lines = ["// UNVERIFIED EXTERNAL BOUNDARY: generated integration stub.",
                 f"public class {component.name} implements {component.implements} {{"]
        for op in (interface.operations if interface else []):
            params = ", ".join(f"int {p.name}" for p in op.params)
            lines += [f"    //@ requires {op.contract.requires};",
                      f"    //@ ensures {op.contract.ensures};",
                      f"    public boolean {op.name}({params}) {{",
                      "        return false;", "    }"]
        return "\n".join(lines + ["}", ""])
    if component.type == "interface":
        def clause(value):
            value = value.replace(" OR ", " || ").replace(" AND ", " && ")
            value = value.replace(" or ", " || ").replace(" and ", " && ")
            value = value.replace(" = ", " == ")
            return value if r"\result" in value else value.replace("result", r"\result")
        lines = [f"public interface {component.name} {{"]
        for op in component.operations:
            params = ", ".join(f"int {p.name}" for p in op.params)
            lines += [f"    //@ requires {clause(op.contract.requires)};",
                      f"    //@ ensures {clause(op.contract.ensures)};",
                      f"    public boolean {op.name}({params});"]
        return "\n".join(lines + ["}", ""])
    domain = _domain_dict(domain)
    state_variables = (domain or {}).get("state_variables", component.state_variables)
    operations = (domain or {}).get("operations", [])
    lines = [f"public class {component.name} {{"]
    for state in state_variables:
        if isinstance(state, dict):
            state = type("State", (), state)()
        lines.append(f"    private int {state.name};")
    lines.append(f"    public {component.name}() {{")
    for state in component.state_variables:
        lines.append(f"        this.{state.name} = {state.initial};")
    lines += ["    }"]
    for operation in operations:
        if isinstance(operation, dict):
            operation = type("Operation", (), operation)()
        return_type = "boolean" if operation.return_type == "boolean" else "void"
        lines.append(f"    public {return_type} {operation.name}() {{")
        if return_type == "boolean":
            lines.append("        return false;")
        lines += ["    }"]
    lines += ["}", ""]
    return "\n".join(lines)


def run_unified_system(artifact_path: str | Path, evidence_path: str | Path,
                       out_dir: str | Path, language: str = "java") -> dict:
    try:
        arch, evidence, artifact_hash = load_bound_artifact(artifact_path, evidence_path)
        root = Path(out_dir); root.mkdir(parents=True, exist_ok=True)
        boundaries = []
        domains_dir = Path(artifact_path).resolve().parent / "domains" / "v2"
        interfaces = {item.name: item for item in arch.components if item.type == "interface"}
        for component in arch.components:
            domain = _load_reviewed_domain(component.domain, domains_dir) if component.domain else None
            target = root / (component.file or f"{component.name}.java")
            target.write_text(lower_component(component, language, domain,
                                              interfaces.get(component.implements)), encoding="utf-8")
            if component.type == "adapter":
                boundaries.append(component.name)
        java_files = [str(path) for path in root.glob("*.java")
                      if "UNVERIFIED EXTERNAL BOUNDARY" not in path.read_text(encoding="utf-8")]
        if not java_files:
            return {"status": "LOWERED", "claim": "NO_PROOF", "architecture_sha256": artifact_hash,
                    "tlc_evidence": evidence, "unverified_boundaries": boundaries,
                    "external_io_safety_proved": False, "out_dir": str(root)}
        openjml = os.environ.get("OPENJML_BIN", "tools/openjml-dist/openjml")
        try:
            result = subprocess.run([openjml, "-esc", *java_files], capture_output=True,
                                    text=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as exc:
            result = None
            esc_output = str(exc)
        else:
            esc_output = result.stdout + result.stderr
        verified = result is not None and result.returncode == 0
        verdict = {"status": "VERIFIED" if verified else "VERIFY_FAILED",
                   "claim": "SYSTEM_COMPOSITION_PROOF" if verified else "NO_PROOF",
                   "architecture_sha256": artifact_hash, "unverified_boundaries": boundaries,
                   "external_io_safety_proved": False, "esc_output": esc_output}
        (root / "composition_verdict.json").write_text(json.dumps(verdict, indent=2) + "\n")
        return verdict
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"status": "UNIFIED_SYSTEM_FAILED", "claim": "NO_PROOF", "message": str(exc)}
