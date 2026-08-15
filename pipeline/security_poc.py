"""Safe vulnerability inspection and local PoC test generation."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .security_assessment import map_formal_failure_to_cwe, map_formal_vcs, run_semgrep
from .verify import verify


def _source_files(source: str | Path) -> list[Path]:
    path = Path(source)
    if path.is_file():
        return [path]
    return sorted(path for path in path.rglob("*")
                  if path.is_file() and path.suffix.lower() in {".java", ".rs", ".c", ".h", ".cpp", ".cc"}) \
        if path.is_dir() else []


def _line_for(label: str, output: str) -> int | None:
    match = re.search(rf"(?m)^.*?:(\d+):.*?{re.escape(label)}", output)
    return int(match.group(1)) if match else None


def inspect_security(source: str | Path) -> dict[str, Any]:
    files = _source_files(source)
    if not files:
        return {"status": "FAIL", "claim": "NO_PROOF", "code": "input_unavailable",
                "message": str(source), "findings": []}
    findings: list[dict[str, Any]] = []
    files_checked = []
    for path in files:
        semgrep = run_semgrep(path) if path.suffix.lower() == ".java" else {"findings": [], "status": "SKIPPED"}
        for item in semgrep.get("findings", []):
            findings.append({**item, "file": str(path), "type": "SAST_PATTERN"})
        exit_code, output = verify(path, mode="esc")
        files_checked.append({"file": str(path), "exit_code": exit_code})
        verifier = {".java": "openjml", ".rs": "prusti", ".c": "framac",
                    ".h": "framac", ".cpp": "esbmc", ".cc": "esbmc"}.get(path.suffix.lower(), "")
        formal_findings = map_formal_vcs(output) if verifier == "openjml" else [
            {**map_formal_failure_to_cwe(verifier, output), "source": verifier,
             "vc": "native_failure", "description": "Native prover failure"}
        ] if exit_code != 0 else []
        for item in formal_findings:
            findings.append({**item, "file": str(path), "line": _line_for(item["vc"], output),
                             "type": "FORMAL_VC"})
    return {"status": "VULNERABILITIES_FOUND" if findings else "NO_FINDINGS",
            "claim": "SECURITY_INSPECTION_COMPLETE", "source": str(source),
            "files_checked": files_checked, "findings": findings,
            "exploitability_proved": False,
            "scope": "Pattern findings and formal counterexample labels only; no exploit execution."}


def _poc_for(finding: dict[str, Any], target: Path, index: int) -> tuple[str, str] | None:
    cwe, kind = finding.get("cwe"), finding.get("type")
    if target.suffix.lower() == ".rs" and cwe == "CWE-125":
        return (f"out_of_bounds_poc_{index}",
                "#[test]\n#[should_panic]\nfn demonstrates_out_of_bounds() {\n"
                "    let values = [1i32];\n    let index: usize = usize::MAX;\n"
                "    let _ = values[index];\n}\n")
    if target.suffix.lower() in {".c", ".h", ".cpp", ".cc"} and cwe == "CWE-125":
        return (f"out_of_bounds_poc_{index}.c",
                "#include <assert.h>\n#include <stddef.h>\n\n"
                "int main(void) { int values[1] = {1}; size_t index = 1;\n"
                "    /* Review-only harness: bounds violation is intentionally not executed. */\n"
                "    assert(index >= sizeof(values) / sizeof(values[0])); return 0; }\n")
    class_name = re.search(r"\bclass\s+(\w+)", target.read_text(encoding="utf-8"))
    source = target.read_text(encoding="utf-8")
    subject = class_name.group(1) if class_name else target.stem
    method_match = re.search(r"\b(?:public|protected)\s+[^(){};]+\s+(\w+)\s*\([^)]*\)", source)
    method = method_match.group(1) if method_match else "get"
    if cwe == "CWE-125" or "INDEX" in str(finding.get("vc", "")).upper():
        name = f"OutOfBoundsPoC{index}"
        code = ("import static org.junit.jupiter.api.Assertions.assertThrows;\n"
                "import org.junit.jupiter.api.Test;\n\n"
                f"class {name} {{\n    @Test\n    void demonstratesOutOfBounds() {{\n"
                f"        {subject} service = new {subject}();\n"
                f"        assertThrows(ArrayIndexOutOfBoundsException.class, () -> service.{method}(new int[]{{1}}, -1));\n"
                "    }\n}\n")
        return name, code
    if cwe == "CWE-89" or "SQL" in str(finding.get("rule_id", "")).upper():
        name = f"SqlInjectionPoC{index}"
        code = ("import org.junit.jupiter.api.Test;\n"
                "import static org.junit.jupiter.api.Assertions.assertTrue;\n\n"
                f"class {name} {{\n    @Test\n    void demonstratesUntrustedQueryText() {{\n"
                "        String payload = \"' OR 1=1 --\";\n"
                "        // Replace this assertion with the target's observable query hook.\n"
                "        assertTrue(payload.contains(\"OR 1=1\"));\n    }\n}\n")
        return name, code
    if cwe == "CWE-22":
        name = f"PathTraversalPoC{index}"
        code = ("import org.junit.jupiter.api.Test;\n"
                "import static org.junit.jupiter.api.Assertions.assertTrue;\n\n"
                f"class {name} {{\n    @Test\n    void demonstratesTraversalInput() {{\n"
                "        String payload = \"../../../../etc/passwd\";\n"
                "        // Verify the application canonicalizes and confines this path.\n"
                "        assertTrue(payload.contains(\"..\"));\n    }\n}\n")
        return name, code
    if cwe == "CWE-502":
        name = f"DeserializationPoC{index}"
        code = ("import org.junit.jupiter.api.Test;\n"
                "import static org.junit.jupiter.api.Assertions.assertNotNull;\n\n"
                f"class {name} {{\n    @Test\n    void demonstratesUntrustedBytes() {{\n"
                "        byte[] untrusted = new byte[]{0, 1, 2, 3};\n"
                "        // Route bytes through a test seam; do not execute gadget payloads.\n"
                "        assertNotNull(untrusted);\n    }\n}\n")
        return name, code
    if cwe == "CWE-190":
        name = f"IntegerOverflowPoC{index}"
        code = ("import org.junit.jupiter.api.Test;\n"
                "import static org.junit.jupiter.api.Assertions.assertThrows;\n\n"
                f"class {name} {{\n    @Test\n    void demonstratesBoundaryInput() {{\n"
                "        int input = Integer.MAX_VALUE;\n"
                "        assertThrows(ArithmeticException.class, () -> Math.addExact(input, 1));\n"
                "    }\n}\n")
        return name, code
    if cwe == "CWE-476":
        name = f"NullDereferencePoC{index}"
        code = ("import org.junit.jupiter.api.Test;\n"
                "import static org.junit.jupiter.api.Assertions.assertThrows;\n\n"
                f"class {name} {{\n    @Test\n    void demonstratesNullInput() {{\n"
                "        assertThrows(NullPointerException.class, () -> ((Object) null).toString());\n"
                "    }\n}\n")
        return name, code
    return None


def generate_pocs(report_path: str | Path, target: str | Path,
                  out_dir: str | Path = "security-pocs") -> dict[str, Any]:
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    findings = report if isinstance(report, list) else report.get("findings", [])
    target_path = Path(target)
    destination = Path(out_dir); destination.mkdir(parents=True, exist_ok=True)
    generated = []
    for index, finding in enumerate(findings, 1):
        result = _poc_for(finding, target_path, index)
        if result is None:
            continue
        name, code = result
        extension = ".java" if target_path.suffix.lower() == ".java" else target_path.suffix.lower()
        output = destination / (name if name.endswith(extension) else f"{name}{extension}")
        output.write_text(code, encoding="utf-8")
        generated.append({"file": str(output), "finding": finding,
                          "status": "POC_GENERATED", "executed": False})
    return {"status": "POCS_GENERATED" if generated else "NO_SUPPORTED_POC",
            "claim": "POC_GENERATED_NOT_EXECUTED", "target": str(target_path),
            "generated": generated, "exploit_proven": False,
            "scope": "Local JUnit source templates only; compilation and execution require explicit human review."}
