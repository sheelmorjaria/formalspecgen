# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Typed concurrency-model lowering judged by SANY/TLC."""
import re
import subprocess
import tempfile
import json
from pathlib import Path

from . import config
from .extract_tla_ir import UnsupportedJmlSemantics, extract_banking_model
from .tla_ir import default_banking_ir, preflight_tla, render_banking_model
from .lifecycle import command_version, sha256_text


def generate_and_check(code: str, provider: str = "glm", max_format_attempts: int = 2,
                       clarifications: str = "", abstraction: str | None = None) -> dict:
    del provider, max_format_attempts  # Source serialization never depends on an LLM.
    from .domains.registry import PLUGINS
    from .domains.router import (AmbiguousDomain, DomainMaturity,
                                 UnsupportedDomain, select_domain)
    try:
        plugin = select_domain(code, PLUGINS,
                               minimum_maturity=DomainMaturity.BOUNDED_EVIDENCE)
    except (UnsupportedDomain, AmbiguousDomain) as exc:
        details = []
        if isinstance(exc, UnsupportedDomain):
            from .domains.traffic_light_controller_extract import diagnose_traffic_light_boundary
            details = diagnose_traffic_light_boundary(code)
        message = str(exc) + ". Direct LLM-to-TLA+ generation is disabled."
        if details:
            message += " Traffic-light adapter mismatch: " + "; ".join(details) + "."
        return {
            "status": "AMBIGUOUS_DOMAIN" if isinstance(exc, AmbiguousDomain) else "UNSUPPORTED_BOUNDARY",
            "message": message,
            "counterexample": [],
            "renderer": "none",
        }
    try:
        ir, consistency = plugin.extract(code, clarifications, abstraction)
    except UnsupportedJmlSemantics as exc:
        return {"status": "UNSUPPORTED_BOUNDARY", "message": str(exc),
                "counterexample": [], "renderer": "none"}
    if consistency:
        return {"status": "CONSISTENCY_FAILED",
                "message": consistency[0]["message"], "consistency": consistency,
                "counterexample": [], "ir": ir.model_dump(), "renderer": "none"}
    tla, cfg = plugin.render(ir)
    renderer_name = f"{plugin.name}_{getattr(ir, 'abstraction', 'atomic_operations')}_v1"
    preflight_errors = preflight_tla(tla)
    if preflight_errors:
        return {"status": "TRANSLATION_ERROR", "message": preflight_errors[0],
                "output": "\n".join(preflight_errors), "counterexample": [],
                "ir": ir.model_dump(), "renderer": renderer_name, "domain": plugin.name}
    result = check_tla(tla, cfg)
    invariant_failed = result.get("status") == "INVARIANT_VIOLATION"
    dumped_ir = ir.model_dump()
    execution_assumption = getattr(ir, "execution_assumption", None)
    bounded_fields = {name: dumped_ir[name] for name in
                      ("accounts", "actors", "products", "max_balance", "max_stock", "amounts")
                      if name in dumped_ir}
    provenance = {
        "source_sha256": sha256_text(code),
        "contract_sha256": sha256_text("\n".join(sorted(
            re.findall(r"(?m)^\s*//@\s*(.+)$", code)))),
        "ir_sha256": sha256_text(json.dumps(dumped_ir, sort_keys=True)),
        "tla_sha256": sha256_text(tla), "cfg_sha256": sha256_text(cfg),
        "backend": "tlc", "tool_version": command_version(
            [config.OPENJML_JAVA, "-jar", config.TLC_JAR, "-version"]),
        "command": [config.OPENJML_JAVA, "-jar", config.TLC_JAR,
                    "-config", "<module>.cfg", "<module>"],
        "bounds": bounded_fields,
        "abstraction": getattr(ir, "abstraction", "atomic_operations"),
        "execution_assumption": execution_assumption,
        "source_refinement_proved": False,
    }
    provenance["tool_versions"] = {"tlc": provenance["tool_version"]}
    return {**result, "tla": tla, "cfg": cfg, "ir": dumped_ir,
            "domain": plugin.name, "model": f"typed-{plugin.name}-ir", "renderer": renderer_name,
            "attempts": [{"attempt": 1, "status": result["status"],
                          "message": result.get("message", ""),
                          "output": result.get("output", "")[-2000:]}],
            "translation": f"bounded_{plugin.name}_v1",
            "claim": "BOUNDED_ARCHITECTURE_EVIDENCE",
            "source_refinement_proved": False,
            "repair_target": "validated_ir" if invariant_failed else None,
            "generated_tla_repair_allowed": False,
            "provenance": provenance,
            "disclaimer": (
                f"TLC checked a bounded {plugin.name} abstraction, not Java/JML source equivalence."
                + (f" The model assumes {execution_assumption.replace('_', ' ')} execution."
                   if execution_assumption else ""))}


def detect_banking_boundary(code: str) -> bool:
    """Recognize only the explicit account-operation vocabulary supported by the template."""
    lowered = code.lower()
    return ("balance" in lowered and all(re.search(rf"\b{name}\s*\(", lowered)
                                          for name in ("deposit", "withdraw", "transfer")))


def banking_model() -> tuple[str, str]:
    """Compatibility facade for callers that consume the rendered artifacts."""
    return render_banking_model(default_banking_ir())


def parse_output(raw: str) -> tuple[str, str]:
    """Accept the documented markers plus common fenced equivalents from local models."""
    marked_tla = re.search(r"===\s*TLA\s*===\s*(.*?)\s*===\s*CFG\s*===", raw,
                           re.S | re.I)
    marked_cfg = re.search(r"===\s*CFG\s*===\s*(.*?)\s*===\s*END\s*===", raw,
                           re.S | re.I)
    if marked_tla and marked_cfg:
        return _validate_output(_unwrap_fence(marked_tla.group(1)),
                                _unwrap_fence(marked_cfg.group(1)))

    tla_fence = re.search(r"```(?:tla\+?|tlaplus)\s*\n(.*?)```", raw, re.S | re.I)
    cfg_fence = re.search(r"```(?:cfg|config|tlacfg)\s*\n(.*?)```", raw, re.S | re.I)
    if tla_fence and cfg_fence:
        return _validate_output(tla_fence.group(1), cfg_fence.group(1))

    # Last conservative recovery: locate a complete TLA+ module, but still require an
    # explicitly labelled configuration after it. Never invent either artifact.
    module = re.search(r"(----\s+MODULE\s+\w+\s+----.*?^====\s*$)", raw, re.S | re.M)
    trailing_cfg = re.search(r"(?:CFG|CONFIG(?:URATION)?)\s*:?\s*\n(.*)$", raw, re.S | re.I)
    if module and trailing_cfg:
        return _validate_output(module.group(1), _unwrap_fence(trailing_cfg.group(1)))
    raise ValueError("translator did not emit a complete TLA+ module and explicit TLC configuration")


def _unwrap_fence(value: str) -> str:
    text = value.strip()
    match = re.fullmatch(r"```[^\n]*\n(.*?)```", text, re.S)
    return (match.group(1) if match else text).strip()


def _validate_output(tla: str, cfg: str) -> tuple[str, str]:
    tla, cfg = normalize_tla_syntax(tla), normalize_cfg(cfg)
    if not re.search(r"----\s+MODULE\s+\w+\s+----", tla):
        raise ValueError("translator output has no valid TLA+ module header")
    if not re.search(r"(?m)^====\s*$", tla):
        # The module terminator carries no behavior; restoring it is a syntactic
        # normalization. TLC still parses and judges every generated definition.
        tla += "\n===="
    if not cfg or not re.search(r"\b(?:SPECIFICATION|INIT|NEXT|INVARIANT|PROPERTY|CONSTANTS?)\b",
                                cfg, re.I):
        raise ValueError("translator output has no usable TLC configuration")
    return tla, cfg


_CFG_KEYWORD = re.compile(
    r"^(SPECIFICATION|CONSTANTS?|INVARIANTS?|PROPERTIES|PROPERTY|CONSTRAINTS?|"
    r"ACTION_CONSTRAINTS?|SYMMETRY|VIEW|CHECK_DEADLOCK|POSTCONDITION|ALIAS|INIT|NEXT|SPEC|INV)\b",
    re.I,
)
_CFG_NAME = re.compile(r"^[A-Za-z_]\w*(?:![A-Za-z_]\w*)*$")


def normalize_cfg(cfg: str) -> str:
    """Canonicalize model-generated invariant/property lists without changing their names.

    TLC accepts explicit keyword entries reliably. Local models commonly emit one plural
    heading followed by several bare names, which some TLC versions reject after the first
    name. Expand only these name lists; preserve constants and all other sections verbatim.
    """
    lines = cfg.strip().splitlines()
    output: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        if not line or line.startswith("\\*"):
            index += 1
            continue
        match = _CFG_KEYWORD.match(line)
        if not match:
            output.append(line)
            index += 1
            continue
        keyword = match.group(1).upper()
        if keyword == "SPEC":
            keyword = "SPECIFICATION"
        elif keyword == "INV":
            keyword = "INVARIANT"
        if keyword not in {"INVARIANT", "INVARIANTS", "PROPERTY", "PROPERTIES"}:
            if match.group(1).upper() == "SPEC":
                output.append("SPECIFICATION" + line[match.end():])
            else:
                output.append(line)
            index += 1
            continue
        canonical = "INVARIANT" if keyword.startswith("INVARIANT") else "PROPERTY"
        values = line[match.end():].strip()
        names = _cfg_names(values) if values else []
        index += 1
        while index < len(lines) and not _CFG_KEYWORD.match(lines[index].strip()):
            candidate = lines[index].strip()
            if candidate and not candidate.startswith("\\*"):
                parsed = _cfg_names(candidate)
                if not parsed:
                    # Preserve an unknown shape so TLC remains the authoritative rejector.
                    names.append(candidate)
                else:
                    names.extend(parsed)
            index += 1
        output.extend(f"{canonical} {name}" for name in names)
    if any(re.match(r"^SPECIFICATION\b", line, re.I) for line in output):
        output = [line for line in output if not re.match(r"^(?:INIT|NEXT)\b", line, re.I)]
    return "\n".join(output).strip()


def _cfg_names(value: str) -> list[str]:
    cleaned = re.sub(r"^[-*]\s*", "", value.strip())
    candidates = [item for item in re.split(r"[\s,]+", cleaned) if item]
    return candidates if candidates and all(_CFG_NAME.fullmatch(item) for item in candidates) else []


def normalize_tla_syntax(tla: str) -> str:
    """Normalize syntax-only Java/model artifacts without touching TLA+ expressions."""
    value = re.sub(r"(?<![A-Za-z0-9_])(\d+)L\b", r"\1", tla.strip())
    value = re.sub(r"(?m)^(\s*[A-Za-z_]\w*(?:\([^\n)]*\))?\s*)=(?!=)\s*",
                   r"\1== ", value)

    def standard_modules(match: re.Match) -> str:
        return re.sub(r"\bInt\b", "Integers", match.group(0))

    return re.sub(r"(?mi)^\s*EXTENDS\s+[^\n]+$", standard_modules, value)


def lint_tla_model(tla: str) -> list[str]:
    """Reject structurally contradictory Next branches before invoking TLC."""
    next_match = re.search(r"(?ms)^Next\s*==\s*(.*?)(?=^[A-Za-z_]\w*\s*==|^====)", tla)
    if not next_match:
        return ["model does not define a top-level Next operator"]
    branches = re.split(r"(?m)^\s*\\/\s+", next_match.group(1))
    findings = []
    for number, branch in enumerate(branches, 1):
        unchanged = set()
        for match in re.finditer(r"UNCHANGED\s*<<([^>]+)>>", branch):
            unchanged.update(re.findall(r"\b[A-Za-z_]\w*\b", match.group(1)))
        assigned = set(re.findall(r"\b([A-Za-z_]\w*)'\s*=", branch))
        conflict = sorted(unchanged & assigned)
        if conflict:
            findings.append(
                f"Next branch {number} both assigns and declares UNCHANGED: {', '.join(conflict)}")
    return findings


def check_tla(tla: str, cfg: str, timeout: int | None = None) -> dict:
    model_findings = lint_tla_model(tla)
    if model_findings:
        return {"status": "MODEL_LINT_FAILED", "exit_code": 2, "counterexample": [],
                "message": model_findings[0], "output": "\n".join(model_findings)}
    module = re.search(r"MODULE\s+(\w+)", tla)
    if not module:
        return {"status": "PARSE_ERROR", "counterexample": [], "message": "missing module name"}
    name = module.group(1)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / f"{name}.tla").write_text(tla)
        (root / f"{name}.cfg").write_text(cfg)
        try:
            command = [config.OPENJML_JAVA, "-jar", config.TLC_JAR]
            if re.search(r"(?mi)^CHECK_DEADLOCK\s+FALSE\s*$", cfg):
                command.append("-deadlock")
            command.extend(["-config", f"{name}.cfg", name])
            process = subprocess.run(
                command,
                cwd=root, capture_output=True, text=True,
                timeout=config.TLC_TIMEOUT if timeout is None else timeout)
            output = (process.stdout or "") + (process.stderr or "")
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "exit_code": 124, "counterexample": []}
        except FileNotFoundError as exc:
            return {"status": "TOOL_MISSING", "exit_code": 127, "counterexample": [], "message": str(exc)}
    status = "VERIFIED" if process.returncode == 0 else "INVARIANT_VIOLATION" if process.returncode == 12 else "TLC_FAILED"
    counterexample = _trace(output)
    return {"status": status, "exit_code": process.returncode,
            "counterexample": counterexample,
            "trace_table": trace_table(counterexample), "output": output[-8000:]}


def _trace(output: str) -> list[str]:
    starts = [match.start() for match in re.finditer(r"(?m)^State \d+:", output)]
    if not starts:
        return []
    starts.append(len(output))
    return [output[starts[i]:starts[i + 1]].strip() for i in range(len(starts) - 1)]


def trace_table(states: list[str]) -> list[dict]:
    """Convert TLC's textual states into UI-safe rows without interpreting values."""
    rows: list[dict] = []
    previous: dict[str, str] = {}
    for fallback_index, state in enumerate(states, 1):
        lines = state.splitlines()
        header = re.match(r"State\s+(\d+):\s*(.*)", lines[0]) if lines else None
        index = int(header.group(1)) if header else fallback_index
        label = header.group(2).strip() if header else ""
        variables: dict[str, str] = {}
        current = ""
        for line in lines[1:]:
            assignment = re.match(r"\s*/\\\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
            if assignment:
                current = assignment.group(1)
                variables[current] = assignment.group(2).strip()
            elif current and line.strip():
                variables[current] = f"{variables[current]} {line.strip()}".strip()
        changed = [name for name, value in variables.items()
                   if name not in previous or previous[name] != value]
        rows.append({"state": index, "label": label, "variables": variables,
                     "changed": changed, "raw": state})
        previous = variables
    return rows
