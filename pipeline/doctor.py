# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Capability-based judge readiness; this module never mints evidence."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

from . import config

Runner = Callable[..., subprocess.CompletedProcess[str]]
Which = Callable[[str], str | None]


def _resolve(command: str, which: Which) -> str | None:
    path = Path(command).expanduser()
    if path.is_absolute() or os.sep in command:
        return str(path.resolve()) if path.is_file() and os.access(path, os.X_OK) else None
    return which(command)


def _probe(name: str, command: list[str], claims: list[str], pending: str,
           *, runner: Runner, which: Which, source: str, timeout: int = 5,
           success_codes: tuple[int, ...] = (0,), env: dict[str, str] | None = None) -> dict[str, Any]:
    resolved = _resolve(command[0], which)
    base = {"name": name, "configured_command": command, "resolved_executable": resolved,
            "configuration_source": source, "claims_enabled": claims,
            "judge_pending": pending}
    if resolved is None:
        return {**base, "status": "ABSENT", "smoke_test": "not_run", "version": None}
    try:
        kwargs: dict[str, Any] = {"capture_output": True, "text": True, "timeout": timeout}
        if env is not None:
            kwargs["env"] = env
        result = runner([resolved, *command[1:]], **kwargs)
    except subprocess.TimeoutExpired:
        return {**base, "status": "ERROR", "smoke_test": "timeout", "version": None}
    except OSError as exc:
        return {**base, "status": "ERROR", "smoke_test": "execution_failed",
                "version": None, "message": str(exc)}
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    ready = result.returncode in success_codes
    return {**base, "status": "READY" if ready else "ERROR",
            "smoke_test": "passed" if ready else "failed", "exit_code": result.returncode,
            "version": output.splitlines()[0][:300] if output else None}


def _tlc_probe(*, runner: Runner, which: Which) -> dict[str, Any]:
    java = _resolve(config.JAVA_BIN, which)
    jar = Path(config.TLC_JAR).expanduser().resolve()
    base = {"name": "TLC", "configured_command": [config.JAVA_BIN, "-cp", str(jar),
                                                    "tlc2.TLC", "-help"],
            "resolved_executable": java, "configuration_source": "environment_or_default",
            "claims_enabled": ["BOUNDED_ARCHITECTURE_EVIDENCE"], "judge_pending": "tlc"}
    if java is None or not jar.is_file():
        missing = "executable" if java is None else "artifact"
        return {**base, "status": "ABSENT", "smoke_test": "not_run", "version": None,
                "message": f"configured {missing} is unavailable"}
    # TLC deliberately exits 1 after rendering its help page.
    return _probe("TLC", [config.JAVA_BIN, "-cp", str(jar), "tlc2.TLC", "-help"],
                  ["BOUNDED_ARCHITECTURE_EVIDENCE"], "tlc", runner=runner,
                  which=which, source="environment_or_default", success_codes=(0, 1))


def inspect_environment(*, runner: Runner = subprocess.run,
                        which: Which = shutil.which) -> dict[str, Any]:
    """Report command readiness and its effect on each evidence ceiling."""
    specs = [
        ("OpenJML", [config.OPENJML, "--version"], ["DEDUCTIVE_PROOF"], "openjml", "OPENJML_BIN"),
        ("Prusti", [config.PRUSTI_BIN, "--version"], ["DEDUCTIVE_RUST_EVIDENCE"], "prusti", "PRUSTI_BIN"),
        ("Frama-C", [config.FRAMAC_BIN, "-version"], ["DEDUCTIVE_C_EVIDENCE"], "frama_c", "FRAMAC_BIN"),
        ("ESBMC", ["esbmc", "--version"], ["BOUNDED_C_EVIDENCE", "LOCKFREE_INTERLEAVING_PROVED"], "esbmc", "PATH"),
        ("Z3", ["z3", "--version"], ["SMT_MODEL_PROVED"], "z3", "PATH"),
        ("Semgrep", ["semgrep", "--version"], ["SAST_CLEAN"], "semgrep", "PATH"),
        ("herd7", ["herd7", "--version"], ["WEAK_MEMORY_SAFETY"], "herd7_or_rc11", "PATH"),
    ]
    checks = [_probe(name, command, claims, pending, runner=runner, which=which,
                     source=source if source == "PATH" or os.environ.get(source) else "default")
              for name, command, claims, pending, source in specs]
    checks.insert(1, _tlc_probe(runner=runner, which=which))
    dafny_env = os.environ.copy()
    dafny_env["DOTNET_ROOT"] = config.DOTNET_ROOT
    checks.append(_probe("Dafny", [config.DAFNY_BIN, "--version"], ["HEAP_SHAPE_PROVED"],
                         "dafny", runner=runner, which=which,
                         source="DAFNY_BIN" if os.environ.get("DAFNY_BIN") else "default",
                         env=dafny_env))

    kani = _probe("Kani", ["cargo", "kani", "--version"],
                  ["BOUNDED_RUST_EVIDENCE", "RUST_WITNESS_REFINEMENT_PROVED"], "kani",
                  runner=runner, which=which, source="cargo_subcommand")
    if Path(config.KANI_BIN).name not in {"cargo", "cargo.exe", "kani-driver", "kani-driver.exe"}:
        kani.update(status="MISCONFIGURED", smoke_test="configuration_mismatch",
                    message=(f"KANI_BIN={config.KANI_BIN!r} is incompatible with the generic "
                             "lane; configure 'cargo' or 'kani-driver'"))
    checks.append(kani)
    counts = {status: sum(item["status"] == status for item in checks)
              for status in ("READY", "ABSENT", "MISCONFIGURED", "ERROR")}
    from .domains.registry import PLUGINS
    from .domains.router import maturity_report
    from .capability_registry import milestone_capabilities
    readiness = {item["name"]: item["status"] for item in checks}
    lanes = []
    for capability in milestone_capabilities():
        milestone = capability.milestone
        assert milestone is not None
        missing = [judge for judge in milestone.required_judges
                   if readiness.get(judge) != "READY"]
        lanes.append({
            "lane": milestone.lane,
            "status": "ENVIRONMENT_READY" if not missing else "JUDGE_PENDING",
            "current_step": milestone.current_step,
            "step_status": milestone.step_status,
            "maturity": milestone.current_maturity,
            "required_judges": list(milestone.required_judges),
            "missing_judges": missing,
            "claims_available": list(milestone.completed_claims),
            "claims_locked": [claim.claim for claim in milestone.claims
                              if claim.claim not in milestone.completed_claims],
            "claims_forbidden": list(milestone.claims_forbidden),
            "deployment_split": milestone.deployment_split,
            "deployment_profiles": list(milestone.deployment_profiles),
            "hardware_profiles": list(milestone.hardware_profiles),
            "assumptions": list(milestone.assumptions),
            "artifact_hash_bindings": list(milestone.artifact_hash_bindings),
        })
    return {"status": "READY" if not counts["MISCONFIGURED"] and not counts["ERROR"]
            else "ATTENTION_REQUIRED", "claim": "NO_PROOF", "evidence_minted": False,
            "scope": "judge_readiness_at_report_time", "summary": counts,
            "capabilities": checks, "domains": maturity_report(PLUGINS), "lanes": lanes}


def required_failures(report: dict[str, Any], required: list[str]) -> list[str]:
    indexed = {item["name"].lower(): item for item in report["capabilities"]}
    return [name for name in required
            if name.lower() not in indexed or indexed[name.lower()]["status"] != "READY"]
