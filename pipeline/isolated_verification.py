# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Strict, observation-preserving adapters for the polyglot ``verify`` workflow."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import config
from .c_support import lint_acsl
from .execution import (
    ExecutionObservation,
    ExecutionPolicy,
    ExecutionRequest,
    SourceSnapshot,
    StrictSandboxExecutor,
)
from .kani import kani_harnesses, parse_kani_diagnostics, verified_property_count
from .parse_esbmc import parse_esbmc_vcs
from .parse_framac import parse_framac_vcs
from .parse_prusti import parse_prusti_vcs
from .rust_support import lint_rust
from .verify import verify_detailed


_PRUSTI_ATTRIBUTE = re.compile(
    r"(?m)^[ \t]*#\[(?:requires|ensures|after_expiry|assert_on_expiry|pure|trusted|predicate|invariant)"
    r"(?:\([^\n]*\))?\][ \t]*(?:\r?\n)?"
)
_PRUSTI_OBLIGATION = re.compile(
    r"#\[\s*(?:requires|ensures|after_expiry|assert_on_expiry)|"
    r"body_invariant!|prusti_assert!"
)
_FRAMAC_PROVED = re.compile(r"Proved goals:\s*(\d+)\s*/\s*(\d+)", re.I)
_RESOURCE_FAILURES = {
    "OUTPUT_LIMIT_EXCEEDED", "MEMORY_LIMIT_EXCEEDED", "PROCESS_LIMIT_EXCEEDED",
    "WRITABLE_STORAGE_LIMIT_EXCEEDED", "CPU_LIMIT_EXCEEDED",
    "FILE_SIZE_LIMIT_EXCEEDED", "TIMEOUT",
}
_TOOL_INITIALIZATION_MARKERS = (
    "failed to find java home directory",
    "error loading java.security file",
    "error while loading shared libraries",
    "unknown prover",
    "the compiler unexpectedly panicked",
)


@dataclass(frozen=True)
class IsolatedVerificationResult:
    """Backend observations plus their semantic interpretation."""

    payload: dict[str, Any]
    observations: tuple[ExecutionObservation, ...] = ()

    @property
    def exit_code(self) -> int:
        return int(self.payload.get("exit_code", 1))

    @property
    def output(self) -> str:
        return str(self.payload.get("output") or self.payload.get("message") or "")

    @property
    def observation(self) -> ExecutionObservation | None:
        return self.observations[-1] if self.observations else None

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.payload,
            "execution": self.observation.as_dict() if self.observation else None,
            "execution_stages": [item.as_dict() for item in self.observations],
        }


def execute_isolated_verification(
        source: str | Path, mode: str = "esc", backend: str = "prusti", *,
        executor: StrictSandboxExecutor | None = None) -> IsolatedVerificationResult:
    """Run one supported verifier without an unrestricted subprocess fallback."""
    path = Path(source)
    suffix = path.suffix.lower()
    if suffix in {".java", ".jml"}:
        detailed = verify_detailed(path, mode=mode, executor=executor)
        return IsolatedVerificationResult(
            {"exit_code": detailed.exit_code, "output": detailed.output},
            (detailed.observation,) if detailed.observation else ())
    if not path.is_file():
        return IsolatedVerificationResult({
            "status": "SOURCE_UNAVAILABLE", "exit_code": 2, "claim": "NO_PROOF",
            "message": f"source file unavailable: {path}",
        })
    if suffix == ".rs":
        return _verify_rust(path, mode, backend, executor)
    if suffix == ".c":
        if mode != "esc":
            return _unsupported_mode("c", "C/ACSL currently supports esc through Frama-C WP")
        return _verify_c(path, executor)
    if suffix in {".cc", ".cpp", ".cxx"}:
        if mode != "esc":
            return _unsupported_mode("cpp", "C++ currently supports bounded ESBMC verification through esc")
        return _verify_cpp(path, executor)
    return IsolatedVerificationResult({
        "status": "UNSUPPORTED_LANGUAGE", "exit_code": 2, "claim": "NO_PROOF",
        "message": f"unsupported source extension: {suffix or '<none>'}",
    })


def _unsupported_mode(language: str, message: str) -> IsolatedVerificationResult:
    return IsolatedVerificationResult({
        "status": "UNSUPPORTED_MODE", "exit_code": 2, "claim": "NO_PROOF",
        "language": language, "message": message,
    })


def _resolve_tool(value: str, label: str) -> tuple[Path | None, dict[str, Any] | None]:
    configured = Path(value).expanduser()
    resolved = None
    if configured.is_absolute() and configured.is_file() and os.access(configured, os.X_OK):
        resolved = configured
    elif found := shutil.which(value):
        discovered = Path(found).absolute()
        if discovered.is_file() and os.access(discovered, os.X_OK):
            resolved = discovered
    if resolved is None:
        return None, {
            "status": "TOOL_MISSING", "exit_code": 127, "claim": "NO_PROOF",
            "message": f"{label} executable not found: {value}",
        }
    return resolved, None


def _tool_identity(binary: Path) -> dict[str, Any]:
    content = binary.read_bytes()
    return {
        "path": str(binary), "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _readonly_tool_root(binary: Path) -> tuple[Path, ...]:
    """Expose non-system managed distributions without mounting a broad home tree."""
    if any(binary.is_relative_to(Path(root)) for root in ("/usr", "/bin", "/lib", "/lib64")):
        return ()
    configured_roots = (
        Path(config.PRUSTI_BIN).expanduser().parent,
        Path(config.FRAMAC_BIN).expanduser().parent.parent,
    )
    root = next((item.resolve() for item in configured_roots
                 if item.exists() and binary.is_relative_to(item.resolve())), binary.parent)
    return (root,)


def _rust_tool_paths(binary: Path, environment: dict[str, str]) -> tuple[Path, ...]:
    roots = [Path(value).resolve() for value in environment.values()
             if Path(value).is_dir()]
    for candidate in _readonly_tool_root(binary):
        if not any(candidate == root or candidate.is_relative_to(root) for root in roots):
            roots.append(candidate)
    return tuple(dict.fromkeys(roots))


def _java_home() -> str | None:
    configured = os.environ.get("JAVA_HOME")
    if configured and Path(configured).is_dir():
        return str(Path(configured).resolve())
    java = shutil.which("java")
    if java:
        resolved = Path(java).resolve()
        if resolved.parent.name == "bin":
            return str(resolved.parent.parent)
    return None


def _java_configuration_paths(java_home: str) -> tuple[Path, ...]:
    """Return narrow external targets of distribution-managed JDK symlinks."""
    home = Path(java_home)
    roots = []
    for directory in (home / "conf", home / "lib"):
        if not directory.is_dir():
            continue
        for link in directory.rglob("*"):
            if not link.is_symlink():
                continue
            target = link.resolve()
            parts = target.parts
            if len(parts) >= 3 and parts[:2] == ("/", "etc"):
                if parts[2].startswith("java-"):
                    root = Path("/etc") / parts[2]
                elif parts[2:5] == ("ssl", "certs", "java"):
                    root = Path("/etc/ssl/certs/java")
                else:
                    continue
                if root.exists() and root not in roots:
                    roots.append(root)
    return tuple(roots)


def _kani_tool_paths(kani: Path) -> tuple[Path, ...]:
    root = kani.parent.parent if kani.parent.name == "bin" else kani.parent
    paths = [root]
    toolchain = root / "toolchain"
    if toolchain.exists():
        target = toolchain.resolve()
        if target != root:
            paths.append(target)
    return tuple(paths)


def _framac_provers() -> tuple[tuple[Path, ...], dict[str, str], dict[str, Any] | None]:
    builtins = {"native", "none", "qed", "script", "tip"}
    binaries = []
    for name in (item.strip() for item in config.FRAMAC_PROVERS.split(",")):
        if not name or name.lower() in builtins:
            continue
        found = shutil.which(name)
        if found is None:
            return (), {}, {
                "status": "PROVER_MISSING", "exit_code": 127,
                "claim": "NO_PROOF",
                "message": f"Frama-C prover executable not found: {name}",
            }
        binaries.append(Path(found).absolute())
    if not binaries:
        return (), {}, None
    search = ":".join(dict.fromkeys(str(path.parent) for path in binaries))
    return tuple(binaries), {"PATH": f"{search}:/usr/bin:/bin"}, None


def _run(
        files: dict[str, str | bytes], command: list[str], tool: str, timeout: int,
        executor: StrictSandboxExecutor | None, readonly_paths: tuple[Path, ...] = (),
        *, memory: int = 2 * 1024 * 1024 * 1024,
        processes: int = 32,
        environment: dict[str, str] | None = None) -> ExecutionObservation:
    with tempfile.TemporaryDirectory(prefix=f"formalspecgen-{tool}-") as directory:
        root = Path(directory)
        snapshot = SourceSnapshot.create(root / "snapshot", files)
        return (executor or StrictSandboxExecutor()).execute(ExecutionRequest(
            tool=tool, command=tuple(command), snapshot=snapshot,
            workspace=root / "workspace",
            policy=ExecutionPolicy(
                timeout_s=float(timeout), max_memory_bytes=memory,
                max_processes=processes),
            environment=environment or {},
            readonly_paths=readonly_paths,
        ))


def _infrastructure_failure(observation: ExecutionObservation) -> dict[str, Any] | None:
    if observation.policy_compliance != "ENFORCED":
        return {
            "status": observation.status, "exit_code": 125, "claim": "NO_PROOF",
            "output": observation.output, "message": observation.message,
            "request_satisfied": False,
        }
    if observation.status in _RESOURCE_FAILURES:
        return {
            "status": observation.status, "exit_code": observation.exit_code or 125,
            "claim": "NO_PROOF", "output": observation.output,
            "message": observation.message, "request_satisfied": False,
        }
    return None


def _tool_initialization_failure(
        observation: ExecutionObservation) -> dict[str, Any] | None:
    output = observation.output.lower()
    if observation.exit_code != 0 and any(
            marker in output for marker in _TOOL_INITIALIZATION_MARKERS):
        return {
            "status": "TOOL_INITIALIZATION_FAILED", "exit_code": 125,
            "claim": "NO_PROOF", "output": observation.output,
            "message": "the verifier or its runtime did not initialize",
            "request_satisfied": False,
        }
    return None


def _verify_rust(
        path: Path, mode: str, backend: str,
        executor: StrictSandboxExecutor | None) -> IsolatedVerificationResult:
    code = path.read_text(encoding="utf-8")
    warnings = lint_rust(code)
    if any(item.get("severity") == "error" for item in warnings):
        return IsolatedVerificationResult({
            "status": "RUST_LINT_FAILED", "exit_code": 2, "claim": "NO_PROOF",
            "language": "rust", "warnings": warnings,
        })
    if mode in {"parse", "check"}:
        rustc, missing = _resolve_tool(config.RUSTC_BIN, "rustc")
        if missing:
            return IsolatedVerificationResult({**missing, "language": "rust", "warnings": warnings})
        erased = re.sub(r"(?m)^\s*use\s+prusti_contracts::\*;\s*$", "", code)
        erased = _PRUSTI_ATTRIBUTE.sub("", erased)
        command = [str(rustc), "--crate-type", "lib", "--edition", "2021"]
        if mode == "parse":
            command.extend(["--emit", "metadata", "-o", "/work/lib.rmeta"])
        else:
            command.extend(["--emit", "metadata", "-D", "warnings", "-o", "/work/lib.rmeta"])
        command.append("/input/candidate.rs")
        rust_environment = {
            name: value for name in ("RUSTUP_HOME", "CARGO_HOME")
            if (value := os.environ.get(name))
        }
        observation = _run(
            {f"reviewed/{path.name}": code, "candidate.rs": erased},
            command, "rustc", 60,
            executor, _rust_tool_paths(rustc, rust_environment),
            environment=rust_environment)
        failure = _infrastructure_failure(observation)
        failure = failure or _tool_initialization_failure(observation)
        payload = failure or {
            "status": ("PARSED" if mode == "parse" else "RUST_CHECKED")
                      if observation.exit_code == 0 else "RUST_CHECK_FAILED",
            "exit_code": observation.exit_code,
            "claim": "NO_PROOF", "output": observation.output[-12000:],
        }
        return IsolatedVerificationResult(
            {**payload, "language": "rust", "warnings": warnings,
             "tool_identities": [_tool_identity(rustc)]}, (observation,))
    if backend == "kani":
        return _verify_kani(path, code, warnings, executor)
    prusti, missing = _resolve_tool(config.PRUSTI_BIN, "Prusti")
    if missing:
        return IsolatedVerificationResult({**missing, "language": "rust", "warnings": warnings})
    rust_environment = {
        name: value for name in ("RUSTUP_HOME", "CARGO_HOME")
        if (value := os.environ.get(name))
    }
    java_paths = ()
    if java_home := _java_home():
        rust_environment["JAVA_HOME"] = java_home
        java_paths = _java_configuration_paths(java_home)
    if rust_environment.get("CARGO_HOME"):
        rust_environment["PATH"] = (
            f"{rust_environment['CARGO_HOME']}/bin:/usr/bin:/bin")
    observation = _run(
        {path.name: code},
        [str(prusti), "--edition=2021", "--crate-type", "lib", f"/input/{path.name}"],
        "prusti", config.PRUSTI_TIMEOUT, executor,
        (*_rust_tool_paths(prusti, rust_environment), *java_paths),
        processes=128, environment=rust_environment)
    failure = _infrastructure_failure(observation)
    failure = failure or _tool_initialization_failure(observation)
    if failure:
        return IsolatedVerificationResult(
            {**failure, "language": "rust", "warnings": warnings,
             "tool_identities": [_tool_identity(prusti)]}, (observation,))
    vcs = parse_prusti_vcs(observation.output)
    status = "VERIFIED" if observation.exit_code == 0 else "VERIFY_FAILED"
    if status == "VERIFIED" and not _PRUSTI_OBLIGATION.search(code):
        status = "VACUOUS_VERIFIED"
    return IsolatedVerificationResult({
        "status": status, "exit_code": observation.exit_code,
        "claim": "DEDUCTIVE_PROOF" if status == "VERIFIED" else "NO_PROOF",
        "language": "rust", "warnings": warnings,
        "tool_identities": [_tool_identity(prusti)],
        "vcs": [item.__dict__ for item in vcs], "output": observation.output[-12000:],
    }, (observation,))


def _verify_kani(
        path: Path, code: str, warnings: list[dict],
        executor: StrictSandboxExecutor | None) -> IsolatedVerificationResult:
    harnesses = kani_harnesses(code)
    if not harnesses:
        return IsolatedVerificationResult({
            "status": "HARNESS_REQUIRED", "exit_code": 2, "claim": "NO_PROOF",
            "language": "rust", "bounded": True, "harnesses": [], "warnings": warnings,
        })
    configured = config.KANI_BIN
    if configured == "cargo":
        configured = "kani-driver" if shutil.which("kani-driver") else "kani"
    kani, missing = _resolve_tool(configured, "Kani")
    if missing:
        return IsolatedVerificationResult({**missing, "language": "rust", "warnings": warnings})
    cleaned = re.sub(r"(?m)^\s*use\s+prusti_contracts::\*;\s*$", "", code)
    cleaned = _PRUSTI_ATTRIBUTE.sub("", cleaned)
    files = {
        f"reviewed/{path.name}": code,
        "Cargo.toml": '[package]\nname="formalspecgen_kani"\nversion="0.0.0"\nedition="2021"\n',
        "src/lib.rs": cleaned,
    }
    # The managed driver accepts a crate copied into the disposable workspace.
    command = [
        "/bin/sh", "-c",
        "cp -R /input/. /work && exec \"$1\" --tests /work/src/lib.rs",
        "kani", str(kani),
    ]
    observation = _run(
        files, command, "kani", config.KANI_TIMEOUT, executor,
        _kani_tool_paths(kani),
        memory=3 * 1024 * 1024 * 1024,
        environment={"PATH": f"{kani.parent}:/usr/bin:/bin"})
    failure = _infrastructure_failure(observation)
    failure = failure or _tool_initialization_failure(observation)
    if failure:
        return IsolatedVerificationResult(
            {**failure, "language": "rust", "warnings": warnings,
             "bounded": True, "harnesses": harnesses,
             "tool_identities": [_tool_identity(kani)]}, (observation,))
    checked = verified_property_count(observation.output) if observation.exit_code == 0 else None
    status = "VERIFIED" if observation.exit_code == 0 and checked else (
        "VACUOUS_VERIFIED" if observation.exit_code == 0 else "VERIFY_FAILED")
    return IsolatedVerificationResult({
        "status": status, "exit_code": observation.exit_code,
        "claim": "BOUNDED_RUST_EVIDENCE" if status == "VERIFIED" else "NO_PROOF",
        "language": "rust", "bounded": True, "harnesses": harnesses,
        "verified_properties": checked, "warnings": warnings,
        "tool_identities": [_tool_identity(kani)],
        "diagnostics": parse_kani_diagnostics(observation.output),
        "output": observation.output[-12000:],
    }, (observation,))


def _verify_c(
        path: Path, executor: StrictSandboxExecutor | None) -> IsolatedVerificationResult:
    code = path.read_text(encoding="utf-8")
    warnings = lint_acsl(code)
    if any(item.get("severity") == "error" for item in warnings):
        return IsolatedVerificationResult({
            "status": "ACSL_LINT_FAILED", "exit_code": 2, "claim": "NO_PROOF",
            "language": "c", "warnings": warnings,
        })
    compiler, missing = _resolve_tool(config.CC_BIN, "C compiler")
    if missing:
        return IsolatedVerificationResult({**missing, "language": "c", "warnings": warnings})
    files = {path.name: code}
    compiled = _run(
        files, [str(compiler), "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-fsyntax-only", f"/input/{path.name}"],
        "c-compiler", config.FRAMAC_TIMEOUT, executor, _readonly_tool_root(compiler))
    failure = _infrastructure_failure(compiled)
    failure = failure or _tool_initialization_failure(compiled)
    if failure or compiled.exit_code:
        payload = failure or {
            "status": "C_COMPILE_FAILED", "exit_code": compiled.exit_code,
            "claim": "NO_PROOF", "output": compiled.output[-12000:],
        }
        return IsolatedVerificationResult(
            {**payload, "language": "c", "warnings": warnings,
             "tool_identities": [_tool_identity(compiler)]}, (compiled,))
    framac, missing = _resolve_tool(config.FRAMAC_BIN, "Frama-C")
    if missing:
        return IsolatedVerificationResult(
            {**missing, "language": "c", "warnings": warnings,
             "tool_identities": [_tool_identity(compiler)]}, (compiled,))
    prover_paths, prover_environment, missing_prover = _framac_provers()
    if missing_prover:
        return IsolatedVerificationResult(
            {**missing_prover, "language": "c", "warnings": warnings,
             "tool_identities": [_tool_identity(compiler), _tool_identity(framac)]},
            (compiled,))
    command = [str(framac), "-wp", "-wp-rte", "-wp-prover", config.FRAMAC_PROVERS,
               f"/input/{path.name}"]
    proved = _run(files, command, "frama-c", config.FRAMAC_TIMEOUT, executor,
                  (*_readonly_tool_root(framac), *prover_paths),
                  memory=3 * 1024 * 1024 * 1024,
                  environment=prover_environment)
    failure = _infrastructure_failure(proved)
    failure = failure or _tool_initialization_failure(proved)
    if failure:
        return IsolatedVerificationResult(
            {**failure, "language": "c", "warnings": warnings,
             "tool_identities": [
                 _tool_identity(compiler), _tool_identity(framac),
                 *(_tool_identity(path) for path in prover_paths)]},
            (compiled, proved))
    summaries = _FRAMAC_PROVED.findall(proved.output)
    goals, total = (tuple(map(int, summaries[-1])) if summaries else (0, 0))
    verified = proved.exit_code == 0 and total > 0 and goals == total
    return IsolatedVerificationResult({
        "status": "VERIFIED" if verified else "VERIFY_FAILED",
        "exit_code": proved.exit_code,
        "claim": "DEDUCTIVE_PROOF" if verified else "NO_PROOF",
        "language": "c", "proved_goals": goals, "total_goals": total,
        "warnings": warnings, "provers": config.FRAMAC_PROVERS.split(","),
        "tool_identities": [
            _tool_identity(compiler), _tool_identity(framac),
            *(_tool_identity(path) for path in prover_paths)],
        "vcs": [item.__dict__ for item in parse_framac_vcs(proved.output)],
        "output": proved.output[-12000:],
    }, (compiled, proved))


def _verify_cpp(
        path: Path, executor: StrictSandboxExecutor | None) -> IsolatedVerificationResult:
    esbmc, missing = _resolve_tool("esbmc", "ESBMC")
    if missing:
        return IsolatedVerificationResult({**missing, "language": "cpp"})
    code = path.read_text(encoding="utf-8")
    files = {path.name: code}
    target = f"/input/{path.name}"
    class_match = re.search(r"\bclass\s+([A-Za-z_]\w*)\s*\{", code)
    has_main = re.search(r"\b(?:int|auto)\s+main\s*\(", code) is not None
    if class_match is not None and not has_main:
        class_name = class_match.group(1)
        methods = [name for name in re.findall(
            r"\b(?:void|bool|int|long|float|double|[A-Za-z_]\w*)\s+"
            r"([A-Za-z_]\w*)\s*\(\s*\)\s*\{", code) if name != "check_invariants"]
        calls = "\n".join(f"    object.{name}();" for name in methods)
        files["harness.cpp"] = (
            f'#include "{path.name}"\nint main() {{\n    {class_name} object;\n'
            f"{calls}\n    return 0;\n}}\n")
        target = "/input/harness.cpp"
    command = [str(esbmc), target, "--unwind", "5", "--memory-leak-check",
               "--force-malloc-success", "--z3"]
    observation = _run(
        files, command, "esbmc", 180, executor, _readonly_tool_root(esbmc),
        memory=3 * 1024 * 1024 * 1024)
    failure = _infrastructure_failure(observation)
    failure = failure or _tool_initialization_failure(observation)
    if failure:
        return IsolatedVerificationResult({
            **failure, "language": "cpp",
            "tool_identities": [_tool_identity(esbmc)]}, (observation,))
    success = observation.exit_code == 0 and "verification successful" in observation.output.lower()
    return IsolatedVerificationResult({
        "status": "VERIFIED" if success else "VERIFY_FAILED",
        "exit_code": observation.exit_code,
        "claim": "BOUNDED_CPP_PROOF" if success else "NO_PROOF",
        "language": "cpp", "bounded": True, "unwind": 5,
        "tool_identities": [_tool_identity(esbmc)],
        "unbounded_loop_proved": False,
        "vcs": [] if success else [item.__dict__ for item in parse_esbmc_vcs(observation.output)],
        "output": observation.output[-12000:],
    }, (observation,))
