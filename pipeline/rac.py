# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""RAC + generated JUnit runtime evidence for failed ESC obligations.

This produces concrete execution evidence, not an SMT counterexample and not a proof.
"""
import re
import os
import subprocess
import tempfile
from pathlib import Path

from . import config, jml_io
from .llm import generate_rac_tests, _chat_fn, LLMError


_JUNIT_ASSERTIONS_IMPORT = "import static org.junit.jupiter.api.Assertions.*;"


def _normalize_junit_source(test_code: str) -> str:
    """Inject the assertion API import required by generated JUnit source."""
    if _JUNIT_ASSERTIONS_IMPORT in test_code:
        return test_code
    package = re.match(r"(?s)(\s*package\s+[\w.]+\s*;)", test_code)
    if package:
        end = package.end()
        return test_code[:end] + "\n\n" + _JUNIT_ASSERTIONS_IMPORT + test_code[end:]
    return _JUNIT_ASSERTIONS_IMPORT + "\n\n" + test_code.lstrip()


def collect_rac_evidence(code: str, diagnostics: str = "", provider: str = "glm") -> dict:
    class_name = jml_io.class_name(code)
    if not class_name:
        return {"status": "INVALID_SOURCE", "inputs": [], "message": "no public class found"}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / f"{class_name}.java"
        source.write_text(code, encoding="utf-8")
        compile_result = _run([config.OPENJML, "-rac", str(source), "-d", str(root)])
        if compile_result[0] != 0:
            return {"status": "RAC_COMPILE_FAILED", "inputs": [], "log": compile_result[1]}
        try:
            test_code, model, _usage = generate_rac_tests(
                code, class_name, diagnostics, chat_fn=_chat_fn(provider))
        except LLMError as exc:
            return {"status": "TESTGEN_ERROR", "inputs": [], "message": str(exc)}
        test_code = _normalize_junit_source(test_code)
        match = re.search(r"\bpublic\s+class\s+(\w+)", test_code)
        test_class = match.group(1) if match else f"Test{class_name}"
        test_file = root / f"{test_class}.java"
        test_file.write_text(test_code, encoding="utf-8")
        classpath = os.pathsep.join((str(root), config.JMLRUNTIME, config.JUNIT_JAR))
        test_compile = _run([config.JAVAC, "-cp", classpath, "-d", str(root), str(test_file)])
        if test_compile[0] != 0:
            return {"status": "TEST_COMPILE_FAILED", "inputs": [], "log": test_compile[1],
                    "test_code": test_code, "model": model}
        runtime_cp = os.pathsep.join((str(root), config.JMLRUNTIME))
        executed = _run([config.OPENJML_JAVA, "-jar", config.JUNIT_JAR,
                         "--class-path", runtime_cp, "--select-class", test_class,
                         "--details", "summary"])
        inputs = re.findall(r"FORMALSPEC_INPUT:\s*(.+)", executed[1])
        violations = [line.strip() for line in executed[1].splitlines()
                      if re.search(r"JML (?:postcondition|precondition|invariant|assertion)|verify:", line, re.I)]
        failed = _summary_count(executed[1], "tests failed")
        passed = _summary_count(executed[1], "tests successful")
        found = bool(failed or violations)
        return {"status": "RUNTIME_FAILURES_FOUND" if found else "NO_RUNTIME_FAILURE_FOUND",
                "inputs": inputs, "violations": violations[:20], "passed": passed, "failed": failed,
                "exit_code": executed[0], "log": executed[1][-6000:], "test_code": test_code,
                "model": model,
                "claim": "COUNTEREXAMPLE_EVIDENCE" if found else "RUNTIME_SAMPLE",
                "proof": False, "regeneration_recommended": found,
                "disclaimer": "RAC samples executions; absence of a failure is not a proof."}


def collect_integration_evidence(files: dict[str, str], provider: str = "glm") -> dict:
    """RAC-compile a complete scaffold and run generated orchestrator integration tests."""
    orchestrators = [name for name in files if name.endswith("Orchestrator.java")]
    if not orchestrators:
        return {"status": "NO_ORCHESTRATOR", "inputs": [], "message": "no orchestrator source found"}
    target = Path(orchestrators[0]).stem
    combined = "\n\n".join(f"// FILE: {name}\n{source}" for name, source in files.items())
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        paths = []
        for name, source in files.items():
            path = root / Path(name).name
            path.write_text(source, encoding="utf-8")
            paths.append(path)
        compiled = _run([config.OPENJML, "-rac", *map(str, paths), "-d", str(root)])
        if compiled[0] != 0:
            return {"status": "RAC_COMPILE_FAILED", "inputs": [], "log": compiled[1]}
        try:
            test_code, model, _usage = generate_rac_tests(
                combined, target, "Generate integration tests for contract composition and environmental failures.",
                chat_fn=_chat_fn(provider))
        except LLMError as exc:
            return {"status": "TESTGEN_ERROR", "inputs": [], "message": str(exc)}
        test_code = _normalize_junit_source(test_code)
        match = re.search(r"\bpublic\s+class\s+(\w+)", test_code)
        test_class = match.group(1) if match else f"Test{target}"
        test_file = root / f"{test_class}.java"
        test_file.write_text(test_code, encoding="utf-8")
        classpath = os.pathsep.join((str(root), config.JMLRUNTIME, config.JUNIT_JAR))
        test_compile = _run([config.JAVAC, "-cp", classpath, "-d", str(root), str(test_file)])
        if test_compile[0] != 0:
            return {"status": "TEST_COMPILE_FAILED", "inputs": [], "log": test_compile[1],
                    "test_code": test_code, "model": model}
        runtime_cp = os.pathsep.join((str(root), config.JMLRUNTIME))
        executed = _run([config.OPENJML_JAVA, "-jar", config.JUNIT_JAR,
                         "--class-path", runtime_cp, "--select-class", test_class,
                         "--details", "summary"])
        failed = _summary_count(executed[1], "tests failed")
        passed = _summary_count(executed[1], "tests successful")
        return {"status": "TESTS_PASSED" if passed and not failed else "TESTS_FAILED",
                "passed": passed, "failed": failed,
                "inputs": re.findall(r"FORMALSPEC_INPUT:\s*(.+)", executed[1]),
                "violations": [line.strip() for line in executed[1].splitlines()
                               if re.search(r"JML (?:postcondition|precondition|invariant|assertion)", line, re.I)][:20],
                "log": executed[1][-6000:], "test_code": test_code, "model": model,
                "disclaimer": "RAC integration tests are a runtime safety net, not a proof."}


def _run(command: list[str]) -> tuple[int, str]:
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=config.RAC_TIMEOUT)
        return process.returncode, (process.stdout or "") + (process.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"<command timed out after {config.RAC_TIMEOUT}s>"
    except FileNotFoundError as exc:
        return 127, f"<tool not found: {exc.filename}>"


def _summary_count(text: str, label: str) -> int:
    match = re.search(rf"\[\s*(\d+)\s+{re.escape(label)}\s*\]", text)
    return int(match.group(1)) if match else 0
