import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def _fail(code, message=""):
    return {"status": "COMPATIBILITY_OPERATIONS_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def verify_compatibility_operations(path):
    path = Path(path)
    try:
        raw = path.read_bytes()
        artifact = json.loads(raw)
        baseline_raw = (path.parent / artifact["baseline"]).read_bytes()
        baseline = json.loads(baseline_raw)
        source_path = path.parent / artifact["implementation"]
        source_raw = source_path.read_bytes()
        source = source_raw.decode("utf-8")
    except (OSError, ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        return _fail("COMPATIBILITY_ARTIFACT_INVALID", str(exc))
    if artifact.get("abi_version") != baseline.get("abi_version") or \
            artifact.get("calls") != baseline.get("calls"):
        return _fail("ABI_BASELINE_DRIFT")
    calls = artifact["calls"]
    if [call.get("number") for call in calls] != [200, 201, 202, 203, 204] or \
            [call.get("name") for call in calls] != ["open", "read", "write", "close", "exit"]:
        return _fail("ABI_NUMBER_OR_ORDER_INVALID")
    if len({call.get("number") for call in calls}) != len(calls):
        return _fail("ABI_NUMBER_COLLISION")
    for call in calls:
        if not re.search(rf"\b{re.escape(call['symbol'])}\s*\(", source):
            return _fail("ABI_IMPLEMENTATION_SYMBOL_MISSING", call["symbol"])
    expected_operations = {
        "trace_schema": ["timestamp", "pid", "syscall", "result"],
        "profile_counters": ["syscall_count", "bytes_read", "bytes_written"],
        "crash_dump_header": ["magic", "abi_version", "reason", "registers_sha256"],
        "upgrade_policy": {"minimum_version": 2, "rollback_target": "recovery"},
    }
    if artifact.get("operations") != expected_operations:
        return _fail("OPERATIONS_SCHEMA_INVALID")
    ceilings = ("full_posix_conformance_proved", "kernel_syscall_refinement_proved",
                "production_observability_proved", "atomic_field_upgrade_proved",
                "crash_dump_completeness_proved", "target_runtime_behavior_proved")
    if any(artifact.get(field) is not False for field in ceilings):
        return _fail("COMPATIBILITY_EPISTEMIC_BOUNDARY_INVALID")
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "c_compiler_unavailable", "judge_pending": "c_compiler"}
    harness = r'''#include <string.h>
int fk_open(const char*); int fk_read(int,char*,unsigned);
int fk_write(int,const char*,unsigned); int fk_close(int); void fk_exit(int);
int fk_observed_exit(void); unsigned fk_console_length(void);
int main(void) {
  char b[6] = {0}; int fd = fk_open("/hello");
  if (fd != 3 || fk_read(fd,b,5) != 5 || memcmp(b,"hello",5) != 0) return 10;
  if (fk_read(fd,b,1) != 0 || fk_close(fd) != 0 || fk_close(fd) != -1) return 11;
  if (fk_write(1,"ok",2) != 2 || fk_console_length() != 2) return 12;
  if (fk_open("/missing") != -1) return 13;
  fk_exit(7); return fk_observed_exit() == 7 ? 0 : 14;
}
'''
    try:
        with tempfile.TemporaryDirectory(prefix="formalspecgen-m85-") as directory:
            root = Path(directory)
            harness_path, executable = root / "harness.c", root / "posix-conformance"
            harness_path.write_text(harness)
            build = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                    str(source_path.resolve()), str(harness_path), "-o", str(executable)],
                                   capture_output=True, text=True, timeout=30)
            if build.returncode:
                return _fail("POSIX_SUBSET_BUILD_FAILED", build.stderr)
            run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _fail("POSIX_SUBSET_EXECUTION_FAILED", str(exc))
    if run.returncode:
        return _fail("POSIX_SUBSET_VECTOR_FAILED", str(run.returncode))
    evidence = {
        "judge": "deterministic_abi_gate+host_c_runtime",
        "scope": "five_call_host_compiled_compatibility_shim",
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "baseline_sha256": hashlib.sha256(baseline_raw).hexdigest(),
        "implementation_sha256": hashlib.sha256(source_raw).hexdigest(),
        "harness_sha256": hashlib.sha256(harness.encode()).hexdigest(),
        "compiler": compiler,
        "vectors_passed": 9,
        "operations_schemas_checked": True,
        **{field: False for field in ceilings},
    }
    return {"status": "COMPATIBILITY_OPERATIONS_EVIDENCE_READY",
            "claims": (
                {"claim": "ABI_STABILITY_CHECKED", **evidence},
                {"claim": "POSIX_CONFORMANCE_TESTED", **evidence},
            )}
