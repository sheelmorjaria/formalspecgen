# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Hand off a validated JML stub to formalspecDD (the dual project) to synthesize and
deductively verify the Java method bodies — closing the NL -> spec -> verified-Java loop.

The stub is ALREADY in DD's exact input format (JML-annotated skeleton, empty bodies), so a
handoff is just: write it to a .java file and emit the DD command. Optionally invoke DD's
orchestrator as a subprocess and return its verdict (HEAVY: LLM body-generation + `openjml -esc`,
typically minutes). formalspecDD is never modified.

This is the realistic "deep check": a meaningful ESC run needs method bodies, which is DD's job.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

from . import config, jml_io

DD_ROOT = Path(os.environ.get("FORMALSPEC_DD_ROOT", str(config.ROOT.parent / "formalspecDD")))


def _dd_python() -> str:
    configured = os.environ.get("FORMALSPEC_DD_PYTHON", "").strip()
    if configured:
        return configured
    if getattr(sys, "frozen", False):
        return "python" if os.name == "nt" else "python3"
    return sys.executable


def dd_available() -> bool:
    return (DD_ROOT / "pipeline" / "orchestrator.py").exists()


def handoff(stub, run_dd=False, timeout=300, expected_passes=None, backend="jml"):
    """Write `stub` to handoff/<ClassName>.java (DD input format) and emit the DD command.
    If run_dd, invoke DD's orchestrator (cwd=DD_ROOT) and return its verdict. Never raises."""
    cname = jml_io.class_name(stub)
    if not cname:
        return {"ok": False, "error": "no parseable public class in stub"}

    out_dir = config.ROOT / "handoff"
    out_dir.mkdir(parents=True, exist_ok=True)
    file = out_dir / f"{cname}.java"
    file.write_text(stub, encoding="utf-8")
    intent = {"spec": stub, "spec_file": str(file),
              "expected_passes": list(expected_passes or []), "backend": backend.upper()}
    intent_file = out_dir / f"{cname}.intent.json"
    intent_file.write_text(json.dumps(intent, indent=2, ensure_ascii=False), encoding="utf-8")
    python = _dd_python()
    cmd = f"cd {DD_ROOT} && FORMALSPEC_INTENT_PATH={intent_file} {python} -m pipeline.orchestrator {file}"

    res = {"ok": True, "class_name": cname, "file": str(file), "dd_root": str(DD_ROOT),
           "dd_available": dd_available(), "dd_command": cmd, "dd_verdict": None}
    res.update({"intent": intent, "intent_file": str(intent_file)})

    if run_dd and dd_available():
        verdict_dir = out_dir / f"{cname}_ddrun"
        verdict_dir.mkdir(parents=True, exist_ok=True)
        try:
            child_env = os.environ.copy()
            child_env["FORMALSPEC_INTENT_PATH"] = str(intent_file)
            p = subprocess.run(
                [python, "-m", "pipeline.orchestrator", str(file), "--out", str(verdict_dir)],
                cwd=str(DD_ROOT), capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout, env=child_env)
            vj = verdict_dir / "verdict.json"
            res["dd_verdict"] = json.loads(vj.read_text(encoding="utf-8")) if vj.exists() else None
            implementation_path = ((res["dd_verdict"] or {}).get("stub_path") or
                                   (res["dd_verdict"] or {}).get("source_path"))
            if implementation_path and Path(implementation_path).exists():
                res["implementation_code"] = Path(implementation_path).read_text(encoding="utf-8")
            res["dd_exit"] = p.returncode
            res["dd_stdout_tail"] = (p.stdout or "")[-1000:]
        except subprocess.TimeoutExpired:
            res["dd_verdict"] = {"final_status": "TIMEOUT",
                                 "stop_reason": f"DD run exceeded {timeout}s"}
        except Exception as e:  # noqa: BLE001
            res["dd_verdict"] = {"final_status": "ERROR", "stop_reason": str(e)}
    return res
