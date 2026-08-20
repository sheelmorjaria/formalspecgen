# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Installed-wheel integrity: no source-checkout resource fallbacks allowed."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from pipeline import config


def test_resource_path_supports_standard_virtualenv_data_layout(tmp_path, monkeypatch):
    package_root = tmp_path / "site-packages"
    prefix = tmp_path / "venv"
    resource = prefix / "security" / "cwe_manifest.json"
    resource.parent.mkdir(parents=True)
    resource.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(config, "ROOT", package_root)
    monkeypatch.setattr(config.sys, "prefix", str(prefix))
    assert config.resource_path("security", "cwe_manifest.json") == resource


def test_wheel_runs_from_empty_directory_with_runtime_data(tmp_path):
    project = Path(__file__).resolve().parents[1]
    wheels = tmp_path / "wheels"
    target = tmp_path / "installed"
    empty = tmp_path / "empty"
    wheels.mkdir(); target.mkdir(); empty.mkdir()
    built = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(project), "--no-deps",
         "--no-build-isolation", "--wheel-dir", str(wheels)],
        capture_output=True, text=True, timeout=120)
    assert built.returncode == 0, (built.stdout + built.stderr)[-4000:]
    wheel = next(wheels.glob("formalspecgen-*.whl"))
    installed = subprocess.run(
        [sys.executable, "-m", "pip", "install", str(wheel), "--no-deps",
         "--target", str(target)], capture_output=True, text=True, timeout=120)
    assert installed.returncode == 0, (installed.stdout + installed.stderr)[-4000:]

    script = r'''
import json
from pathlib import Path
import mcp_server
from pipeline import config
from pipeline.cwe_registry import entries
from pipeline.doctor import inspect_environment
from pipeline.scaffold_domain import load_spec

root = Path(config.ROOT)
elevator = load_spec(root / "domains/elevator_controller.yaml")
domain = json.loads((root / "domains/v2/inventory.json").read_text(encoding="utf-8"))
report = inspect_environment(runner=lambda command, **kwargs: __import__("subprocess").CompletedProcess(command, 0, "tool 1.0", ""),
                             which=lambda name: "/bin/true")
assert len(entries()) > 0
assert elevator.domain_name == "ElevatorController"
assert domain["domain_name"]
assert report["domains"]
assert (root / "security/cwe_manifest.json").is_file()
assert (root / "ci/rust-deps/Cargo.lock").is_file()
assert callable(mcp_server.create_server)
import tree_sitter, tree_sitter_java, tree_sitter_rust, tree_sitter_c, tree_sitter_cpp
print(json.dumps({"root": str(root), "domain": domain["domain_name"],
                  "elevator": elevator.domain_name, "cwes": len(entries())}))
'''
    environment = os.environ.copy()
    # pytest-cov instruments subprocesses through these variables. The wheel
    # smoke process is a separate installed artifact, not a second source tree
    # to merge into the unit-suite coverage denominator.
    for name in list(environment):
        if name.startswith(("COVERAGE_", "COV_CORE_")):
            environment.pop(name)
    environment["PYTHONPATH"] = str(target)
    checked = subprocess.run([sys.executable, "-c", script], cwd=empty,
                             env=environment, capture_output=True, text=True, timeout=30)
    assert checked.returncode == 0, (checked.stdout + checked.stderr)[-4000:]
    result = json.loads(checked.stdout.strip().splitlines()[-1])
    assert Path(result["root"]).resolve() == target.resolve()
    assert result["cwes"] > 0
    doctor = subprocess.run(
        [sys.executable, "-m", "pipeline.cli", "doctor", "--json", "-"],
        cwd=empty, env=environment, capture_output=True, text=True, timeout=30)
    assert doctor.returncode == 0, (doctor.stdout + doctor.stderr)[-4000:]
    doctor_report = json.loads(doctor.stdout)
    assert doctor_report["claim"] == "NO_PROOF"
    assert doctor_report["domains"]
