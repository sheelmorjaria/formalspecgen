# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M74 Z3 mitigation completeness and declared WCET-budget gate."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path


HAZARDS = ("MDS", "TAA", "L1TF", "SRSO", "BHI")
MITIGATIONS = ("verw_clear", "tsx_disabled", "pte_inversion",
               "srso_safe_ret", "eibrs_bhb_clear", "smt_disabled")


def _fail(code: str, message: str = "") -> dict:
    return {"status": "MICROARCH_POLICY_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def verify_microarch_policy(path: str | Path, profile: dict) -> dict:
    artifact_path = Path(path)
    try:
        raw = artifact_path.read_bytes()
        artifact = json.loads(raw)
        hazards = artifact["hazards"]
        selected = artifact["selected_mitigations"]
        costs = artifact["declared_cycle_costs"]
        cpuid = artifact["cpuid"]
        microcode = artifact["microcode"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _fail("MICROARCH_POLICY_ARTIFACT_INVALID", str(exc))
    if profile.get("target") != "n150" or profile.get("memory_model") != "x86_tso":
        return _fail("MICROARCH_PROFILE_MISMATCH")
    if set(hazards) != set(HAZARDS) or set(selected) != set(MITIGATIONS) \
            or set(costs) != set(MITIGATIONS):
        return _fail("MICROARCH_POLICY_SET_INCOMPLETE")
    if not all(isinstance(value, bool) for value in hazards.values()) \
            or not all(isinstance(value, bool) for value in selected.values()):
        return _fail("MICROARCH_POLICY_VALUE_INVALID")
    if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0
               for value in costs.values()):
        return _fail("MITIGATION_COST_INVALID")
    if artifact.get("profile_source") != "human_declared_not_runtime_cpuid" \
            or microcode.get("runtime_revision_validated") is not False \
            or artifact.get("measured_cost_validated") is not False \
            or artifact.get("speculative_noninterference_proved") is not False:
        return _fail("MICROARCH_EPISTEMIC_BOUNDARY_INVALID")
    if microcode.get("declared_revision", -1) < microcode.get(
            "minimum_reviewed_revision", 0):
        return _fail("MICROCODE_REVISION_BELOW_POLICY")
    if selected["verw_clear"] and cpuid.get("md_clear_available") is not True:
        return _fail("MITIGATION_CAPABILITY_UNAVAILABLE", "MD_CLEAR unavailable")
    if selected["eibrs_bhb_clear"] and cpuid.get("ibrs_available") is not True:
        return _fail("MITIGATION_CAPABILITY_UNAVAILABLE", "IBRS unavailable")
    expected = {
        "MDS": "verw_clear", "TAA": "tsx_disabled",
        "L1TF": "pte_inversion", "SRSO": "srso_safe_ret",
        "BHI": "eibrs_bhb_clear"}
    lines = ["(set-logic QF_UF)"]
    for name in HAZARDS:
        lines.append(f"(declare-const hazard_{name} Bool)")
    for name in MITIGATIONS:
        lines.append(f"(declare-const mitigation_{name} Bool)")
    for name, value in hazards.items():
        lines.append(f"(assert (= hazard_{name} {'true' if value else 'false'}))")
    for name, value in selected.items():
        lines.append(f"(assert (= mitigation_{name} {'true' if value else 'false'}))")
    violations = [f"(and hazard_{hazard} (not mitigation_{mitigation}))"
                  for hazard, mitigation in expected.items()]
    if cpuid.get("smt_enabled") is True:
        violations.append("(not mitigation_smt_disabled)")
    lines.extend([f"(assert (or {' '.join(violations)}))", "(check-sat)"])
    smt = "\n".join(lines) + "\n"
    z3 = shutil.which("z3")
    if z3 is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "z3_unavailable", "judge_pending": "z3"}
    try:
        run = subprocess.run([z3, "-in"], input=smt, capture_output=True,
                             text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _fail("MICROARCH_Z3_EXECUTION_FAILED", str(exc))
    if run.returncode != 0 or run.stdout.strip() != "unsat":
        return _fail("MICROARCH_MITIGATION_INCOMPLETE", run.stdout + run.stderr)
    total_cost = sum(costs[name] for name in MITIGATIONS if selected[name])
    budget = artifact.get("mitigation_budget_cycles")
    if not isinstance(budget, int) or isinstance(budget, bool) or total_cost > budget:
        return _fail("MITIGATION_WCET_BUDGET_EXCEEDED",
                     f"declared cost {total_cost} exceeds budget {budget}")
    return {
        "status": "MICROARCH_MITIGATION_POLICY_PROVED",
        "claims": ["MICROARCH_MITIGATION_POLICY_PROVED",
                   "MITIGATION_WCET_BUDGET_PROVED"],
        "judge": "z3+deterministic_cost_equation",
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "smt_sha256": hashlib.sha256(smt.encode()).hexdigest(),
        "selected_mitigations": sorted(name for name in MITIGATIONS
                                        if selected[name]),
        "declared_cost_cycles": total_cost, "budget_cycles": budget,
        "runtime_cpuid_validated": False,
        "runtime_microcode_validated": False,
        "measured_cost_validated": False,
        "speculative_noninterference_proved": False,
    }
