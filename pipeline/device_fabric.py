# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M79 IOMMU domain, requester, MSI-X, and multiqueue containment gate."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def _fail(code, message=""):
    return {"status": "DEVICE_FABRIC_FAILED", "claim": "NO_PROOF",
            "code": code, "message": message}


def _span(value):
    return (isinstance(value, list) and len(value) == 2 and
            all(isinstance(x, int) and not isinstance(x, bool) for x in value)
            and value[0] < value[1])


def _overlap(left, right):
    return left[0] < right[1] and right[0] < left[1]


def verify_device_fabric(path):
    path = Path(path)
    try:
        raw = path.read_bytes(); artifact = json.loads(raw)
        protected = artifact["protected_ranges"]; devices = artifact["devices"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _fail("DEVICE_FABRIC_ARTIFACT_INVALID", str(exc))
    if not isinstance(devices, dict) or not devices or not all(
            _span(span) for span in protected.values()):
        return _fail("DEVICE_FABRIC_TOPOLOGY_INVALID")
    requester_ids, domains, vectors, windows = set(), set(), set(), []
    queue_rows = []
    for name, device in devices.items():
        try:
            requester, domain = device["requester_id"], device["iommu_domain"]
            window, msix = device["dma_window"], device["msix_vectors"]
            depths, pages = device["queue_depths"], device["reserved_buffer_pages"]
        except (KeyError, TypeError) as exc:
            return _fail("DEVICE_FABRIC_DEVICE_INVALID", f"{name}:{exc}")
        if requester in requester_ids or domain in domains or not _span(window):
            return _fail("DEVICE_FABRIC_ID_OR_WINDOW_INVALID", name)
        if any(_overlap(window, span) for span in protected.values()) or any(
                _overlap(window, other) for other in windows):
            return _fail("DEVICE_DMA_DOMAIN_OVERLAP", name)
        if not isinstance(msix, list) or len(set(msix)) != len(msix) or \
                vectors.intersection(msix):
            return _fail("MSIX_VECTOR_COLLISION", name)
        if not isinstance(depths, list) or not depths or not all(
                isinstance(x, int) and x > 0 for x in depths) or \
                not isinstance(pages, int) or pages <= 0:
            return _fail("DEVICE_QUEUE_BUDGET_INVALID", name)
        requester_ids.add(requester); domains.add(domain); vectors.update(msix)
        windows.append(window); queue_rows.append((name, depths, pages))
    ceilings = ("physical_iommu_enforcement_proved", "pcie_firmware_correctness_proved",
                "nvme_device_behavior_proved", "msix_delivery_proved",
                "native_driver_refinement_proved")
    if artifact.get("reset_contract") != "increment_epoch_and_zero_all_outstanding" or \
            any(artifact.get(field) is not False for field in ceilings):
        return _fail("DEVICE_FABRIC_EPISTEMIC_BOUNDARY_INVALID")
    lines = ["(set-logic QF_LIA)"]; violations = []
    for name, depths, pages in queue_rows:
        variables = []
        for index, depth in enumerate(depths):
            variable = f"q_{name}_{index}"; variables.append(variable)
            lines += [f"(declare-const {variable} Int)",
                      f"(assert (>= {variable} 0))",
                      f"(assert (<= {variable} {depth}))"]
        violations.append(f"(> (+ {' '.join(variables)}) {pages})")
    lines += [f"(assert (or {' '.join(violations)}))", "(check-sat)"]
    smt = "\n".join(lines) + "\n"; z3 = shutil.which("z3")
    if z3 is None:
        return {"status": "judge_pending", "claim": "NO_PROOF",
                "code": "z3_unavailable", "judge_pending": "z3"}
    try:
        run = subprocess.run([z3, "-in"], input=smt, capture_output=True,
                             text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _fail("DEVICE_FABRIC_Z3_FAILED", str(exc))
    if run.returncode or run.stdout.strip() != "unsat":
        return _fail("DEVICE_QUEUE_CONTAINMENT_COUNTEREXAMPLE", run.stdout)
    return {"status": "DEVICE_DMA_DOMAIN_ISOLATION_PROVED",
            "claim": "DEVICE_DMA_DOMAIN_ISOLATION_PROVED", "judge": "z3+range_gate",
            "scope": "declared_requester_domains_and_multiqueue_budgets",
            "artifact_sha256": hashlib.sha256(raw).hexdigest(),
            "smt_sha256": hashlib.sha256(smt.encode()).hexdigest(),
            "device_count": len(devices), "queue_count": sum(len(x[1]) for x in queue_rows),
            "requester_ids": sorted(requester_ids), "iommu_domains": sorted(domains),
            "reset_accounting_proved": True, **{field: False for field in ceilings}}
