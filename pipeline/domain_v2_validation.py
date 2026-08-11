# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""End-to-end deterministic validation orchestration for V2 domain candidates."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .domain_v2_model import state_space_upper_bound, validate_transitions_and_invariants
from .domain_v2_promotion import candidate_sha256, load_candidate
from .domain_v2_publication import (
    TlcEvidence, ValidatedEvidence, publish_validation_failure, publish_validation_success,
)
from .domain_v2_tla import render_v2_tla
from .domain_v2_tools import get_tlc_provenance, require_tlc_provenance, run_tlc_artifacts


def _bounds(spec) -> dict[str, int | list[int]]:
    values: dict[str, int | list[int]] = {}
    for variable in spec.state_variables:
        values[variable.name] = (list(variable.bound) if hasattr(variable, "bound") else 2)
    values["actors"] = spec.actors
    return values


def validate_v2_candidate(candidate_path: str | Path, validation_path: str | Path, *,
                          failure_path: str | Path, tlc_jar: str, java: str = "java",
                          timeout: int = 120, runner=None) -> ValidatedEvidence:
    """Validate, model-check, and publish evidence for an immutable V2 candidate."""
    candidate = load_candidate(candidate_path)
    digest = candidate_sha256(candidate)
    gate = "schema"
    provenance: dict = {}
    try:
        gate = "bounded_traversal"
        states, transitions = validate_transitions_and_invariants(candidate)
        gate = "tla_render"
        tla, cfg = render_v2_tla(candidate)
        gate = "tlc_provenance"
        kwargs = {} if runner is None else {"runner": runner}
        provenance = require_tlc_provenance(get_tlc_provenance(
            tlc_jar, java=java, **kwargs))
        gate = "tlc"
        result = run_tlc_artifacts(tla, cfg, module_name=candidate.domain_name,
                                   tlc_jar=tlc_jar, java=java, timeout=timeout, **kwargs)
        if result.get("status") != "VERIFIED" or result.get("exit_status") != 0:
            raise RuntimeError(
                f"TLC did not verify candidate: {result.get('status')}\n"
                f"{result.get('output', result.get('diagnostic', ''))}")
        evidence = ValidatedEvidence(
            candidate_sha256=digest,
            generated_tla_sha256=hashlib.sha256(tla.encode("utf-8")).hexdigest(),
            execution_assumption="atomic_last_result_abstraction",
            abstraction_mode="atomic_operations",
            bounds=_bounds(candidate),
            state_space_upper_bound=state_space_upper_bound(candidate),
            reachable_state_count=states,
            reachable_transition_count=transitions,
            tools={"tlc": TlcEvidence(version=provenance["version"],
                                      command=provenance["command"])},
            tlc_exit_status=0,
        )
        publish_validation_success(validation_path, evidence)
        return evidence
    except Exception as exc:
        publish_validation_failure(failure_path, candidate_sha256=digest, failed_gate=gate,
                                   diagnostic=str(exc), tool_provenance=provenance)
        raise


def validate_domain(name: str, *, project_root: str | Path = ".",
                    tlc_jar: str | None = None, java: str | None = None,
                    timeout: int | None = None) -> ValidatedEvidence:
    """Validate a named CLI-layout candidate using the configured real TLC toolchain."""
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", name):
        raise ValueError("V2 domain name must be a safe module identifier")
    from . import config
    root = Path(project_root).resolve()
    candidate = root / "domains" / "candidates" / f"{name}.v2.yaml"
    return validate_v2_candidate(
        candidate,
        root / "domains" / "candidates" / f"{name}.v2.validation.json",
        failure_path=root / "domains" / "candidates" / f"{name}.v2.validation_failed.json",
        tlc_jar=tlc_jar or config.TLC_JAR,
        java=java or config.JAVA_BIN,
        timeout=timeout or config.TLC_TIMEOUT,
    )
