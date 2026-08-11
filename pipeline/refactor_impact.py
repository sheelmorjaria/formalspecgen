# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0

"""Contract-diff impact tracing and affected-scaffold re-verification."""
import tempfile
from pathlib import Path

from .architecture import parse_architecture
from .jml_io import clause_diff
from .verify import verify_files, classify, has_dropped_vc
from .parse_check import parse_check
from .parse_vcs import parse_vcs


def analyze_refactor(architecture_value, before_files: dict[str, str],
                     after_files: dict[str, str]) -> dict:
    architecture = parse_architecture(architecture_value)
    changed = []
    diffs = {}
    all_names = sorted(set(before_files) | set(after_files))
    for name in all_names:
        diff = clause_diff(before_files.get(name, ""), after_files.get(name, ""))
        if diff["added"] or diff["removed"]:
            changed.append(name)
            diffs[name] = diff
    component_by_file = {f"{component.name}.java": component.id for component in architecture.components}
    seeds = {component_by_file[name] for name in changed if name in component_by_file}
    reverse = {component.id: set() for component in architecture.components}
    for component in architecture.components:
        for dependency in component.dependencies:
            reverse.setdefault(dependency.target, set()).add(component.id)
    impacted = set(seeds)
    frontier = list(seeds)
    while frontier:
        current = frontier.pop()
        for dependent in reverse.get(current, set()):
            if dependent not in impacted:
                impacted.add(dependent); frontier.append(dependent)
    use_cases = [use_case.name for use_case in architecture.use_cases
                 if any(step.component in impacted for step in use_case.steps)]
    orchestrators = [f"{_java_name(name)}Orchestrator.java" for name in use_cases]
    verification = _verify_sources(after_files) if changed else {
        "check_status": "SKIPPED", "esc_status": "SKIPPED", "diagnostics": []}
    return {"status": "UNCHANGED" if not changed else
            "REVERIFIED" if verification["esc_status"] == "VERIFIED" else "REVERIFICATION_FAILED",
            "changed_contract_files": changed, "diffs": diffs,
            "impacted_components": sorted(impacted), "impacted_use_cases": use_cases,
            "impacted_orchestrators": orchestrators, "verification": verification}


def _verify_sources(files: dict[str, str]) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        paths = []
        for name, source in files.items():
            path = root / Path(name).name
            path.write_text(source, encoding="utf-8"); paths.append(path)
        check_exit, check_output = verify_files(paths, mode="check")
        if check_exit != 0:
            return {"check_status": classify(check_exit), "esc_status": "SKIPPED",
                    "diagnostics": [item.__dict__ for item in parse_check(check_output)]}
        esc_exit, esc_output = verify_files(paths, mode="esc")
        esc_status = classify(esc_exit)
        if esc_status == "VERIFIED" and has_dropped_vc(esc_output):
            esc_status = "VACUOUS_VERIFIED"
        diagnostics = parse_vcs(esc_output) if esc_exit == 6 else parse_check(esc_output)
        return {"check_status": "VERIFIED", "esc_status": esc_status,
                "diagnostics": [item.__dict__ for item in diagnostics]}


def _java_name(value: str) -> str:
    import re
    return "".join(word[:1].upper() + word[1:] for word in re.findall(r"[A-Za-z0-9]+", value)) or "UseCase"
