"""M11: deterministic capacity bounding of V2 YAML candidates (C/Rust lane).

correct-behavior on a .v2.yaml target re-bounds the state machine to a
hardware profile's derived capacity — no LLM, the silicon chooses the number.
Proof stays downstream (validate-domain TLC -> promote -> Prusti), so the
command mints an APPLIED claim, never a PROVEN one.
"""
from __future__ import annotations

import json

import yaml

from pipeline.behavior_correction import correct_behavior


CANDIDATE = {
    "schema_version": 2,
    "module_name": "parser",
    "domain_name": "Parser",
    "review_status": "unreviewed",
    "state_variables": [
        {"kind": "int", "name": "pending", "bound": [0, 512], "initial": 0},
        {"kind": "int", "name": "bulklen", "bound": [-1, 512], "initial": -1},
        {"kind": "boolean", "name": "active", "initial": False},
        {"kind": "int", "name": "unbounded_counter", "initial": 0},
    ],
    "operations": [
        {"name": "enqueue", "return_type": "void", "failure_semantics": "unavailable",
         "guards": [{"id": "g1", "expression": {
             "kind": "lt",
             "left": {"kind": "field", "name": "pending"},
             "right": {"kind": "integer", "value": 512}}}],
         "effects": [{"id": "e1", "target": "pending", "value": {
             "kind": "add",
             "left": {"kind": "field", "name": "pending"},
             "right": {"kind": "integer", "value": 1}}}],
         "frame": ["pending"]},
    ],
    "tlc_invariants": [
        {"id": "inv1", "expression": {
            "kind": "gte",
            "left": {"kind": "field", "name": "pending"},
            "right": {"kind": "integer", "value": 0}}},
    ],
    "actors": [],
}

# 1024 usable, margin 0.9 -> 921 budget; struct = 3 int fields * 4 = 12 bytes
# -> capacity 76 (floor(921/12)).
PROFILE = {"target": "TestMCU", "total_sram_bytes": 1024, "reserved_system_bytes": 0,
           "max_stack_depth_bytes": 512, "word_size_bytes": 4}


def _write(tmp_path, candidate=CANDIDATE):
    candidate_path = tmp_path / "parser.v2.yaml"
    candidate_path.write_text(yaml.safe_dump(candidate, sort_keys=False),
                              encoding="utf-8")
    profile_path = tmp_path / "hardware_profile.json"
    profile_path.write_text(json.dumps(PROFILE), encoding="utf-8")
    return candidate_path, profile_path


def test_yaml_candidate_is_rebounded_to_hardware_capacity(tmp_path):
    candidate_path, profile_path = _write(tmp_path)
    result = correct_behavior(candidate_path, "CWE-400", tmp_path / "out",
                              strategy="static-pool", hardware=profile_path)
    assert result["status"] == "CAPACITY_BOUND_CANDIDATE_GENERATED"
    assert result["claim"] == "NO_PROOF"          # proof is downstream (TLC/Prusti)
    assert "CAPACITY_BOUNDING_APPLIED" in result["claims"]
    assert "HARDWARE_MEMORY_BOUND_PROVEN" not in result["claims"]
    assert result["hardware"]["derived_capacity"] == 76
    assert result["memory_footprint_bytes"] == 76 * 12
    bounded_path = tmp_path / "out" / "parser_bounded.v2.yaml"
    assert bounded_path.exists()
    bounded = yaml.safe_load(bounded_path.read_text(encoding="utf-8"))
    assert bounded["module_name"] == "parser_bounded"
    by_name = {v["name"]: v for v in bounded["state_variables"]}
    assert by_name["pending"]["bound"] == [0, 76]        # clamped 512 -> 76
    assert by_name["bulklen"]["bound"] == [-1, 76]       # lo preserved
    assert by_name["unbounded_counter"]["bound"] == [0, 76]  # UNBOUNDED -> bounded
    assert "bound" not in by_name["active"]              # booleans untouched
    invariant_texts = [inv["id"] for inv in bounded["tlc_invariants"]]
    assert "inv_hw_bound_pending" in invariant_texts
    assert "inv_hw_bound_unbounded_counter" in invariant_texts
    hw = next(inv for inv in bounded["tlc_invariants"]
              if inv["id"] == "inv_hw_bound_pending")["expression"]
    assert hw["kind"] == "and"
    assert hw["right"]["right"]["value"] == 76
    # the original candidate is never modified
    original = yaml.safe_load(candidate_path.read_text(encoding="utf-8"))
    assert original["state_variables"][0]["bound"] == [0, 512]
    assert original["module_name"] == "parser"
    # evidence records the full derivation for review
    assert result["bounded_candidate"] == str(bounded_path)
    assert result["struct_size_bytes"] == 12
    assert result["next_steps"] == [
        "validate-domain parser_bounded --project-root <root>",
        "promote-domain parser_bounded --accept-candidate-sha256 <hash>",
        "draft \"...\" --canonical-domain parser_bounded --lang rust",
    ]


def test_yaml_lane_requires_hardware_profile(tmp_path):
    candidate_path, _ = _write(tmp_path)
    result = correct_behavior(candidate_path, "CWE-400", tmp_path / "out",
                              strategy="static-pool", hardware=None)
    assert result["status"] == "CORRECTION_FAILED"
    assert result["code"] == "hardware_profile_required"


def test_yaml_lane_rejects_inapplicable_strategy_and_cwe(tmp_path):
    candidate_path, profile_path = _write(tmp_path)
    result = correct_behavior(candidate_path, "CWE-400", tmp_path / "out",
                              strategy="bound-loop", hardware=profile_path)
    assert result["code"] == "strategy_not_applicable"
    result = correct_behavior(candidate_path, "CWE-476", tmp_path / "out",
                              strategy="static-pool", hardware=profile_path)
    assert result["code"] == "unsupported_cwe_for_candidate"


def test_yaml_lane_respects_explicit_struct_size(tmp_path):
    candidate_path, profile_path = _write(tmp_path)
    result = correct_behavior(candidate_path, "CWE-400", tmp_path / "out",
                              strategy="bounded-cache", hardware=profile_path,
                              struct_size_bytes=64)
    # 921 // 64 = 14
    assert result["hardware"]["derived_capacity"] == 14
    assert result["memory_footprint_bytes"] == 14 * 64


def test_yaml_lane_oversized_struct_fails_closed(tmp_path):
    candidate_path, profile_path = _write(tmp_path)
    result = correct_behavior(candidate_path, "CWE-400", tmp_path / "out",
                              strategy="static-pool", hardware=profile_path,
                              struct_size_bytes=100000)
    assert result["status"] == "CORRECTION_FAILED"
    assert result["code"] == "HARDWARE_MEMORY_EXCEEDED"


def test_java_lane_still_routes_by_extension(tmp_path):
    # a .java target must keep taking the Java/JML correction path, not YAML
    source = tmp_path / "Service.java"
    source.write_text("public class Service { public int x; }", encoding="utf-8")
    result = correct_behavior(source, "CWE-400", tmp_path / "out",
                              strategy="static-pool")
    assert result["code"] != "hardware_profile_required"
    assert result["status"] == "CORRECTION_FAILED"   # provider unreachable is fine


def test_yaml_lane_fail_closed_on_missing_and_malformed(tmp_path):
    profile_path = tmp_path / "hardware_profile.json"
    profile_path.write_text(json.dumps(PROFILE), encoding="utf-8")
    missing = correct_behavior(tmp_path / "nope.v2.yaml", "CWE-400",
                               tmp_path / "out", strategy="static-pool",
                               hardware=profile_path)
    assert missing["code"] == "input_unavailable"
    garbage = tmp_path / "garbage.v2.yaml"
    garbage.write_text("{not: yaml: at all", encoding="utf-8")
    malformed = correct_behavior(garbage, "CWE-400", tmp_path / "out",
                                 strategy="static-pool", hardware=profile_path)
    assert malformed["code"] == "candidate_unreadable"


def test_fields_already_within_capacity_are_left_unchanged(tmp_path):
    within = dict(CANDIDATE)
    within["state_variables"] = [
        {"kind": "int", "name": "small", "bound": [0, 10], "initial": 0},
        {"kind": "int", "name": "huge", "bound": [0, 512], "initial": 0},
    ]
    candidate_path, profile_path = _write(tmp_path, within)
    result = correct_behavior(candidate_path, "CWE-400", tmp_path / "out",
                              strategy="static-pool", hardware=profile_path,
                              struct_size_bytes=12)
    bounded = yaml.safe_load(
        (tmp_path / "out" / "parser_bounded.v2.yaml").read_text(encoding="utf-8"))
    by_name = {v["name"]: v for v in bounded["state_variables"]}
    assert by_name["small"]["bound"] == [0, 10]      # already fits: untouched
    assert by_name["huge"]["bound"] == [0, 76]       # clamped
    assert result["clamped_fields"] == ["huge"]
    assert result["gained_bounds"] == []
