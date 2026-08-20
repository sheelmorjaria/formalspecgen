# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M30 (roadmap Feature 8): safe autonomous porting within hardware bounds.

The full chain: an unbounded dynamic structure is refused by name at
extraction (UNBOUNDED_HEAP_DETECTED), the human models it as a bounded
counter machine, correct-behavior clamps it to the silicon's capacity and
adds growth guards, and the deterministic Rust lowering materializes the
static pool ([bool; CAP] occupancy — exactly the reviewed semantics) whose
Prusti contracts prove size <= CAP and reject-when-full.
"""
from __future__ import annotations

import json

import pytest

from pipeline.codebase_analysis import analyze_codebase


@pytest.fixture(autouse=True)
def deterministic_z3_capacity_seam(monkeypatch):
    """Unit-test the porting chain independently of host judge installs."""
    def proved(profile, capacity, struct_size_bytes, safety_margin=0.9):
        budget = int(profile.usable_sram_bytes * safety_margin)
        return {"status": "VERIFIED", "claim": "HARDWARE_MEMORY_BOUND_PROVED",
                "solver": "test-seam", "encoding_sha256": "0" * 64,
                "capacity_bound": capacity,
                "struct_size_bytes": struct_size_bytes,
                "memory_footprint_bytes": capacity * struct_size_bytes,
                "sram_budget_bytes": budget}
    monkeypatch.setattr("pipeline.hardware_profile.prove_fixed_pool_fits", proved)

C_LINKED_LIST = """typedef struct Node {
    int val;
    struct Node* next;
} Node;

typedef struct Log {
    char fmt[64];
    char* buf;
    struct Node* head;
} Log;

void push(Node** head, int v) {
    Node* n = malloc(sizeof(Node));
    n->val = v;
    n->next = *head;
    *head = n;
}
"""

JAVA_ARRAY_LIST = """public class Registry {
    private java.util.List<Object> items = new java.util.ArrayList<>();

    public void add(Object item) {
        items.add(item);
    }
}
"""

# The human-modeled bounded counter machine for the same structure.
LIST_V2 = """schema_version: 2
review_status: unreviewed
domain_name: BoundedList
module_name: bounded_list
actors: 1
state_variables:
  - kind: int
    name: size
    bound: [0, 1000000]
    initial: 0
operations:
  - name: push
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: g1
        expression:
          kind: lt
          left: {kind: field, name: size}
          right: {kind: integer, value: 1000000}
    effects:
      - id: e1
        target: size
        value:
          kind: add
          left: {kind: field, name: size}
          right: {kind: integer, value: 1}
    frame: [size]
  - name: pop
    return_type: boolean
    failure_semantics: false_and_stutter
    guards:
      - id: g2
        expression:
          kind: gt
          left: {kind: field, name: size}
          right: {kind: integer, value: 0}
    effects:
      - id: e2
        target: size
        value:
          kind: sub
          left: {kind: field, name: size}
          right: {kind: integer, value: 1}
    frame: [size]
tlc_invariants:
  - id: inv1
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: size}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: size}
        right: {kind: integer, value: 1000000}
"""

HW_PROFILE = {
    "target": "STM32F411 (safe-port chain)",
    "total_sram_bytes": 131072,
    "reserved_system_bytes": 32768,
    "max_stack_depth_bytes": 4096,
    "word_size_bytes": 4,
}
# usable 98304; budget 98304*0.9 = 88473; capacity = 88473 // 16 = 5529


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_c_dynamic_pointer_field_refused_by_name(tmp_path):
    """Test 1.1: the extractor names the offending field and struct."""
    source = tmp_path / "legacy"; source.mkdir()
    (source / "list.c").write_text(C_LINKED_LIST, encoding="utf-8")
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    heap = [w for w in result["warnings"]
            if w["code"] == "UNBOUNDED_HEAP_DETECTED"]
    assert heap, "dynamic pointers must be refused by name"
    assert "next" in heap[0]["message"] and "Node" in heap[0]["message"]
    assert "capacity bounding" in heap[0]["message"]
    # char fmt[]/buf buffers are static scratch, not dynamic heap state
    assert all("fmt" not in w["message"] and "buf" not in w["message"]
               for w in heap)


def test_java_dynamic_collection_field_refused_by_name(tmp_path):
    """Test 1.2: dynamic collections are named, and never become scalar
    state (a List field is occupancy, not an int)."""
    source = tmp_path / "java"; source.mkdir()
    (source / "Registry.java").write_text(JAVA_ARRAY_LIST, encoding="utf-8")
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    heap = [w for w in result["warnings"]
            if w["code"] == "UNBOUNDED_HEAP_DETECTED"]
    assert heap and "items" in heap[0]["message"]
    assert "dynamic collection" in heap[0]["message"]
    registry = next(c for c in result["components"] if c["name"] == "Registry")
    assert all(f["name"] != "items" for f in registry["fields"])


def test_human_modeled_v2_domain_bypasses_the_refusal(tmp_path):
    """Test 1.3: the V2 lifecycle accepts the hand-modeled machine — the
    refusal is at extraction, never a gate on the reviewed math."""
    from pipeline.domain_v2_promotion import load_candidate
    candidate = _write(tmp_path, "bounded_list.v2.yaml", LIST_V2)
    spec = load_candidate(candidate)
    assert [v.name for v in spec.state_variables] == ["size"]
    assert {op.name for op in spec.operations} == {"push", "pop"}


def test_candidate_bounding_clamps_and_adds_growth_guards(tmp_path):
    """Test 2.1/2.2: the silicon picks 5529; size clamps to [0, 5529] and
    push gains requires size < 5529; without hardware it fails closed."""
    from pipeline.behavior_correction import correct_behavior
    profile = _write(tmp_path, "hw.json", json.dumps(HW_PROFILE))
    candidate = _write(tmp_path, "bounded_list.v2.yaml", LIST_V2)
    result = correct_behavior(candidate, "CWE-400", tmp_path / "out",
                              strategy="static-pool", hardware=profile,
                              struct_size_bytes=16)
    assert result["status"] == "CAPACITY_BOUND_CANDIDATE_GENERATED", result
    assert result["derived_capacity"] == 5529
    assert result["memory_footprint_bytes"] == 5529 * 16      # 88464 <= 88473
    import yaml
    bounded = yaml.safe_load(
        (tmp_path / "out" / "bounded_list_bounded.v2.yaml").read_text())
    assert bounded["capacity_bound"] == 5529
    size = next(v for v in bounded["state_variables"] if v["name"] == "size")
    assert size["bound"] == [0, 5529]
    push = next(op for op in bounded["operations"] if op["name"] == "push")
    guards = [g["expression"] for g in push["guards"]]
    growth = {"kind": "lt", "left": {"kind": "field", "name": "size"},
              "right": {"kind": "integer", "value": 5529}}
    assert growth in guards, "push must require size < capacity"

    missing = correct_behavior(candidate, "CWE-400", tmp_path / "out2",
                               strategy="static-pool")
    assert missing["code"] == "hardware_profile_required"


def test_rust_lowering_materializes_the_static_pool(tmp_path):
    """Test 3.1: the bounded domain lowers to a fixed-capacity pool whose
    occupancy array is exactly [bool; CAP] — the reviewed counter semantics
    materialized, no values invented."""
    from pipeline.behavior_correction import correct_behavior
    from pipeline.canonical_draft import canonical_draft_rust
    profile = _write(tmp_path, "hw.json", json.dumps(HW_PROFILE))
    candidate = _write(tmp_path, "bounded_list.v2.yaml", LIST_V2)
    result = correct_behavior(candidate, "CWE-400", tmp_path / "out",
                              strategy="static-pool", hardware=profile,
                              struct_size_bytes=16)
    bounded_path = tmp_path / "out" / "bounded_list_bounded.v2.yaml"
    # review + promote the bounded machine, then lower deterministically
    from pipeline.domain_v2_model import validate_transitions_and_invariants
    from pipeline.domain_v2_promotion import load_candidate
    spec = load_candidate(bounded_path)
    validate_transitions_and_invariants(spec)     # traverser accepts it
    reviewed = tmp_path / "domains" / "v2" / "bounded_list_bounded.json"
    reviewed.parent.mkdir(parents=True, exist_ok=True)
    payload = spec.model_dump(mode="json")
    payload.update(review_status="reviewed",
                   accepted_candidate_sha256="0" * 64,
                   accepted_evidence_sha256="0" * 64)
    reviewed.write_text(json.dumps(payload))
    out = tmp_path / "List.rs"
    canonical_draft_rust("bounded_list_bounded", "port",
                         out_file=str(out),
                         domains_root=tmp_path / "domains" / "v2")
    code = out.read_text()
    assert "slots: [bool; 5529]" in code
    assert "size < 5529" in code               # the growth guard's requires


def test_final_verdict_carries_the_hardware_memory_bound(tmp_path):
    """Test 3.3: the chain's terminal verdict proves the port fits the
    silicon — HARDWARE_MEMORY_BOUND_PROVED with the exact footprint
    (5529 x 16 = 88464 <= the 88473-byte budget)."""
    import hashlib
    from pipeline.behavior_correction import correct_behavior
    from pipeline.domain_v2_evidence import canonical_sha256
    from pipeline.domain_v2_promotion import load_candidate
    from pipeline.domain_v2_tla import render_v2_tla
    from pipeline.polyglot_refinement_gate import polyglot_v2_refinement_gate
    profile = _write(tmp_path, "hw.json", json.dumps(HW_PROFILE))
    candidate = _write(tmp_path, "bounded_list.v2.yaml", LIST_V2)
    correct_behavior(candidate, "CWE-400", tmp_path / "out",
                     strategy="static-pool", hardware=profile,
                     struct_size_bytes=16)
    spec = load_candidate(tmp_path / "out" / "bounded_list_bounded.v2.yaml")
    reviewed_payload = spec.model_dump(mode="json")
    candidate_sha = hashlib.sha256(
        (tmp_path / "out" / "bounded_list_bounded.v2.yaml")
        .read_bytes()).hexdigest()
    tla, _ = render_v2_tla(spec)
    evidence = {"schema_version": 2, "candidate_sha256": candidate_sha,
                "validation_status": "VALIDATED", "tlc_exit_status": 0,
                "generated_tla_sha256": hashlib.sha256(tla.encode()).hexdigest()}
    envelope = {"evidence": evidence,
                "evidence_sha256": canonical_sha256(evidence)}
    reviewed_payload.update(review_status="reviewed",
                            accepted_candidate_sha256=candidate_sha,
                            accepted_evidence_sha256=envelope["evidence_sha256"])
    reviewed_path = tmp_path / "bounded_list_bounded.json"
    reviewed_path.write_text(json.dumps(reviewed_payload))
    validation_path = tmp_path / "validation.json"
    validation_path.write_text(json.dumps(envelope))
    from pipeline.v2_prusti_serializer import render_reviewed_v2_prusti_file
    _, code = render_reviewed_v2_prusti_file(reviewed_path)
    verdict = polyglot_v2_refinement_gate(
        reviewed_path, validation_path, code, code, "rust",
        backend_verified=True)
    assert verdict["status"] == "VERIFIED", verdict
    assert "HARDWARE_MEMORY_BOUND_PROVED" in verdict["claims"]
    assert verdict["hardware_memory_bound_proved"] is True
    assert verdict["capacity_bound"] == 5529
    assert verdict["static_pool_materialized"] is True
    assert verdict["memory_footprint_bytes"] == 5529 * 16   # 88464 <= 88473


def _bounded_spec(tmp_path, machine_yaml, name):
    """Run the correction lane, then load the bounded machine as reviewed.

    Returns (spec, payload, bounded_yaml_path) so tests can mutate the raw
    payload (drop provenance fields) before re-validating.
    """
    from pipeline.behavior_correction import correct_behavior
    from pipeline.domain_v2_promotion import ReviewedDomainSpecV2, load_candidate
    profile = _write(tmp_path, "hw.json", json.dumps(HW_PROFILE))
    candidate = _write(tmp_path, f"{name}.v2.yaml", machine_yaml)
    correct_behavior(candidate, "CWE-400", tmp_path / f"out_{name}",
                     strategy="static-pool", hardware=profile,
                     struct_size_bytes=16)
    bounded_path = tmp_path / f"out_{name}" / f"{name}_bounded.v2.yaml"
    spec = load_candidate(bounded_path)
    payload = spec.model_dump(mode="json")
    payload.update(review_status="reviewed",
                   accepted_candidate_sha256="0" * 64,
                   accepted_evidence_sha256="0" * 64)
    return ReviewedDomainSpecV2.model_validate(payload), payload, bounded_path


# A `clear`/`reset` op writes the counter with a literal — occupancy of a
# literal jump has no pool semantics, so the pool is refused, not faked.
LITERAL_RESET_V2 = LIST_V2.replace(
    "domain_name: BoundedList\nmodule_name: bounded_list",
    "domain_name: LiteralReset\nmodule_name: literal_reset").replace(
    """  - name: pop""", """  - name: reset
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: gr
        expression:
          kind: gt
          left: {kind: field, name: size}
          right: {kind: integer, value: 0}
    effects:
      - id: er
        target: size
        value: {kind: integer, value: 0}
    frame: [size]
  - name: pop""")

# A +2 step is not element-granular: two slots change, one bit cannot shadow it.
PLUS_TWO_V2 = LIST_V2.replace(
    "domain_name: BoundedList\nmodule_name: bounded_list",
    "domain_name: PlusTwo\nmodule_name: plus_two").replace(
    """          kind: add
          left: {kind: field, name: size}
          right: {kind: integer, value: 1}""", """          kind: add
          left: {kind: field, name: size}
          right: {kind: integer, value: 2}""")

# Counter + an unrelated small phase field: the pool shadows ONLY the
# capacity-bounded counter; the phase field lowers as plain scalar state.
MIXED_MACHINE_V2 = LIST_V2.replace(
    "domain_name: BoundedList\nmodule_name: bounded_list",
    "domain_name: MixedMachine\nmodule_name: mixed_machine").replace(
    """    initial: 0
operations:""", """    initial: 0
  - kind: int
    name: phase
    bound: [0, 3]
    initial: 0
operations:""").replace("""  - name: pop""", """  - name: mark
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: gm
        expression:
          kind: lt
          left: {kind: field, name: phase}
          right: {kind: integer, value: 3}
    effects:
      - id: em
        target: phase
        value:
          kind: add
          left: {kind: field, name: phase}
          right: {kind: integer, value: 1}
    frame: [phase]
  - name: pop""").replace("""  - id: inv1
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: size}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: size}
        right: {kind: integer, value: 1000000}""", """  - id: inv1
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: size}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: size}
        right: {kind: integer, value: 1000000}
  - id: inv2
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: phase}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: phase}
        right: {kind: integer, value: 3}""")


def test_pool_refused_for_non_counter_writes_and_shadowed_machines(tmp_path):
    """The pool materializes only the honest counter-machine shape: literal
    writes and non-unit steps refuse it (bounds still prove via guards)."""
    from pipeline.v2_prusti_serializer import _pool_counter, render_struct
    literal, _, _ = _bounded_spec(tmp_path, LITERAL_RESET_V2, "literal_reset")
    assert _pool_counter(literal) is None
    assert "pub slots" not in render_struct(literal)

    plus_two, _, _ = _bounded_spec(tmp_path, PLUS_TWO_V2, "plus_two")
    assert _pool_counter(plus_two) is None
    assert "pub slots" not in render_struct(plus_two)


def test_pool_shadows_only_the_capacity_bounded_counter(tmp_path):
    """A machine with a counter at capacity plus an unrelated small field:
    the pool engages for the counter and the other field lowers as plain
    scalar state beside it."""
    from pipeline.v2_prusti_serializer import _pool_counter, render_struct
    mixed, _, _ = _bounded_spec(tmp_path, MIXED_MACHINE_V2, "mixed_machine")
    assert _pool_counter(mixed) == "size"
    code = render_struct(mixed)
    assert "slots: [bool; 5529]" in code
    assert "pub phase: i32" in code
    assert "self.slots[pre_size as usize] = true;" in code
    assert "self.phase = pre_phase + 1;" in code


# Two counters both sitting at the capacity: sharing one occupancy array
# between them would be an invented design, so the pool is refused.
TWO_COUNTERS_V2 = MIXED_MACHINE_V2.replace(
    "domain_name: MixedMachine\nmodule_name: mixed_machine",
    "domain_name: TwoCounters\nmodule_name: two_counters").replace(
    """  - kind: int
    name: phase
    bound: [0, 3]
    initial: 0""", """  - kind: int
    name: count
    bound: [0, 1000000]
    initial: 0""").replace("""  - name: mark
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: gm
        expression:
          kind: lt
          left: {kind: field, name: phase}
          right: {kind: integer, value: 3}
    effects:
      - id: em
        target: phase
        value:
          kind: add
          left: {kind: field, name: phase}
          right: {kind: integer, value: 1}
    frame: [phase]""", """  - name: bump
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: gm
        expression:
          kind: lt
          left: {kind: field, name: count}
          right: {kind: integer, value: 1000000}
    effects:
      - id: em
        target: count
        value:
          kind: add
          left: {kind: field, name: count}
          right: {kind: integer, value: 1}
    frame: [count]""").replace("""  - id: inv2
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: phase}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: phase}
        right: {kind: integer, value: 3}""", """  - id: inv2
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: count}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: count}
        right: {kind: integer, value: 1000000}""")

# A boolean beside the counter: bools are never pool candidates, and the
# machine still lowers with the pool shadowing only the int counter.
BOOL_BESIDE_V2 = MIXED_MACHINE_V2.replace(
    "domain_name: MixedMachine\nmodule_name: mixed_machine",
    "domain_name: BoolBeside\nmodule_name: bool_beside").replace(
    """  - kind: int
    name: phase
    bound: [0, 3]
    initial: 0""", """  - kind: bool
    name: ready
    initial: false""").replace("""  - name: mark
    return_type: void
    failure_semantics: unavailable
    guards:
      - id: gm
        expression:
          kind: lt
          left: {kind: field, name: phase}
          right: {kind: integer, value: 3}
    effects:
      - id: em
        target: phase
        value:
          kind: add
          left: {kind: field, name: phase}
          right: {kind: integer, value: 1}
    frame: [phase]
""", "").replace("""  - id: inv2
    expression:
      kind: and
      left:
        kind: gte
        left: {kind: field, name: phase}
        right: {kind: integer, value: 0}
      right:
        kind: lte
        left: {kind: field, name: phase}
        right: {kind: integer, value: 3}
""", "")


def test_pool_refused_for_two_counters_and_ignores_bool_fields(tmp_path):
    """Two counters at the same capacity refuse the pool (no invented
    sharing design); a bool beside the single counter changes nothing."""
    from pipeline.v2_prusti_serializer import _pool_counter, render_struct
    two, _, _ = _bounded_spec(tmp_path, TWO_COUNTERS_V2, "two_counters")
    assert _pool_counter(two) is None
    assert "pub slots" not in render_struct(two)

    bool_beside, _, _ = _bounded_spec(tmp_path, BOOL_BESIDE_V2, "bool_beside")
    assert _pool_counter(bool_beside) == "size"
    code = render_struct(bool_beside)
    assert "slots: [bool; 5529]" in code
    assert "pub ready: bool" in code

    # An int field clamped to the same capacity but never written by any
    # operation is a constant ceiling, not a counter: the pool ignores it.
    never_written = _bounded_spec(
        tmp_path,
        LIST_V2.replace("domain_name: BoundedList\nmodule_name: bounded_list",
                        "domain_name: NeverWritten\nmodule_name: never_written")
        .replace("""    initial: 0
operations:""", """    initial: 0
  - kind: int
    name: ceiling
    bound: [0, 1000000]
    initial: 0
operations:""")
        .replace("""      right:
        kind: lte
        left: {kind: field, name: size}
        right: {kind: integer, value: 1000000}""", """      right:
        kind: lte
        left: {kind: field, name: size}
        right: {kind: integer, value: 1000000}
  - id: inv2
    expression:
      kind: lte
      left: {kind: field, name: ceiling}
      right: {kind: integer, value: 1000000}"""),
        "never_written")[0]
    assert _pool_counter(never_written) == "size"
    assert "slots: [bool; 5529]" in render_struct(never_written)


def test_capacity_tag_without_struct_size_omits_footprint(tmp_path):
    """A hand-tagged capacity_bound with no silicon provenance still earns
    HARDWARE_MEMORY_BOUND_PROVED, but the verdict refuses to state a byte
    footprint it cannot derive."""
    import hashlib
    from pipeline.domain_v2_evidence import canonical_sha256
    from pipeline.domain_v2_promotion import ReviewedDomainSpecV2
    from pipeline.domain_v2_tla import render_v2_tla
    from pipeline.polyglot_refinement_gate import polyglot_v2_refinement_gate
    from pipeline.v2_prusti_serializer import render_reviewed_v2_prusti_file
    spec, payload, bounded_path = _bounded_spec(tmp_path, LIST_V2, "bounded_list")
    del payload["struct_size_bytes"]
    spec = ReviewedDomainSpecV2.model_validate(payload)
    candidate_sha = hashlib.sha256(bounded_path.read_bytes()).hexdigest()
    tla, _ = render_v2_tla(spec)
    evidence = {"schema_version": 2, "candidate_sha256": candidate_sha,
                "validation_status": "VALIDATED", "tlc_exit_status": 0,
                "generated_tla_sha256": hashlib.sha256(tla.encode()).hexdigest()}
    envelope = {"evidence": evidence,
                "evidence_sha256": canonical_sha256(evidence)}
    payload["accepted_candidate_sha256"] = candidate_sha
    payload["accepted_evidence_sha256"] = envelope["evidence_sha256"]
    reviewed_path = tmp_path / "tagged.json"
    reviewed_path.write_text(json.dumps(payload))
    validation_path = tmp_path / "tagged.validation.json"
    validation_path.write_text(json.dumps(envelope))
    _, code = render_reviewed_v2_prusti_file(reviewed_path)
    verdict = polyglot_v2_refinement_gate(
        reviewed_path, validation_path, code, code, "rust",
        backend_verified=True)
    assert verdict["status"] == "VERIFIED", verdict
    assert "HARDWARE_MEMORY_BOUND_PROVED" in verdict["claims"]
    assert "memory_footprint_bytes" not in verdict
