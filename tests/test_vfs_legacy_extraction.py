from pathlib import Path

import yaml

from pipeline.codebase_analysis import analyze_codebase


FIXTURE = Path(__file__).parent / "fixtures" / "legacy_vfs"


def test_legacy_vfs_list_is_bounded_and_complex_shapes_are_refused(tmp_path):
    result = analyze_codebase(FIXTURE, tmp_path / "extracted",
                              project_root=tmp_path)

    lists = [item for item in result["os_pattern_evidence"]
             if item["status"] == "INTRUSIVE_LIST_ABSTRACTED"]
    assert len(lists) == 1
    assert lists[0]["abstract_state_field"] == "size"
    assert lists[0]["pool_capacity"] == 4
    assert lists[0]["size_invariant"] == "0 <= size <= 4"
    assert {item["size_effect"] for item in lists[0]["transitions"]} == {-1, 1}

    refusals = {item.get("shape") for item in result["warnings"]
                if item["code"] ==
                "UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW"}
    assert {"RB_TREE", "HASH_BUCKETS", "POINTER_ALIAS"} <= refusals
    assert result["claim"] == "UNREVIEWED_EXTRACTION_CANDIDATE"
    assert result["validation"]["status"] == "NOT_RUN"


def test_list_abstraction_refuses_to_guess_missing_capacity(tmp_path):
    source = tmp_path / "legacy"
    source.mkdir()
    (source / "list.c").write_text(
        "struct item { struct list_head links; };\n"
        "void add(struct item *i) { list_add(&i->links, &items); }\n",
        encoding="utf-8")
    result = analyze_codebase(source, tmp_path / "out", project_root=tmp_path)
    assert result["os_pattern_evidence"][0]["code"] == \
        "pool_capacity_missing"
    assert result["os_pattern_evidence"][0]["claim"] == "NO_PROOF"


def test_manual_mapping_keeps_refusals_and_claims_locked():
    mapping = yaml.safe_load((Path(__file__).parents[1] / "domains" /
                              "candidates" /
                              "vfs.legacy-mapping.yaml").read_text())
    assert mapping["review_status"] == "unreviewed"
    assert mapping["claim"] == "NO_PROOF"
    assert {item["refusal"] for item in mapping["manual_review_mappings"]} == \
        {"RB_TREE", "HASH_BUCKETS", "POINTER_ALIAS"}
    assert mapping["locked_claims"] == [
        "BOUNDED_ARCHITECTURE_EVIDENCE",
        "SOURCE_MODEL_REFINEMENT",
        "HARDWARE_MEMORY_BOUND_PROVED",
    ]
