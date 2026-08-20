from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server


def test_mcp_workspace_paths_are_contained(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = Path("Counter.java")
    source.write_text("public class Counter {}", encoding="utf-8")
    assert mcp_server.inspect_code("Counter.java")["status"] == "INSPECTED"
    with pytest.raises(ValueError, match="inside"):
        mcp_server.inspect_code("../Counter.java")


def test_mcp_verify_code_returns_structured_java_verdict(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = Path("Counter.java"); source.write_text("public class Counter {}")
    with patch("mcp_server.verify", return_value=(0, "ok")):
        result = mcp_server.verify_code("Counter.java", "check")
    assert result["status"] == "VERIFIED"
    assert result["claim"] == "NO_PROOF"
    assert result["exit_code"] == 0


def test_mcp_server_reports_optional_dependency_boundary():
    if mcp_server.FastMCP is not None:
        pytest.skip("MCP SDK is installed in this environment")
    with pytest.raises(RuntimeError, match="MCP SDK is not installed"):
        mcp_server.create_server()


# ------------------------------------------------- v2.3 tool surface -------


def _workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = Path("Service.java")
    source.write_text("public class Service { private int count; "
                      "public void inc() { if (count < 5) { count = count + 1; } } }",
                      encoding="utf-8")
    return source


def test_mcp_analyze_and_document_guarded(tmp_path, monkeypatch):
    source = _workspace(tmp_path, monkeypatch)
    with patch("pipeline.codebase_analysis.analyze_codebase",
               return_value={"status": "EXTRACTED", "components": []}) as analyze:
        result = mcp_server.analyze_codebase(".", out_dir="extracted", project_root=".")
        analyze.assert_called_once()
    assert result["status"] == "EXTRACTED"
    escape = mcp_server.analyze_codebase("..", out_dir="extracted")
    assert escape["code"] == "path_outside_workspace"

    with patch("pipeline.code_documentation.document_code",
               return_value={"status": "DOCUMENTED"}) as document:
        assert mcp_server.document_code(str(source), "docs/S.md")["status"] == "DOCUMENTED"
        document.assert_called_once()
    escape = mcp_server.document_code(str(source), "../escape.md")
    assert escape["status"] == "FAIL" and escape["code"] == "path_outside_workspace"
    missing = mcp_server.document_code("Nope.java", "docs/Nope.md")
    assert missing["code"] == "input_unavailable"


def test_mcp_security_tools_guarded(tmp_path, monkeypatch):
    source = _workspace(tmp_path, monkeypatch)
    Path("report.json").write_text('{"findings": []}', encoding="utf-8")
    with patch("pipeline.security_assessment.assess_security",
               return_value={"status": "VERIFIED_SECURE"}) as assess:
        assert mcp_server.assess_security(str(source))["status"] == "VERIFIED_SECURE"
        assess.assert_called_once()
    with patch("pipeline.security_poc.inspect_security",
               return_value={"status": "NO_FINDINGS"}) as inspect_:
        assert mcp_server.security_inspect(str(source))["status"] == "NO_FINDINGS"
        inspect_.assert_called_once()
    with patch("pipeline.security_poc.generate_pocs",
               return_value={"status": "POCS_GENERATED"}) as pocs:
        assert mcp_server.security_exploit("report.json", str(source),
                                          out_dir="pocs")["status"] == "POCS_GENERATED"
        pocs.assert_called_once()
    escape = mcp_server.security_exploit("report.json", str(source), out_dir="../pocs")
    assert escape["code"] == "path_outside_workspace"


def test_mcp_remediation_and_correction_guarded(tmp_path, monkeypatch):
    source = _workspace(tmp_path, monkeypatch)
    report = Path("report.json")
    report.write_text('{"findings": []}', encoding="utf-8")
    with patch("pipeline.remediation.remediate",
               return_value={"status": "NO_REMEDIATION_REQUIRED"}) as fix:
        assert mcp_server.remediate_code(str(source), str(report))[
            "status"] == "NO_REMEDIATION_REQUIRED"
        fix.assert_called_once()
    with patch("pipeline.behavior_correction.correct_behavior",
               return_value={"status": "BEHAVIOR_CORRECTION_VERIFIED"}) as correct:
        assert mcp_server.correct_behavior(str(source), "CWE-125")[
            "status"] == "BEHAVIOR_CORRECTION_VERIFIED"
        correct.assert_called_once()


def test_mcp_refactor_tools_guarded(tmp_path, monkeypatch):
    source = _workspace(tmp_path, monkeypatch)
    inspection = Path("inspection.json")
    inspection.write_text('{"status": "INSPECTED"}', encoding="utf-8")
    with patch("pipeline.refactor_actions.apply_refactor",
               return_value={"status": "VERIFIED"}) as apply:
        assert mcp_server.apply_refactor(str(source), str(inspection),
                                         "extract-method", "inc",
                                         "refactored/S.java")["status"] == "VERIFIED"
        apply.assert_called_once()
    escape = mcp_server.apply_refactor(str(source), str(inspection),
                                       "extract-method", "inc", "../refactored")
    assert escape["code"] == "path_outside_workspace"

    with patch("pipeline.refactor_gate.verify_contract_preserving_refactor",
               return_value={"status": "VERIFIED", "claim": "REFACTOR_CONTRACT_PRESERVED"}):
        target = Path("Refactored.java"); target.write_text("class X {}", encoding="utf-8")
        assert mcp_server.verify_refactor(str(source), str(target))[
            "claim"] == "REFACTOR_CONTRACT_PRESERVED"
    with patch("pipeline.refactor_gate.verify_multifile_contract_refactor",
               return_value={"status": "VERIFIED"}):
        (tmp_path / "refactored").mkdir()
        assert mcp_server.verify_refactor(str(source), "refactored")["status"] == "VERIFIED"

    mapping = Path("mapping.json"); mapping.write_text("{}", encoding="utf-8")
    with patch("pipeline.bisimulation.verify_bisimulation_inputs",
               return_value={"status": "BISIMULATION_PREFLIGHT_READY"}) as bisim:
        assert mcp_server.verify_bisimulation(str(source), "refactored", str(mapping))[
            "status"] == "BISIMULATION_PREFLIGHT_READY"
        bisim.assert_called_once()


def test_mcp_algorithm_tools_guarded(tmp_path, monkeypatch):
    source = _workspace(tmp_path, monkeypatch)
    with patch("pipeline.algorithm_optimization.optimize_algorithm",
               return_value={"status": "VERIFIED"}) as optimize:
        assert mcp_server.optimize_algorithm(str(source), "optimized/S.java",
                                             "hashmap")["status"] == "VERIFIED"
        optimize.assert_called_once()
    with patch("pipeline.algorithm_discovery.discover_algorithms",
               return_value={"status": "ALGORITHM_DISCOVERY_COMPLETE"}) as discover:
        assert mcp_server.discover_algorithms(str(source), out_dir="discovered")[
            "status"] == "ALGORITHM_DISCOVERY_COMPLETE"
        discover.assert_called_once()
    escape = mcp_server.discover_algorithms(str(source), out_dir="../discovered")
    assert escape["code"] == "path_outside_workspace"


def test_mcp_validate_domain_and_composition_guarded(tmp_path, monkeypatch):
    _workspace(tmp_path, monkeypatch)
    evidence = type("Evidence", (), {"model_dump": lambda self, mode="json": {
        "candidate_sha256": "a" * 64, "validation_status": "VALIDATED"}})()
    with patch("pipeline.domain_v2_validation.validate_domain",
               return_value=evidence) as validate:
        result = mcp_server.validate_domain("counter")
        validate.assert_called_once()
    assert result["status"] == "VALIDATED"
    assert result["claim"] == "BOUNDED_ARCHITECTURE_EVIDENCE"
    with patch("pipeline.domain_v2_validation.validate_domain",
               side_effect=ValueError("candidate not found")):
        failure = mcp_server.validate_domain("missing")
    assert failure["status"] == "VALIDATION_FAILED"

    artifact = Path("composition.json")
    artifact.write_text('{"composition": {}}', encoding="utf-8")
    with patch("pipeline.composition_render.verify_composition",
               return_value={"status": "COMPOSITION_VERIFIED"}) as compose:
        assert mcp_server.compose(str(artifact))["status"] == "COMPOSITION_VERIFIED"
        compose.assert_called_once()
    with patch("pipeline.composition_render.reverify_composition",
               return_value={"status": "REVERIFIED"}) as reverify:
        assert mcp_server.reverify_composition(str(artifact), "smart_lock")[
            "status"] == "REVERIFIED"
        reverify.assert_called_once()
    broken = mcp_server.compose("missing.json")
    assert broken["code"] == "input_unavailable"


def test_mcp_unified_system_and_canonical_draft_guarded(tmp_path, monkeypatch):
    _workspace(tmp_path, monkeypatch)
    artifact = Path("arch.json"); artifact.write_text("{}", encoding="utf-8")
    evidence = Path("evidence.json"); evidence.write_text('{"status": "VERIFIED"}',
                                                          encoding="utf-8")
    with patch("pipeline.unified_system_runner.run_unified_system",
               return_value={"status": "LOWERED"}) as lower:
        assert mcp_server.unified_system(str(artifact), str(evidence), "src/")[
            "status"] == "LOWERED"
        lower.assert_called_once()
    escape = mcp_server.unified_system(str(artifact), str(evidence), "../src")
    assert escape["code"] == "path_outside_workspace"

    with patch("pipeline.canonical_draft.canonical_draft",
               return_value={"evidence": {"claim": "REVIEWED_TRANSFORMATION"},
                             "code_file": "SmartLock.java",
                             "evidence_file": "SmartLock.java.canonical.json"}) as draft:
        result = mcp_server.draft_canonical_contract("smart_lock")
        draft.assert_called_once()
    assert result["evidence"]["claim"] == "REVIEWED_TRANSFORMATION"


# --------------------------------------------------- M21: full MCP parity ---

def test_mcp_architecture_tool_runs_the_bounded_tlc_gate(tmp_path, monkeypatch):
    """Milestone 1: the `architecture` command (JML -> TLA+ -> TLC) exposed."""
    source = _workspace(tmp_path, monkeypatch)
    with patch("pipeline.tla_backend.generate_and_check",
               return_value={"status": "VERIFIED",
                             "claim": "BOUNDED_ARCHITECTURE_EVIDENCE"}) as gate:
        result = mcp_server.architecture(str(source),
                                         abstraction="atomic_operations")
    assert result["claim"] == "BOUNDED_ARCHITECTURE_EVIDENCE"
    gate.assert_called_once()
    assert gate.call_args.kwargs["abstraction"] == "atomic_operations"


def test_mcp_system_tool_dispatches_all_three_modes(tmp_path, monkeypatch):
    """Milestone 1: the `system` orchestrator (implement/refactor/correct)."""
    _workspace(tmp_path, monkeypatch)
    plan = Path("plan.json")
    plan.write_text('{"components": []}', encoding="utf-8")

    with patch("pipeline.system_orchestrator.verify_system",
               return_value={"status": "SYSTEM_SYNTHESIS_VERIFIED"}) as verify:
        assert mcp_server.system("plan.json", out_dir="out")[
            "status"] == "SYSTEM_SYNTHESIS_VERIFIED"
        verify.assert_called_once()

    with patch("pipeline.system_orchestrator.refactor_system",
               return_value={"status": "SYSTEM_REFACTOR_VERIFIED"}) as refactor:
        assert mcp_server.system("plan.json", mode="refactor",
                                 out_dir="refactored")[
            "status"] == "SYSTEM_REFACTOR_VERIFIED"
        refactor.assert_called_once()

    with patch("pipeline.system_orchestrator.correct_system",
               return_value={"status": "SYSTEM_CORRECTION_VERIFIED"}) as correct:
        assert mcp_server.system("plan.json", mode="correct",
                                 out_dir="corrected")[
            "status"] == "SYSTEM_CORRECTION_VERIFIED"
        correct.assert_called_once()

    assert mcp_server.system("plan.json", mode="teleport",
                             out_dir="out")["code"] == "invalid_request"
    assert mcp_server.system("plan.json", out_dir="../escape")[
        "code"] == "path_outside_workspace"


def test_mcp_correct_behavior_accepts_strategy_and_hardware(tmp_path, monkeypatch):
    """Milestone 2: the M13-M17 hardening flags reach the correction lane."""
    source = _workspace(tmp_path, monkeypatch)
    hardware = Path("stm32.json")
    hardware.write_text('{"total_sram_bytes": 1}', encoding="utf-8")
    with patch("pipeline.behavior_correction.correct_behavior",
               return_value={"status": "BEHAVIOR_CORRECTION_VERIFIED",
                             "claims": ["HARDWARE_MEMORY_BOUND_PROVEN"]}) as correct:
        result = mcp_server.correct_behavior(
            str(source), "CWE-400", strategy="bounded-pool",
            hardware="stm32.json", struct_size_bytes=16, auto_strategy=True)
    assert result["status"] == "BEHAVIOR_CORRECTION_VERIFIED"
    assert "HARDWARE_MEMORY_BOUND_PROVEN" in result["claims"]
    correct.assert_called_once()
    kwargs = correct.call_args.kwargs
    assert kwargs["strategy"] == "bounded-pool"
    assert kwargs["hardware"].name == "stm32.json"
    assert kwargs["struct_size_bytes"] == 16 and kwargs["auto_strategy"] is True


def test_mcp_implement_code_accepts_v2_refinement_evidence(tmp_path, monkeypatch):
    """Milestone 3: the SOURCE_MODEL_REFINEMENT gate is reachable."""
    source = _workspace(tmp_path, monkeypatch)
    domain = Path("domain.json"); domain.write_text("{}", encoding="utf-8")
    evidence = Path("evidence.json"); evidence.write_text("{}", encoding="utf-8")
    with patch("pipeline.orchestrator.run_implementation_loop",
               return_value={"claim": "SOURCE_MODEL_REFINEMENT"}) as run:
        result = mcp_server.implement_code(
            str(source), v2_reviewed_domain="domain.json",
            v2_validation_evidence="evidence.json")
    assert result["claim"] == "SOURCE_MODEL_REFINEMENT"
    run.assert_called_once()
    kwargs = run.call_args.kwargs
    assert kwargs["v2_reviewed_domain"].name == "domain.json"
    assert kwargs["v2_validation_evidence"].name == "evidence.json"


# ----------------------------- M28: full command parity (28 tools) ----------------

def test_mcp_prove_equivalence_guarded(tmp_path, monkeypatch):
    _workspace(tmp_path, monkeypatch)
    for name in ("b.v2.yaml", "r.v2.yaml"):
        (Path.cwd() / name).write_text("{}", encoding="utf-8")
    (Path.cwd() / "map.json").write_text('{"states": []}', encoding="utf-8")
    with patch("pipeline.equivalence.prove_equivalence",
               return_value={"status": "EQUIVALENCE_PROVED",
                             "claim": "BEHAVIORAL_EQUIVALENCE_PROVED"}) as prove:
        result = mcp_server.prove_equivalence("b.v2.yaml", "r.v2.yaml",
                                              "map.json")
    assert result["claim"] == "BEHAVIORAL_EQUIVALENCE_PROVED"
    prove.assert_called_once()
    escape = mcp_server.prove_equivalence("b.v2.yaml", "r.v2.yaml",
                                          "../map.json")
    assert escape["code"] == "path_outside_workspace"


def test_mcp_generate_traceability_matrix_guarded(tmp_path, monkeypatch):
    _workspace(tmp_path, monkeypatch)
    (Path.cwd() / "d.v2.yaml").write_text("{}", encoding="utf-8")
    (Path.cwd() / "r.req").write_text("REQ-001: x\n", encoding="utf-8")
    with patch("pipeline.traceability.generate_traceability_matrix",
               return_value={"rows": [], "domain": "d.v2.yaml",
                             "coverage": {"mapped": 0, "total": 1}}) as gen:
        result = mcp_server.generate_traceability_matrix(
            "d.v2.yaml", ".", "r.req", "matrix.md")
    assert result["coverage"]["total"] == 1
    gen.assert_called_once()


def test_mcp_verify_unbounded_guarded(tmp_path, monkeypatch):
    _workspace(tmp_path, monkeypatch)
    (Path.cwd() / "c.cpp").write_text("int f(int n){int i=0;while(i<n){i=i+1;}}",
                                       encoding="utf-8")
    with patch("pipeline.unbounded.verify_unbounded",
               return_value={"status": "UNBOUNDED_VERIFIED",
                             "claim": "DEDUCTIVE_PROOF"}) as unbounded:
        result = mcp_server.verify_unbounded("c.cpp",
                                             invariant="i >= 0 && i <= n")
    assert result["claim"] == "DEDUCTIVE_PROOF"
    unbounded.assert_called_once()


def test_mcp_verify_linearizability_guarded(tmp_path, monkeypatch):
    _workspace(tmp_path, monkeypatch)
    (Path.cwd() / "Bank.java").write_text("class B {}", encoding="utf-8")
    (Path.cwd() / "d.v2.yaml").write_text("{}", encoding="utf-8")
    with patch("pipeline.linearizability.verify_linearizability",
               return_value={"status": "LINEARIZABILITY_PROVED",
                             "claim": "CONCURRENT_LINEARIZABILITY_PROVED"}) as lin:
        result = mcp_server.verify_linearizability("Bank.java", "d.v2.yaml")
    assert result["claim"] == "CONCURRENT_LINEARIZABILITY_PROVED"
    lin.assert_called_once()


def test_mcp_verify_distributed_guarded(tmp_path, monkeypatch):
    _workspace(tmp_path, monkeypatch)
    (Path.cwd() / "pp.v2.yaml").write_text("{}", encoding="utf-8")
    with patch("pipeline.distributed.verify_distributed",
               return_value={"status": "DISTRIBUTED_SAFETY_PROVED",
                             "claim": "DISTRIBUTED_SAFETY_PROVED"}) as dist:
        result = mcp_server.verify_distributed(
            "pp.v2.yaml", "cmd_slot,ack_slot",
            "message_loss,duplication,reordering")
    assert result["status"] == "DISTRIBUTED_SAFETY_PROVED"
    kwargs = dist.call_args.kwargs
    assert kwargs["message_fields"] == ["cmd_slot", "ack_slot"]
    assert kwargs["faults"] == ["message_loss", "duplication", "reordering"]


def test_mcp_create_server_registers_all_permitted_tools():
    """Registry is the MCP source of truth; trust actions stay out."""
    from pipeline.capability_registry import mcp_capabilities
    registered = [item.mcp_tool for item in mcp_capabilities()]
    assert len(registered) == 39
    for name in ("prove_equivalence", "generate_traceability_matrix",
                 "verify_unbounded", "verify_linearizability",
                 "verify_distributed", "verify_heap", "verify_hal",
                 "macro_translate", "verify_lockfree",
                 "verify_weak_memory", "verify_wcet", "verify_liveness",
                 "verify_dma", "extract_intrusive_list", "resolve_callbacks",
                 "verify_kernel"):
        assert name in registered
    for excluded in ("sign_artifact", "manage_trust", "promote_domain"):
        assert excluded not in registered


def test_mcp_verify_kernel_uses_registry_schema_and_workspace_guard(tmp_path, monkeypatch):
    _workspace(tmp_path, monkeypatch)
    root = Path.cwd() / "kernel"
    root.mkdir()
    profile = Path.cwd() / "arm.json"
    profile.write_text("{}", encoding="utf-8")
    with patch("pipeline.kernel_lattice.verify_kernel",
               return_value={"status": "KERNEL_EVIDENCE_BUNDLE", "claims": []}) as kernel:
        result = mcp_server.verify_kernel("kernel", ["arm.json"], "monolith.json")
    assert result["status"] == "KERNEL_EVIDENCE_BUNDLE"
    kernel.assert_called_once_with(root, [profile], manifest_name="monolith.json")
    assert mcp_server.verify_kernel("kernel", ["arm.json"], "../kernel.json")["code"] == \
        "invalid_request"


def test_mcp_os_lanes_two_through_five_guarded(tmp_path, monkeypatch):
    """The M37-M40 lanes exposed end-to-end: real deterministic verdicts
    through the MCP wiring (no external judge needed), fail-closed
    refusals, and the workspace-escape guard."""
    _workspace(tmp_path, monkeypatch)
    cwd = Path.cwd()
    harness = ("int main(void){ pthread_t t1, t2;"
               " pthread_create(&t1,0,p,0); pthread_create(&t2,0,c,0);"
               " pthread_join(t1,0); pthread_join(t2,0); return 0; }\n")
    (cwd / "b.c").write_text(
        "#include <pthread.h>\nint ready = 0, data = 0;\n"
        "void *p(void *a){ data = 42; smp_mb(); ready = 1; return 0; }\n"
        "void *c(void *a){ while (!ready){} smp_rmb();"
        " return (void *)data; }\n" + harness, encoding="utf-8")
    barriered = mcp_server.verify_weak_memory("b.c")
    assert barriered["status"] == "BARRIER_CORRESPONDENCE_PROVED"
    assert barriered["weak_memory_safety"] == "unmintable_judge_pending"
    (cwd / "r.c").write_text(
        "#include <pthread.h>\nint ready = 0, data = 0;\n"
        "void *p(void *a){ data = 42; ready = 1; return 0; }\n"
        "void *c(void *a){ while (!ready){} return (void *)data; }\n"
        + harness, encoding="utf-8")
    assert mcp_server.verify_weak_memory("r.c")["code"] == \
        "WEAK_MEMORY_VIOLATION"
    assert mcp_server.verify_weak_memory("../escape.c")["code"] == \
        "path_outside_workspace"

    (cwd / "isr.c").write_text(
        "int handle(int irq) {\n    int status = irq & 3;\n"
        "    for (int i = 0; i < 8; i++) { status = status + 1; }\n"
        "    return status;\n}\n", encoding="utf-8")
    assert mcp_server.verify_wcet("isr.c", {"max_cycles": 500})["status"] \
        == "WCET_BOUND_PROVEN"
    assert mcp_server.verify_wcet("isr.c", {})["code"] == \
        "timing_constraints_missing"

    live = mcp_server.verify_liveness({"transitions": [
        {"from": {"state": "READY"}, "to": {"state": "BUSY"}},
        {"from": {"state": "BUSY"}, "to": {"state": "READY"}}],
        "ready_state": {"state": "READY"}})
    assert live["status"] == "LIVENESS_PROVED"
    stuck = mcp_server.verify_liveness({"transitions": [
        {"from": {"state": "READY"}, "to": {"state": "STUCK"}}],
        "ready_state": {"state": "READY"}})
    assert stuck["code"] == "LIVENESS_VIOLATION"

    (cwd / "eth.c").write_text(
        "void *eth_setup(void) { return dma_map(eth, 0x100); }\n",
        encoding="utf-8")
    dma = mcp_server.verify_dma(
        "eth.c",
        {"kernel_pools": {"object_pool": [0x4000, 0x8000]},
         "devices": {"eth": [0x10000, 0x11000]}},
        {"eth": [0x10000, 0x10800]})
    assert dma["status"] == "DMA_ISOLATION_PROVED"

    (cwd / "list.c").write_text(
        "struct list_head { struct list_head *next, *prev; };\n"
        "struct device { int id; struct list_head links; };\n"
        "void register_dev(struct device *d)"
        " { list_add(&d->links, &device_list); }\n"
        "void unregister_dev(struct device *d)"
        " { list_del(&d->links); }\n", encoding="utf-8")
    assert mcp_server.extract_intrusive_list("list.c", 8)["status"] == \
        "INTRUSIVE_LIST_ABSTRACTED"
    (cwd / "fops.c").write_text(
        "ssize_t dev_read(int fd) { return 0; }\n"
        "extern ssize_t vendor_ioctl(int fd);\n"
        "struct file_operations dev_fops = { .read = dev_read,"
        " .unlocked_ioctl = vendor_ioctl };\n", encoding="utf-8")
    fops = mcp_server.resolve_callbacks("fops.c")
    assert fops["unresolved"] == ["vendor_ioctl"]
    assert fops["machines_for_extraction"] == ["dev_read"]


def test_mcp_verify_heap_guarded(tmp_path, monkeypatch):
    _workspace(tmp_path, monkeypatch)
    (Path.cwd() / "list.rs").write_text(
        "pub struct Node { pub v: i32, pub next: Option<Box<Node>> }\n",
        encoding="utf-8")
    with patch("pipeline.heap.verify_heap",
               return_value={"status": "HEAP_VERIFICATION_PROVED",
                             "claim": "HEAP_REASONING_PROVED"}) as heap:
        result = mcp_server.verify_heap("list.rs")
    assert result["claim"] == "HEAP_REASONING_PROVED"
    heap.assert_called_once()
    non_rust = mcp_server.verify_heap("../escape.rs")
    assert non_rust["code"] == "path_outside_workspace"


def test_mcp_verify_hal_guarded(tmp_path, monkeypatch):
    _workspace(tmp_path, monkeypatch)
    (Path.cwd() / "hal.h").write_text(
        "typedef struct { unsigned enable : 1; } uart_ctrl_t;\n",
        encoding="utf-8")
    with patch("pipeline.hal_mmio.verify_hal",
               return_value={"status": "HAL_VERIFICATION_PROVED",
                             "claim": "HAL_REASONING_PROVED"}) as hal:
        result = mcp_server.verify_hal("hal.h")
    assert result["claim"] == "HAL_REASONING_PROVED"
    hal.assert_called_once()
    escape = mcp_server.verify_hal("../escape.h")
    assert escape["code"] == "path_outside_workspace"


def test_mcp_macro_translate_guarded(tmp_path, monkeypatch):
    _workspace(tmp_path, monkeypatch)
    (Path.cwd() / "macros.json").write_text(
        '{"READ_ONCE": "V2::Read"}', encoding="utf-8")
    (Path.cwd() / "dev.c").write_text(
        "struct dev { int state; };\n"
        "void stop(struct dev *d) { if (READ_ONCE(d->state) == 1) {} }\n",
        encoding="utf-8")
    with patch("pipeline.macro_semantics.synthesize_v2_from_macros",
               return_value={"status": "V2_SYNTHESIZED_FROM_MACROS",
                             "claim": "MACRO_SYNTHESIS_PROVED"}) as run:
        result = mcp_server.macro_translate("dev.c", "macros.json")
    assert result["claim"] == "MACRO_SYNTHESIS_PROVED"
    run.assert_called_once()
    escape = mcp_server.macro_translate("../escape.c", "macros.json")
    assert escape["code"] == "path_outside_workspace"


def test_mcp_verify_lockfree_guarded(tmp_path, monkeypatch):
    _workspace(tmp_path, monkeypatch)
    (Path.cwd() / "ring.c").write_text("#define CAP 4\nint buf[4];\n",
                                       encoding="utf-8")
    with patch("pipeline.lockfree.verify_lockfree",
               return_value={
                   "status": "LOCK_FREE_LINEARIZABILITY_PROVED",
                   "claim": "LOCK_FREE_LINEARIZABILITY_PROVED"}) as run:
        result = mcp_server.verify_lockfree("ring.c")
    assert result["claim"] == "LOCK_FREE_LINEARIZABILITY_PROVED"
    run.assert_called_once()
    assert mcp_server.verify_lockfree("../escape.c")["code"] == \
        "path_outside_workspace"
