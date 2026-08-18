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
    """28 tools registered; the trust actions and wizards stay out."""
    import mcp_server as module
    import inspect, re
    source = inspect.getsource(module.create_server)
    registered = re.findall(r"[a-z_]+", source.split("for tool in (")[1]
                            .split("):")[0])
    assert len(registered) == 28
    for name in ("prove_equivalence", "generate_traceability_matrix",
                 "verify_unbounded", "verify_linearizability",
                 "verify_distributed"):
        assert name in registered
    for excluded in ("sign_artifact", "manage_trust", "promote_domain"):
        assert excluded not in registered
