from pathlib import Path
from pipeline.capability_registry import capability
from pipeline.smp_scheduler import verify_smp_scheduler

ARTIFACT = Path("examples/formalkernel/kernel/scheduler/smp_scheduler.json")


def test_parameterized_smp_scheduler_invariants():
    verdict = verify_smp_scheduler(ARTIFACT)
    if verdict["status"] == "judge_pending":
        assert verdict["judge_pending"] == "tlapm"
        return
    assert verdict["status"] == "SMP_SCHEDULER_INVARIANTS_PROVED"
    assert verdict["parameterized"] is True
    assert verdict["scheduler_liveness_proved"] is False
    assert verdict["load_balancer_implementation_refinement_proved"] is False


def test_registry_locks_smp_runtime_claims():
    milestone = capability("m78_scalable_smp_scheduler").milestone
    assert milestone is not None
    assert "SMP_IMPLEMENTATION_REFINEMENT_PROVED" in milestone.claims_forbidden
