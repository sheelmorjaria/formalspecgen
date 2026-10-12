# MCP parity status

This file is generated from the live CLI parser and `mcpdocs/mcp_parity_plan.json`.
Do not edit it by hand.

## Inventory

- Commands mapped: 44 / 44
- Argument declarations mapped: 244 / 244
- Commands with at least one admitted invocation profile: 18 / 44
- Complete command workflows: 0 / 44
- Inventory drift: none
- Full workflow parity: in progress

## Per-command status

| CLI command | Target MCP tool | Workflow | Admission | Completion | Arguments |
| --- | --- | --- | --- | --- | ---: |
| `analyze-codebase` | `analyze_codebase` | `direct_or_task` | `admitted` | `incomplete` | 4 |
| `apply-refactor` | `apply_refactor` | `direct_or_task` | `admitted` | `incomplete` | 6 |
| `architecture` | `architecture` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 5 |
| `assess-security` | `assess_security` | `direct` | `admitted` | `incomplete` | 3 |
| `capabilities` | `describe_capabilities` | `direct` | `admitted` | `incomplete` | 2 |
| `compose` | `compose` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 7 |
| `contract` | `inspect_contract` | `direct` | `admitted` | `incomplete` | 4 |
| `correct-behavior` | `correct_behavior` | `direct_or_task_with_approval` | `adapter_present_not_admitted` | `incomplete` | 12 |
| `design-system` | `design_system` | `resumable` | `adapter_missing` | `incomplete` | 8 |
| `discover-algorithms` | `discover_algorithms` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 7 |
| `doctor` | `doctor_environment` | `direct` | `adapter_present_not_admitted` | `incomplete` | 4 |
| `document-code` | `document_code` | `direct_or_task` | `admitted` | `incomplete` | 7 |
| `domain` | `elicit_domain` | `resumable` | `session_adapter_v2_partial` | `incomplete` | 8 |
| `draft` | `draft_contract` | `resumable` | `reviewed_java_profile_partial` | `incomplete` | 16 |
| `evidence` | `inspect_evidence` | `direct` | `admitted` | `incomplete` | 7 |
| `generate-traceability-matrix` | `generate_traceability_matrix` | `direct` | `admitted` | `incomplete` | 5 |
| `implement` | `implement_code` | `direct_or_task` | `reviewed_java_profile_partial` | `incomplete` | 23 |
| `inspect` | `inspect_code` | `direct` | `admitted` | `incomplete` | 2 |
| `macro-dictionary` | `macro_dictionary` | `direct_or_task` | `compatibility_alias_present_target_missing` | `incomplete` | 6 |
| `manage-trust` | `manage_trust` | `read_or_human_approval` | `approval_coordinator_missing` | `incomplete` | 4 |
| `optimize-algorithm` | `optimize_algorithm` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 6 |
| `project` | `inspect_project` | `direct` | `admitted` | `incomplete` | 5 |
| `promote-domain` | `promote_domain` | `human_approval` | `approval_coordinator_v2_partial` | `incomplete` | 9 |
| `prove-equivalence` | `prove_equivalence` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 4 |
| `remediate` | `remediate_code` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 6 |
| `reverify` | `reverify_composition` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 4 |
| `run` | `get_agent_run` | `direct` | `admitted` | `incomplete` | 3 |
| `security-exploit` | `security_exploit` | `direct` | `admitted` | `incomplete` | 4 |
| `security-inspect` | `security_inspect` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 2 |
| `sign-artifact` | `sign_artifact` | `human_approval` | `approval_coordinator_missing` | `incomplete` | 2 |
| `system` | `system` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 9 |
| `unified-system` | `unified_system` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 6 |
| `validate-architecture` | `validate_architecture` | `direct` | `admitted` | `incomplete` | 3 |
| `validate-domain` | `validate_domain` | `direct` | `admitted` | `incomplete` | 8 |
| `verify` | `verify_code` | `direct_or_task` | `admitted` | `incomplete` | 4 |
| `verify-bisimulation` | `verify_bisimulation` | `direct` | `admitted` | `incomplete` | 4 |
| `verify-distributed` | `verify_distributed` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 4 |
| `verify-hal` | `verify_hal` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 2 |
| `verify-heap` | `verify_heap` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 3 |
| `verify-linearizability` | `verify_linearizability` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 3 |
| `verify-lockfree` | `verify_lockfree` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 2 |
| `verify-refactor` | `verify_refactor` | `direct_or_task_with_approval` | `admitted` | `incomplete` | 4 |
| `verify-unbounded` | `verify_unbounded` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 4 |
| `worker` | `get_work_artifacts` | `direct` | `admitted` | `incomplete` | 3 |

## Drift

`domain`: Resumable V2 domain sessions available; legacy V1 scaffolding, force/replacement and terminal wizard semantics remain outside this profile. Full domain parity is partial.
Coordinator stages: start: `start_domain_session`, inspect: `get_domain_session`, continue: `continue_domain_session`, finalize: `finalize_domain_candidate`.
These stages implement one workflow; they do not increment whole-command completion.

`draft`: Sequential atomic reviewed V2 Java generation and one-candidate native ESC; no source/model refinement. Legacy V1, generative draft clarification, other languages, repair loops, critical architecture orchestration and specialist options remain unmapped.
Coordinator stages: generate: `draft_canonical_contract`, implement: `implement_code`.
These stages implement one workflow; they do not increment whole-command completion.

`implement`: Sequential atomic reviewed V2 Java generation and one-candidate native ESC; no source/model refinement. Legacy V1, generative draft clarification, other languages, repair loops, critical architecture orchestration and specialist options remain unmapped.
Coordinator stages: generate: `draft_canonical_contract`, implement: `implement_code`.
These stages implement one workflow; they do not increment whole-command completion.

`promote-domain`: V2 coordinator available; legacy V1 remains operator-only. Full promote-domain parity is partial. CI qualification is reported separately for the tested V2 combinations.
Coordinator stages: request: `request_domain_promotion`, inspect: `get_domain_promotion`, complete: `complete_domain_promotion`.
These stages implement one workflow; they do not increment whole-command completion.

No command or argument drift detected.
