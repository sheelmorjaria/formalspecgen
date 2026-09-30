# MCP parity status

This file is generated from the live CLI parser and `mcpdocs/mcp_parity_plan.json`.
Do not edit it by hand.

## Inventory

- Commands mapped: 44 / 44
- Argument declarations mapped: 229 / 229
- Commands with at least one admitted invocation profile: 15 / 44
- Complete command workflows: 0 / 44
- Inventory drift: none
- Full workflow parity: in progress

## Per-command status

| CLI command | Target MCP tool | Workflow | Admission | Completion | Arguments |
| --- | --- | --- | --- | --- | ---: |
| `analyze-codebase` | `analyze_codebase` | `direct_or_task` | `admitted` | `incomplete` | 4 |
| `apply-refactor` | `apply_refactor` | `direct_or_task` | `admitted` | `incomplete` | 6 |
| `architecture` | `architecture` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 5 |
| `assess-security` | `assess_security` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 3 |
| `capabilities` | `describe_capabilities` | `direct` | `admitted` | `incomplete` | 2 |
| `compose` | `compose` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 7 |
| `contract` | `inspect_contract` | `direct` | `admitted` | `incomplete` | 4 |
| `correct-behavior` | `correct_behavior` | `direct_or_task_with_approval` | `adapter_present_not_admitted` | `incomplete` | 12 |
| `design-system` | `design_system` | `resumable` | `adapter_missing` | `incomplete` | 8 |
| `discover-algorithms` | `discover_algorithms` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 7 |
| `doctor` | `doctor_environment` | `direct` | `adapter_present_not_admitted` | `incomplete` | 4 |
| `document-code` | `document_code` | `direct_or_task` | `admitted` | `incomplete` | 7 |
| `domain` | `elicit_domain` | `resumable` | `adapter_missing` | `incomplete` | 8 |
| `draft` | `draft_contract` | `resumable` | `compatibility_alias_present_target_missing` | `incomplete` | 12 |
| `evidence` | `inspect_evidence` | `direct` | `admitted` | `incomplete` | 7 |
| `generate-traceability-matrix` | `generate_traceability_matrix` | `direct` | `admitted` | `incomplete` | 5 |
| `implement` | `implement_code` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 20 |
| `inspect` | `inspect_code` | `direct` | `admitted` | `incomplete` | 2 |
| `macro-dictionary` | `macro_dictionary` | `direct_or_task` | `compatibility_alias_present_target_missing` | `incomplete` | 6 |
| `manage-trust` | `manage_trust` | `read_or_human_approval` | `approval_coordinator_missing` | `incomplete` | 4 |
| `optimize-algorithm` | `optimize_algorithm` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 6 |
| `project` | `inspect_project` | `direct` | `admitted` | `incomplete` | 5 |
| `promote-domain` | `promote_domain` | `human_approval` | `approval_coordinator_missing` | `incomplete` | 6 |
| `prove-equivalence` | `prove_equivalence` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 4 |
| `remediate` | `remediate_code` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 6 |
| `reverify` | `reverify_composition` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 4 |
| `run` | `get_agent_run` | `direct` | `admitted` | `incomplete` | 3 |
| `security-exploit` | `security_exploit` | `direct` | `admitted` | `incomplete` | 4 |
| `security-inspect` | `security_inspect` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 2 |
| `sign-artifact` | `sign_artifact` | `human_approval` | `approval_coordinator_missing` | `incomplete` | 2 |
| `system` | `system` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 9 |
| `unified-system` | `unified_system` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 6 |
| `validate-architecture` | `validate_architecture` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 3 |
| `validate-domain` | `validate_domain` | `direct_or_task` | `adapter_present_not_admitted` | `incomplete` | 3 |
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

No command or argument drift detected.
