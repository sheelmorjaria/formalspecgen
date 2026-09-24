# MCP parity status

This file is generated from the live CLI parser and `mcpdocs/mcp_parity_plan.json`.
Do not edit it by hand.

## Inventory

- Commands mapped: 38 / 38
- Argument declarations mapped: 205 / 205
- Strictly admitted command workflows: 3 / 38
- Inventory drift: none
- Full workflow parity: in progress

## Per-command status

| CLI command | Target MCP tool | Workflow | Adapter/admission status | Arguments |
| --- | --- | --- | --- | ---: |
| `analyze-codebase` | `analyze_codebase` | `direct_or_task` | `adapter_present_not_admitted` | 4 |
| `apply-refactor` | `apply_refactor` | `direct_or_task` | `adapter_present_not_admitted` | 6 |
| `architecture` | `architecture` | `direct_or_task` | `adapter_present_not_admitted` | 5 |
| `assess-security` | `assess_security` | `direct_or_task` | `adapter_present_not_admitted` | 3 |
| `compose` | `compose` | `direct_or_task` | `adapter_present_not_admitted` | 7 |
| `correct-behavior` | `correct_behavior` | `direct_or_task_with_approval` | `adapter_present_not_admitted` | 12 |
| `design-system` | `design_system` | `resumable` | `adapter_missing` | 8 |
| `discover-algorithms` | `discover_algorithms` | `direct_or_task` | `adapter_present_not_admitted` | 7 |
| `doctor` | `doctor_environment` | `direct` | `adapter_present_not_admitted` | 4 |
| `document-code` | `document_code` | `direct_or_task` | `admitted` | 7 |
| `domain` | `elicit_domain` | `resumable` | `adapter_missing` | 8 |
| `draft` | `draft_contract` | `resumable` | `compatibility_alias_present_target_missing` | 12 |
| `generate-traceability-matrix` | `generate_traceability_matrix` | `direct` | `adapter_present_not_admitted` | 5 |
| `implement` | `implement_code` | `direct_or_task` | `adapter_present_not_admitted` | 20 |
| `inspect` | `inspect_code` | `direct` | `admitted` | 2 |
| `macro-dictionary` | `macro_dictionary` | `direct_or_task` | `compatibility_alias_present_target_missing` | 6 |
| `manage-trust` | `manage_trust` | `read_or_human_approval` | `approval_coordinator_missing` | 4 |
| `optimize-algorithm` | `optimize_algorithm` | `direct_or_task` | `adapter_present_not_admitted` | 6 |
| `promote-domain` | `promote_domain` | `human_approval` | `approval_coordinator_missing` | 6 |
| `prove-equivalence` | `prove_equivalence` | `direct_or_task` | `adapter_present_not_admitted` | 4 |
| `remediate` | `remediate_code` | `direct_or_task` | `adapter_present_not_admitted` | 6 |
| `reverify` | `reverify_composition` | `direct_or_task` | `adapter_present_not_admitted` | 4 |
| `security-exploit` | `security_exploit` | `direct` | `adapter_present_not_admitted` | 4 |
| `security-inspect` | `security_inspect` | `direct_or_task` | `adapter_present_not_admitted` | 2 |
| `sign-artifact` | `sign_artifact` | `human_approval` | `approval_coordinator_missing` | 2 |
| `system` | `system` | `direct_or_task` | `adapter_present_not_admitted` | 9 |
| `unified-system` | `unified_system` | `direct_or_task` | `adapter_present_not_admitted` | 6 |
| `validate-architecture` | `validate_architecture` | `direct_or_task` | `adapter_present_not_admitted` | 3 |
| `validate-domain` | `validate_domain` | `direct_or_task` | `adapter_present_not_admitted` | 3 |
| `verify` | `verify_code` | `direct_or_task` | `admitted` | 4 |
| `verify-bisimulation` | `verify_bisimulation` | `direct_or_task` | `adapter_present_not_admitted` | 4 |
| `verify-distributed` | `verify_distributed` | `direct_or_task` | `adapter_present_not_admitted` | 4 |
| `verify-hal` | `verify_hal` | `direct_or_task` | `adapter_present_not_admitted` | 2 |
| `verify-heap` | `verify_heap` | `direct_or_task` | `adapter_present_not_admitted` | 3 |
| `verify-linearizability` | `verify_linearizability` | `direct_or_task` | `adapter_present_not_admitted` | 3 |
| `verify-lockfree` | `verify_lockfree` | `direct_or_task` | `adapter_present_not_admitted` | 2 |
| `verify-refactor` | `verify_refactor` | `direct_or_task_with_approval` | `adapter_present_not_admitted` | 4 |
| `verify-unbounded` | `verify_unbounded` | `direct_or_task` | `adapter_present_not_admitted` | 4 |

## Drift

No command or argument drift detected.
