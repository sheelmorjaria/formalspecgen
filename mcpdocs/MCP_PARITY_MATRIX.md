# Full CLI–MCP parity matrix

**Status:** proposed implementation target, not an enabled catalogue. **Baseline:** `91c6790`.

The retained guide inventory contains 38 built-in commands and 205 argument declarations. Re-enumerate the target checkout and all approved installed command plugins before release. Every option is mapped individually in `mcp_parity_plan.json`.

Tool names below are proposed target names. Existing compatible names should be retained; new coordinator names do not grant human signing or promotion authority to the model.

| CLI command | Target MCP entry | Invocation style | Required completion work |
|---|---|---|---|
| `doctor` | `doctor_environment` | direct | Probe each selected tool through the shared executor; return readiness, not proof. |
| `draft` | `draft_contract` | resumable | Both generative clarification and canonical-domain rendering; retain draft_canonical_contract as a compatible adapter. |
| `implement` | `implement_code` | direct_or_task | Preserve all assurance, budget, postprocessing, refinement, parallel-wrapper, dependency and DMA options. |
| `verify` | `verify_code` | direct_or_task | Retain parse/check/esc and every supported native backend; never substitute a different backend silently. |
| `verify-refactor` | `verify_refactor` | direct_or_task_with_approval | Single-file and multifile preservation; optional signing uses the human approval broker. |
| `optimize-algorithm` | `optimize_algorithm` | direct_or_task | Preserve strategy and destination; generation and proof are separate permissioned stages. |
| `discover-algorithms` | `discover_algorithms` | direct_or_task | All selected strategies, worker limits, output roots and provider/model selection; parent budget bounds fanout. |
| `assess-security` | `assess_security` | direct_or_task | Formal and SAST stages; no-sast keeps its restricted claim rather than full assessment assurance. |
| `security-inspect` | `security_inspect` | direct_or_task | Sandbox actual formal/SAST probes; name does not imply non-executing behavior. |
| `security-exploit` | `security_exploit` | direct | Generate reviewed-source local reproduction templates only; no implicit compile, execution or network activity. |
| `remediate` | `remediate_code` | direct_or_task | Preserve target, report, provider/model and separate output artifact behavior. |
| `correct-behavior` | `correct_behavior` | direct_or_task_with_approval | All strategy/hardware/pool/attempt parameters; report contract change, not contract preservation; obtain approval before any promotion. |
| `verify-bisimulation` | `verify_bisimulation` | direct_or_task | Keep scoped mapping-preflight semantics; do not upgrade this into bounded equivalence. |
| `inspect` | `inspect_code` | direct | Bounded read-only inspection; optional JSON export is a separately authorized write. |
| `apply-refactor` | `apply_refactor` | direct_or_task | Every supported pattern, inspected method, baseline hash, output path and proof gate. |
| `architecture` | `architecture` | direct_or_task | Clarifications, abstraction, generated TLA destination and TLC evidence. |
| `design-system` | `design_system` | resumable | Ordinary and staged design, all supported languages, attempts and TLC limits; clarify without terminal input. |
| `validate-architecture` | `validate_architecture` | direct_or_task | Architecture input, timeout and exact real-TLC observation. |
| `domain` | `elicit_domain` | resumable | Schema V1/V2, restart, project destination and provider; force/reviewed replacement requires constrained approval. |
| `validate-domain` | `validate_domain` | direct_or_task | Candidate name, project root, TLA export, deterministic traversal and real TLC. |
| `promote-domain` | `promote_domain` | human_approval | Callable coordinator requests, tracks and completes a human-authorized promotion; trusted executor remains outside ordinary agent admission. |
| `sign-artifact` | `sign_artifact` | human_approval | Callable coordinator binds exact artifact and key policy; trusted signing service requires authenticated human approval. |
| `manage-trust` | `manage_trust` | read_or_human_approval | List under authorized read policy; add/remove under separately authenticated administrative approval. |
| `verify-heap` | `verify_heap` | direct_or_task | Provider-assisted inference and every reachable native/proof stage retain limits, scope and evidence. |
| `verify-hal` | `verify_hal` | direct_or_task | HAL input and real backend execution; hardware assumptions remain explicit. |
| `macro-dictionary` | `macro_dictionary` | direct_or_task | Dictionary-only, source translation, synthesis and no-verify profiles; retain macro_translate compatibility alias without forcing synthesis. |
| `verify-lockfree` | `verify_lockfree` | direct_or_task | Real backend interleaving checks and bounded claim, with explicit scheduler assumptions. |
| `verify-distributed` | `verify_distributed` | direct_or_task | Fault selection and explicit message fields; model faults do not authorize real network traffic. |
| `verify-linearizability` | `verify_linearizability` | direct_or_task | Source/domain pair, correspondence gate and bounded-history evidence. |
| `verify-unbounded` | `verify_unbounded` | direct_or_task | Explicit or provider-proposed invariant; preserve actual induction verdict and limits. |
| `prove-equivalence` | `prove_equivalence` | direct_or_task | Both domains and mapping; bound inputs and preserve the bounded scope. |
| `generate-traceability-matrix` | `generate_traceability_matrix` | direct | Domain, source tree, requirements file, Markdown output and optional JSON export; no proof inferred from trace links. |
| `compose` | `compose` | direct_or_task | All CLI languages, actors, reviewed-domain roots, output roots, ESC/check-only choice and backend evidence. |
| `reverify` | `reverify_composition` | direct_or_task | Changed-module selection and exact dependency/evidence invalidation. |
| `system` | `system` | direct_or_task | Implement/refactor/correct; provider/model/attempts; aggregate worker budgets; executable option maps to an operator-approved toolchain identity. |
| `unified-system` | `unified_system` | direct_or_task | Evidence input, output root, language and reviewed-V2 directory. |
| `analyze-codebase` | `analyze_codebase` | direct_or_task | Bounded tree extraction and unreviewed candidates; no project hooks or workspace plugin imports. |
| `document-code` | `document_code` | direct_or_task | Deterministic and provider-assisted modes; account for document and candidate-registration writes. |

## Cross-cutting argument policy

`--json` maps to a structured result plus an optional authorized export; `--executable` maps to an operator-controlled toolchain ID; `--signing-key`, reviewed replacement, and equivalent sensitive flags map to approval-bound intent, not model assertion. All other arguments retain semantic meaning and defaults subject to declared policy constraints. No argument is silently discarded.

A target entry is not complete until its input schema, semantic mode coverage, effect plan, actual shared implementation, failure outcomes, evidence and transport tests exist. Modes unavailable solely because a dependency is absent must be distinguished from migration gaps.

## Provenance

Command/argument inventory is taken from the supplied edition-1.1 guide snapshot and checked against relevant browser-readable pinned source sections. The checkout parser, MCP transport and formal tools were not executed during preparation. The option mapping and all proposed names are design recommendations, not observed current support.
