# Strict MCP admission guide

Strict MCP exposes invocation profiles, not whole commands. A profile is the combination of a
command, mode, language, backend, provider policy, workspace effects, and evidence behavior that
has completed admission testing. An unlisted combination fails before side effects with
`ISOLATION_UNSUPPORTED` and `claim=NO_PROOF`.

The full migration inventory is generated from the live CLI parser and the reviewed target plan.
See [MCP_PARITY_STATUS.md](MCP_PARITY_STATUS.md) for the current per-command completion report.
Being inventoried or having a legacy handler does not make a workflow admitted. Likewise, having
one admitted profile does not make the full CLI command complete. The generated report therefore
shows both **commands with at least one admitted invocation profile** and **complete command
workflows**.

Completion is calculated rather than asserted by a standalone Boolean. Every mapped argument must
be marked verified and appear in the observed MCP handler schema; all declared command variants
must be covered; and revision-bound passing cases must demonstrate request equivalence, argument
delivery, effect enforcement, result equivalence, and real MCP transport. Results written into the
reviewed plan are not evidence. A dedicated CI runner executes the declared test nodes, rejects
failures and skips, records the clean Git revision, observed transport schema/result digests, and
publishes the derived manifest, raw JUnit XML, and redacted pytest output as workflow artifacts.
Transport collection is implemented by reviewed per-workflow adapters rather than a command-name
special case in the runner. Resumable and approval workflows
additionally require replay/session and approval-security cases. Missing or stale runner evidence
keeps the command incomplete even when its restricted profile remains useful.

The committed parity report deliberately has no same-commit execution record and therefore remains
the evidence-free baseline. The `MCP transport and parity acceptance` CI job publishes the
revision-bound report in which workflows supported by that run may become complete. This avoids
claiming that a committed report tested the commit that contains itself.

A profile is a permission ceiling, not a bundle of permissions silently granted to every matching
request. An invocation receives only the intersection of its explicitly requested effects and that
ceiling. Omitting execution, publication, provider access, or writes means the corresponding effect
boundary will reject the operation even when the broader profile could have allowed it.

> Strict MCP exposes only explicitly admitted invocation profiles. Executing workflows require
> approved isolation and evidence publication across all execution stages. Non-executing workflows
> require bounded processing and explicitly constrained workspace and provider access. Unsupported
> combinations fail before side effects. Human promotion, signing, and trust administration remain
> outside agent authority.

## Current admitted profiles

| Workflow | CLI | Strict MCP | Modes / language / backend | Workspace effects | Provider access | Evidence | Human approval |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `verify_code` | Yes | Admitted | `parse`, `check`, `esc` / Java or JML / OpenJML | Read immutable input; strict execution; optional new JSON export | None | Exact execution observation and terminal manifest | Required for any later promotion or signing |
| `verify_code` | Yes | Admitted | `parse`, `check` / Rust / rustc | Reviewed and transformed compiler inputs are both snapshotted; strict execution | None | Static-check observation and terminal manifest; no proof claim | Required for any later promotion or signing |
| `verify_code` | Yes | Admitted | `esc` / Rust / Prusti or Kani | Read immutable input; strict execution | None | Deductive Prusti or bounded Kani evidence with terminal manifest | Required for any later promotion or signing |
| `verify_code` | Yes | Admitted | `esc` / C or C++ / Frama-C WP or ESBMC | Strict compiler/preflight and verifier stages | None | Deductive C or bounded C++ evidence with every execution stage | Required for any later promotion or signing |
| `verify_code` | Yes | Admitted | `parse`, `check` / C or C++ / structured rejection | Read request metadata; no external execution | None | Immutable unsupported-mode result | None |
| `verify_refactor` | Yes | Admitted, unsigned subset | `preserve` / Java or JML, Rust, C, or C++ / language verifier | Read immutable baseline and candidate snapshots; strict baseline/candidate execution; optional new JSON export | None | One immutable bundle binding both input manifests, semantic surfaces, proof-trust inventories, actual observations, claim limits, and admission | Signing intent returns `APPROVAL_REQUIRED`; authenticated signing parity is not yet implemented |
| `inspect_code` | Yes | Admitted | `inspect` / Java or JML / built-in inspector | Read one bounded workspace input; optionally create one new JSON export beneath the designated output root | None | Structured findings and optional unreviewed export; no proof receipt | Required before applying proposed changes |
| `document_code` | Yes | Admitted | `deterministic` or `provider-assisted` / Java / built-in documentation | Read one bounded source; create new artifacts only beneath the designated output root | GLM, OpenAI, or Ollama through server-controlled endpoints and approved models | Unreviewed Markdown, V2 candidate, and optional JSON result; no proof receipt | Required before review, use, or promotion |
| `submit_work_item` | No coordinator CLI | Admitted | `submit` / approved workflow and A2A 1.0 worker | Read current revision; append service task state; dispatch to an approved worker | Worker endpoint only; no model/provider permission | Hash-chained worker-task events and unaccepted proposal references | Trusted acceptance and human merge review remain separate |
| `get_work_item` | No coordinator CLI | Admitted | local read or explicit remote refresh | Principal-scoped service-state read; refresh separately adds dispatch and state-write authority | Worker endpoint only for refresh | Current worker state; no proof claim | None for status; acceptance remains separate |
| `get_work_artifacts` | No coordinator CLI | Admitted | digest-bound artifact references | Principal-scoped service-state read only | None | Unaccepted worker artifact identities | Required before retrieval/application/integration |
| `cancel_work_item` | No coordinator CLI | Admitted | remote task cancellation | Principal-scoped state read/write and approved worker dispatch | Approved worker endpoint | Hash-chained cancellation outcome; no proof claim | None |
| `start_agent_run` / `resume_agent_run` | No supervisor CLI | Admitted | supervised `inspect` then `verify` / Java or JML / OpenJML | Exact source read; strict verification; protected service-state read/write | None | Child verification manifest plus no-replace goal review | Required for contract changes, applying source changes, signing, promotion, trust changes, or merge |
| `get_agent_run` / `cancel_agent_run` | No supervisor CLI | Admitted | principal-scoped local state | Protected service-state read, plus state write and terminal-review publication for cancellation | None | Hash-chained run events and no-replace cancellation review; cancellation never becomes proof | None |

Admission is checked before input processing and again at concrete execution and evidence-publication
boundaries. The strict catalogue is generated from these registry profiles, so an unsupported tool
is not registered merely because it has a Python handler.

The admitted adapters share typed application requests and a permission-carrying workflow context.
The request owns default resolution, effective language/backend selection, and effect planning.
The context owns workspace/output scopes and granted effects; child stages may narrow that context
but cannot add authority. Results expose separate workflow, verification, admission, execution,
publication, and approval dimensions under `workflow_result` while retaining compatible top-level
fields.

Published verification evidence records requested and granted effects, the complete canonical
profile definition and its SHA-256 digest, and the admission-policy version. This binds a run to the
policy contents that authorized it rather than relying on a mutable profile name.

`verify_code` accepts `source`, `mode`, `backend`, and optional `result_export`. The backend field
selects Prusti or Kani only for Rust ESC; Java/JML, C, and C++ resolve to their named backend without
silent substitution. A result export is a separate invocation profile requiring the complete read,
execution, evidence-publication, and new-write effect set. Omitting the write effect cannot be
repaired later at the file boundary. Existing destinations, absolute paths, traversal, and unsafe
symlink components are rejected without replacing prior data.

The provisioned acceptance job installs checksum-pinned OpenJML, Prusti, Kani, and Frama-C bundles
plus ESBMC, enters a delegated cgroup leaf, and exercises positive and negative fixtures through the
real stdio MCP server. The revision-bound parity report may count `verify` complete only when that
job also observes the expected bounded/deductive claim distinctions and validates publication.

`verify_refactor` accepts `baseline`, a candidate file or collaborator directory as `refactored`,
optional `result_export`, and `signing_intent`. The unsigned profiles preserve the existing
contract, proof-trust, semantic-context, and collaborator checks, then verify both snapshots through
strict execution. Negative results can be exported through the same no-replace publisher and cannot
erase successful baseline observations. Signing intent never grants signing authority or exposes a
key to MCP; it stops with `APPROVAL_REQUIRED`. Consequently this admitted subset remains an
incomplete CLI workflow until an authenticated human signing coordinator has acceptance evidence.

The A2A coordinator profiles are additional MCP-only application capabilities, so they do not
alter the 38-command CLI parity denominator or mark a CLI workflow complete. Their policy and
append-only state live outside the agent workspace. Endpoint, Agent Card digest, principal,
credentials, path ceilings, workflow allowlists, and budgets are operator-controlled. See
[A2A_COORDINATION.md](A2A_COORDINATION.md). The provisioned A2A job exercises both the official
A2A 1.0 client/server round trip and submission through the real MCP stdio server.

The supervised goal tools are also MCP-only and do not alter the CLI parity denominator. Their
operator-owned state is outside the workspace, while the exact approved source remains bound by Git
revision and SHA-256. See [AGENTIC_SUPERVISOR.md](AGENTIC_SUPERVISOR.md). The initial profile accepts
only a typed `inspect` then `verify` proposal; it cannot edit source or contracts, call a provider,
delegate work, approve, sign, promote, or merge.

## Available through CLI but not admitted to strict MCP

The following legacy MCP handlers remain classified `unsupported`. Their CLI availability is
unchanged, but no command/mode/backend profile below is authorized for unattended MCP use:

```text
validate_architecture  implement_code        analyze_codebase
assess_security        security_inspect      security_exploit
remediate_code         correct_behavior      apply_refactor
verify_bisimulation    optimize_algorithm
discover_algorithms    validate_domain        compose
reverify_composition   unified_system         draft_canonical_contract
architecture           system                 prove_equivalence
generate_traceability_matrix
verify_unbounded       verify_linearizability verify_distributed
verify_heap            verify_hal             macro_translate
verify_lockfree        verify_weak_memory     verify_wcet
verify_liveness        verify_dma             extract_intrusive_list
resolve_callbacks      doctor_environment
```

This classification does not mean that every handler is unsafe. It means its complete reachable
workflow has not yet demonstrated the required constraints. For example, `doctor_environment`
launches executable version/help probes and therefore cannot be admitted as non-executing.
The documentation handler accepts `source`, a relative Markdown `out`, a relative `project_root`
namespace for candidate placement, `no_llm`, `provider`, `model`, and an optional relative JSON
`result_export`. It reads at most one MiB and publishes at most two MiB across the generated
artifacts. Its output root defaults to `.formalspecgen/mcp-output` and may be configured by the
trusted server through `FORMALSPECGEN_MCP_OUTPUT_ROOT`. Absolute paths, traversal, symlinked output
components, and existing destinations fail closed.

Deterministic requests receive no provider authority. Provider-assisted requests separately
request `provider_access`; endpoints and credentials remain server-controlled through the normal
provider configuration. An explicit model is accepted only when it is the configured default or
appears in the trusted `FORMALSPECGEN_MCP_DOCUMENT_MODELS` comma-separated `provider:model`
allowlist. One narrative request is made, its selected and reported model are recorded without
credentials, and provider or schema failure stops the workflow without deterministic fallback.
Provider prose and all published artifacts remain explicitly unreviewed and do not carry a proof
receipt.

The inspection handler accepts `source` and optional `result_export`. Inputs are limited to one
MiB. Without an export it receives read authority only; with a relative `.json` export it must match
the separate controlled-write profile. The result is published without replacement beneath the
same server-designated output root and remains an unreviewed inspection result, not proof evidence.

## Admission paths

### Non-executing profiles

A non-executing profile must have bounded input traversal, processing time, and response size. It
must not launch external commands, evaluate submitted code, run project hooks, contact a provider,
or write files unless those effects are separately declared. A deterministic transformation should
initially write only new artifacts beneath a designated output root and must never promote them.

### Executing profiles

Every reachable compiler, verifier, generated program, subprocess, and delegated backend must use
the approved executor. Inputs come from an immutable snapshot; writable locations are bounded and
disposable; networking is denied unless a distinct reviewed profile permits it; descendants share
enforced resource limits; and infrastructure failure never falls back to unrestricted execution.
The actual execution observation—not a reconstructed command—must reach immutable publication and
the MCP response.

### Provider-assisted profiles

Provider access is never implied by a non-executing or transformation label. A future admitted
profile must bind server-controlled endpoint/model selection, explicit source-export permission,
request budgets, and a no-fallback policy. Credentials remain in the trusted controller and are
excluded from generated-program environments and evidence logs. Provider output remains an
untrusted proposal until independently reviewed and checked.

### A2A coordination profiles

Remote worker dispatch is separate from local execution and provider access. A coordinator
profile may read/write service-owned task state and contact an approved worker, but cannot acquire
compiler execution, provider, signing, promotion, or source-application authority. A work item's
`authority_ref` is resolved against operator policy; it is not a serialized grant. Worker task
completion remains `NO_PROOF` with acceptance pending until trusted integration validates and
tests the proposal on the integrated revision.

## Permanent human boundary

`promote_domain`, `sign_artifact`, and `manage_trust` are human trust actions. They cannot acquire
an MCP invocation profile even if their implementation could run in a sandbox. An agent may prepare
a review package, but it cannot accept, sign, or change reviewer trust policy.

## Deployment

Leave `FORMALSPECGEN_MCP_STRICT_JAVA_ONLY` unset for the strict catalogue. Setting it to `0` restores
the full legacy catalogue for explicitly trusted local compatibility work; it is not an admission
mechanism and does not grant those workflows strict-isolation or durable-publication claims.

For a supervised agent deployment, install a pinned package outside the agent-editable checkout,
run the MCP service in a delegated cgroup-v2 leaf, and expose only the default strict catalogue.
