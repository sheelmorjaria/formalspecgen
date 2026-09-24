# Full CLI-to-MCP workflow parity under enforced permissions

**Status:** implementation specification; no repository changes are included.

**Baseline:** FormalSpecGen `91c6790`. Re-enumerate the checkout being implemented. This baseline is not an assertion about the current moving `main` branch.

**Release objective:** every functional CLI command, semantic mode, and supported option has a usable MCP workflow. The workflow must preserve the CLI's operational meaning and evidence limits while enforcing invocation-specific authority. A listing of tools, compatibility-mode exposure, or a handler that always returns `ISOLATION_UNSUPPORTED` does not meet this objective.

## 1. Definition of parity

For equivalent inputs, approved authority, tool configuration, and source snapshots, CLI and MCP must dispatch the same application workflow and produce equivalent semantic results. Interface presentation, run IDs, timestamps, temporary paths, and serialized transport may differ. A stronger policy may reject a request, but that must be an explicit authorization or environment decision—not an undisclosed missing adapter.

Parity includes command discovery, option/default/choice mapping, clarification and restart steps, selected language/backend/provider, source and output effects, assurance mode, terminal errors, bounded claims, evidence, cancellation, and human approval when required.

Do not remove CLI commands, choices, or existing functionality to manufacture a coverage result. Do not copy a legacy bug simply for equality: fix the shared service and document intentional behavioral changes in both interfaces.

### Inventory

The retained guide snapshot has **38 built-in commands and 205 command-specific argument declarations**. `MCP_PARITY_MATRIX.md` maps every command; `mcp_parity_plan.json` maps every declaration. The inventory was supplied by the earlier guide and cross-checked with relevant pinned source sections, not regenerated from a running checkout during this preparation.

At implementation time, enumerate the real parser, registered modes, installed approved command plugins, and current MCP schemas. Include hidden arguments and shared parent arguments. Record root `--help`, `--version`, REPL interactions, and legacy MCP-only tools separately. A static count is a baseline, not the long-term coverage oracle.

## 2. Discovery, authorization, and readiness are separate

The operator-authorized MCP client should discover every implemented workflow adapter. Tool descriptions must explain behavior, claim limits, readiness and any approval boundary. Discovery does not grant execution permissions or reveal sensitive registry/workspace details to other principals.

For each invocation:

1. Validate the typed request and resolve the operation/mode.
2. Derive the effects required by that specific workflow and request.
3. Resolve the caller/workspace/provider/toolchain policy.
4. Reject or request approval if the required effects are unavailable.
5. Check environment readiness without performing undeclared probes.
6. Execute with effect checks and publish the appropriate result.

Migration gaps must be reported separately from permission denial, missing dependencies, or a negative verification result. During development an incomplete adapter may remain unregistered; the full-parity release cannot count it as complete. A CLI workflow whose intended existing outcome is judge-pending or a scoped non-proof report may return that same outcome through MCP; parity does not require inventing a missing formal backend or upgrading its claim. This is distinct from an MCP adapter that is simply unimplemented.

Do not make strict mode a switch that means 'Java only'. Retain strict enforcement as the default and replace the language-specific catalogue filter with policy-driven admission for all migrated lanes. Deprecate the old environment variable with an explicit compatibility plan; do not silently change the meaning of a deployed setting. No user should need to disable enforcement to access a completed workflow.

## 3. One application layer, two adapters

Refactor terminal-specific orchestration into reusable typed services. The CLI should handle argparse, terminal presentation and human interaction. MCP should handle schemas, caller context and transport. Both call the same workflow implementation.

Conceptual structure (proposed, not existing module names):

```text
CLI request adapter ─┐
                     ├─ shared workflow request and service
MCP request adapter ─┘       │
                              ├─ admission / approval
                              ├─ bounded reads and staged writes
                              ├─ provider broker
                              ├─ strict execution
                              ├─ claim policy
                              └─ immutable publication
```

Extend the existing registry and `mcp_policy.py` rather than build a second independent allowlist. Each workflow definition should identify its request and response schemas, CLI mapping, application handler, effect planner, supported semantic profiles, claim ceiling, evidence policy, session behavior and approval requirements.

Generate or cross-check argparse and MCP schemas from the same definitions. Existing named MCP tools may remain compatibility aliases, but aliases must reach the same dispatcher and may not bypass admission. A generic shell command or unvalidated argv tool is not an acceptable shortcut.

## 4. Complete option-level behavior

Map every positional and option, including defaults, enums, list/repeat semantics, nullable values and mode-dependent requirements. Where transport or authority requires a different representation, record the exact semantic mapping.

| CLI feature | Required MCP treatment |
|---|---|
| `--json` / stdout selection | Structured MCP result plus optional authorized export. Do not run the CLI just to scrape JSON. |
| Output directories and files | Typed destination or artifact reference with root restrictions and explicit create/replace policy. |
| `--provider`, `--model`, fallback provider | Resolve a server-approved endpoint/model; require independent data-export permission and explicit fallback approval. |
| `--backend`, `--lang`, abstraction and assurance modes | Preserve every supported variant; do not silently substitute a more convenient backend. |
| `--no-esc`, `--no-verify`, `--no-sast`, method-only proof | Preserve the weaker assurance and accurately lower the claim. |
| `--signing-key`, promotion acceptance hashes | Route into exact-artifact approval; the argument is intent, not proof of human consent. |
| `--force`, reviewed-domain replacement, trust-relevant accepted passes | Support the requested operation under an explicit replacement/trust approval policy; do not turn a flag into authority. |
| Hidden `system --executable` | Map to an operator-configured toolchain identity, with no arbitrary executable supplied by the model. |
| Worker, timeout and retry budgets | Enforce aggregate server ceilings; report effective limits and stop if the required assurance cannot be supported. |
| Clarification restart / skip options | Represent explicit session transitions and unresolved assumptions; do not fabricate answers. |

The existing `implement`, `compose`, `system` and `macro-dictionary` families require particular attention: a handler name alone does not cover every CLI branch. Dictionary inspection, translation, synthesis and synthesis without a proof are distinct macro workflows.

All baseline option mappings are design requirements in `mcp_parity_plan.json`, not a claim that current handlers implement them.

## 5. Preserve least privilege through the workflow

Retain requested/granted-effect attenuation and canonical admission-profile evidence. Add caller authorization, resource scopes and workflow context around it, not a blanket grant.

A useful invariant for the trusted planner is:

```text
required effects = effect_plan(validated workflow request)
granted effects  = requested effects ∩ profile ceiling ∩ caller policy
required effects must be a subset of granted effects before that stage runs
child authority must not exceed parent authority
```

The model may request a workflow; it must not supply trusted labels such as 'this is read-only', an arbitrary backend executable, or 'approval=true'. The server computes those meanings.

Recheck permissions at actual read, write, provider, execution, publication and approval boundaries. Scope permission by workspace/input snapshot, destination, provider identity, budgets and workflow ID, not only by a Boolean effect name. Denied operations must not perform the forbidden action before returning the error.

Do not silently switch to compatibility mode, shell out around the executor, or retry with broader permissions. A changed plan or new effect after clarification requires fresh admission/consent. Revocation and expiry must be checked before a resumed sensitive stage.

Account for run/session storage and audit records explicitly under a service-state policy; do not hide unrestricted filesystem writes behind 'non-executing'. Service-owned security auditing is not permission for the candidate to write workspace evidence.

Approved plugins belong to the operator trust boundary. Never discover/import executable command plugins from an agent-editable project merely because the project declares one.

## 6. Complete execution and provider coverage

Every external compiler, verifier, tool probe, source preprocessor, SAST scanner, build helper and generated program reachable from an admitted workflow must use the shared strict execution path. This includes native verifiers, TLC, solver subprocesses, doctor smoke probes, security workflows and child component orchestration.

Refactor in-process evaluation that can execute submitted code or load untrusted plugins into an isolated stage, or reject it. Cheap read-only parsing still needs input, recursion, traversal, time and output limits.

Execution-unit controls must include the source snapshot, allowlisted environment, network policy, memory and process accounting, bounded temporary/work storage, output caps, complete process-tree cleanup and cancellation. Preserve actual observations through the result and terminal manifest. Resource/tool initialization failures are infrastructure failures, not program counterexamples.

Provider calls use a distinct trusted broker. Pin the provider endpoint/model, input disclosure scope, prompt size, token/cost/attempt budget, retention policy and credential placement. A local provider is still a separate data boundary. Explicit fallback is a new allowed destination, not an unrestricted retry mechanism. Credentials never enter generated execution environments, prompts or public evidence.

Parent budgets must bound all child runs and provider attempts together. A four-worker system should not multiply an approved budget without authorization.

## 7. Interactive workflows and long runs

Implement resumable sessions for `domain`, generative `draft` and `design-system`. Support equivalent structured answers supplied up front when no clarification is necessary. No handler may block on terminal stdin.

A portable application pattern is:

```text
start workflow → questions or run handle
submit answers → revised plan or next questions
resume workflow → execution or approval pending
read status/result → bounded progress and final evidence
cancel → stop descendants and record a non-success terminal outcome
```

Use protocol-native elicitation/tasks only when the actual negotiated protocol, SDK and client support them. Keep ordinary typed continuation/status tools as a tested fallback; do not assume a particular AiderDesk build supports every optional protocol capability. Form answers are not signing credentials or independently authenticated human approvals.

Bind run IDs to principal and workspace. Add idempotency keys for mutations and provider spending; replaying a completed request must not duplicate publication, signing, source replacement or model calls. Reconnect/resume must revalidate authority and input digests. Ensure stdin/stdout remain valid MCP transport and send diagnostic logs separately.

Proposed application states should separate request progress from verification outcome, for example queued/running/awaiting-input/awaiting-approval/completed/failed/cancelled. These are design concepts, not assertions about existing status enums.

## 8. All trust workflows remain accessible, with human authority

Expose typed request/status/continuation coordinators for `promote-domain`, `sign-artifact` and `manage-trust`. Listing authorized reviewers may have read-only policy; adding/removing keys and promotion/signing require the corresponding authenticated human authority.

The raw trust executor remains excluded from ordinary agent invocation profiles. Register a separate approval coordinator that cannot mint approval or execute the trusted action on its own. Completion happens in a trusted signer/admin service after independent approval, then the MCP workflow returns the actual receipt.

Bind approval to principal, action, exact source/artifact/evidence digests, destination, key or registry identity, expected current registry version, admission-profile hash, expiry and a single-use nonce. Re-read/revalidate those bindings immediately before committing. Reject forged, expired, replayed, wrong-principal or stale-artifact approval.

A key identifier, `accept_candidate_sha256`, UI tool-confirmation click, or model-supplied Boolean is not sufficient cryptographic/administrative authority. Keep reviewer keys and approval secrets out of the model and worker sandboxes. Signing is not verification; approval does not upgrade a proof claim.

This is full workflow parity: the agent can start, follow, and receive the result of every CLI workflow. It does not mean the agent inherits the operator's signing identity.

## 9. Evidence and result continuity

Use one typed result envelope with separate fields for workflow completion, backend verification, claim, request satisfaction, execution compliance, publication state and approval state. Reuse existing status/claim semantics rather than conflate them.

Every execution-bearing completed workflow must publish the evidence required by its profile. Record the immutable input snapshot, actual execution observations, requested/granted effects, complete canonical policy and hash, admission-policy version, dependency/tool identities, effective parameters and output digests. Parent results reference child evidence; they do not upgrade a child failure or missing obligation.

Read-only findings and deterministic artifacts need provenance appropriate to their scope, not invented proof receipts. Readiness metadata stays `NO_PROOF`. Template PoCs are not automatically executed or represented as proven exploits. A hash-consistent manifest does not by itself prove semantic correctness.

Only the trusted publisher can write authoritative evidence. Publication failure must prevent a successful evidence-bearing terminal response. Interrupted runs remain visibly incomplete; retries cannot overwrite prior committed artifacts. Enforce authorization on evidence and run-result retrieval too.

## 10. Repository work packages

These are dependency-ordered implementation packages within ONE full-parity objective, not a proposal to stop after a few tools.

| Package | Main integration points | Exit condition |
|---|---|---|
| Inventory and contract | CLI parser, capability registry, plugin schemas, MCP handlers | Generated command/mode/argument mapping with zero unexplained omissions; baseline is pinned. |
| Shared services and policy | Application handlers, `mcp_policy.py`, registry definitions | CLI/MCP share request semantics; effect planning and scope enforcement are tested. |
| All execution/effect adapters | Executor, native/model-checker/SAST/doctor adapters, provider and output writers | No reachable undeclared effect; real backend profiles provisioned and validated. |
| Sessions and approvals | New structured session and approval services | Interactive workflows and actual approved trust operations complete without terminal input. |
| Evidence and transport | Publisher, results, MCP schemas, client lifecycle | Exact observations and policy bindings survive transport; replay/cancel/reconnect are safe. |
| Parity release | CI, user guide, AiderDesk acceptance | Every command and semantic profile is usable under approved policy in its reference environment. |

Do not expose arbitrary subprocess strings as an intermediate shortcut. Do not weaken strict enforcement while the migration is incomplete. Register newly completed adapters behind their exact policies and retain compatibility aliases where safe.

## 11. Release acceptance

CI must compare the live CLI/plugin inventory with the mapping and emitted MCP schemas. It must fail for missing operations, silently ignored flags, drifted defaults/choices, missing callables, duplicate tool names or policy-incoherent profiles.

For each finite mode/language/backend/provider/assurance variant, keep a registered scenario and relevant invalid combinations. For unbounded values, test equivalence partitions, boundaries and schema/property invariants. Do not claim the Cartesian product has been tested when only a few samples ran.

Run positive and negative real-tool acceptance per backend in provisioned jobs. Mandatory backend jobs must fail—not skip—when their required resource controls/tools are absent. A user's missing dependency should return an honest readiness failure, distinct from missing implementation.

Compare CLI and MCP semantic outputs using the same source, deterministic provider transcripts where necessary, tool versions and authority. Allow differences in transport, run IDs and nondeterministic timestamps; do not ignore claim, bounds, assumptions, requested backend, input/output hashes or exit semantics.

Transport acceptance must start the actual MCP process, negotiate the supported protocol, discover typed tools, call workflows, receive structured errors, retrieve evidence and complete clarification/approval. Direct Python handler tests are not sufficient. Include unauthorized direct and indirect entry points.

Required adversarial cases include all granted-effect subsets; omitted provider/write/publication permission; hidden subprocess; provider fallback; out-of-root/symlink output; stale snapshot; attempt to replace evidence; child budget escalation; cancellation; session theft; duplicate submission; forged approval; approval replay; changed artifact after approval; and trust changes through ordinary workflows.

The final user acceptance must complete both a greenfield and brownfield workflow from AiderDesk without a shell or legacy-mode workaround. Human approval is a supported step, not an implementation omission.

## 12. Documentation and completion metrics

Generate the guide matrix from the registry/parity manifest: command, semantic modes, MCP tool/workflow, arguments, reads/writes, provider disclosure, execution backend, evidence, approval and prerequisites. Include recipes for greenfield elicitation-to-promotion-to-implementation and brownfield extraction-to-documentation-to-refactoring/remediation-to-reverification.

Track implemented commands / discovered commands, mapped argument declarations / discovered declarations, implemented semantic profiles / supported profiles, provisioned real backend coverage and complete client workflows. Publish limitations explicitly. Never substitute tool-count growth or statement coverage for these metrics.

**Done means:** every CLI-supported operation in the release scope can complete through the MCP interface, including human-approved trust actions, with no unrestricted shell fallback, no silent option loss, and no weakening of admission or evidence guarantees.

## Sources and preparation limits

Baseline primary references:

- https://raw.githubusercontent.com/sheelmorjaria/formalspecgen/91c6790/pipeline/cli.py
- https://raw.githubusercontent.com/sheelmorjaria/formalspecgen/91c6790/mcp_server.py
- https://raw.githubusercontent.com/sheelmorjaria/formalspecgen/91c6790/pipeline/capability_registry.py
- https://raw.githubusercontent.com/sheelmorjaria/formalspecgen/91c6790/pipeline/mcp_policy.py
- https://raw.githubusercontent.com/sheelmorjaria/formalspecgen/91c6790/docs/MCP_ADMISSION.md

Protocol references (version-specific examples, not a mandate to upgrade):

- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation
- https://modelcontextprotocol.io/extensions/tasks/overview

This specification, its proposed tool names and mappings are recommendations. Browser-readable primary source and the supplied prior guide inventory were used. A checkout could not be downloaded in the local execution environment; no repository suite, MCP transport, provider, approval service, or formal backend was run. Local validation establishes only mapping completeness against that retained inventory and document/JSON consistency.
