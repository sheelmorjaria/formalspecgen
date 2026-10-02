# Strict MCP admission guide

## Read-only project validation and static planning

`project validate/plan MANIFEST [--target NAME] --json -` and MCP
`inspect_project(manifest, operation="validate", target=null)` share
`ProjectWorkflowRequest` and `inspect_project`. The admitted profile permits
only workspace reading. It captures an explicit versioned JSON manifest and
selected source/contract inputs, validates dependencies, and consults the
installed registry for exact capability/profile names. No tool, provider,
workspace plugin, build script, publication, or workflow dispatch occurs.

Paths declared inside the manifest are relative to its directory and must stay
inside the caller's workspace. Aggregate capture ceilings are 4 MiB, 128 files,
32 path components, 64 targets and 128 workflow entries. Context budgets can
only lower these ceilings. Unknown fields, duplicate keys, cycles, unsafe paths,
symlinks and nonregular files fail closed. Selected targets include dependencies;
unselected targets remain explicit. Digests bind the bytes actually captured,
including the manifest; repeated paths are captured once.

All operations return `target_inputs`, keyed by selected target name. Its
`sources` and `contracts` lists retain declaration order and contain workspace-
relative paths, sizes and SHA-256 digests from the same captured bytes as the
aggregate input manifest. `capture_complete` means only that the target's
explicit inputs were captured, not that it is approved or verified. A later
capture failure preserves earlier dependency bindings, marks the failing
target incomplete and leaves the overall request unsuccessful. These references
do not make the workspace immutable; consumers must recheck the identities
before later authorized actions.

`project impact MANIFEST --changed PATH [--changed PATH ...] --json -` uses the
same service with `operation="impact"` and `changed_paths=[...]`. It requires
1–128 unique, manifest-relative paths and the full project (no target selection).
Changed paths are bounded labels, not additional read requests. Direct source or
contract matches propagate through declared dependencies with per-target reasons;
a change to the manifest affects every target. Unmapped paths remain explicit
and cause `PROJECT_BLOCKED`; otherwise the operation returns
`PROJECT_IMPACT_ANALYZED`. All current declared inputs must still pass capture:
missing or deleted inputs fail with `PROJECT_INVALID` before impact is reported.
No Git command, verifier or evidence cache is consulted. The report is not a
semantic dependency proof: `not_identified_as_affected` is not a reuse decision,
and `evidence_reuse_authorized` remains false.

`PROJECT_VALIDATED` and `PROJECT_PLANNED` do not establish source-fragment
support, tool readiness, contract approval or requested assurance. Unavailable
profiles produce `PROJECT_BLOCKED`; absent contracts produce a warning, not an
invented specification. Results remain `NO_PROOF`. Manifest policy declarations
do not grant authority, reserve budgets or change admission. The static plan
is not executable: actual invocation arguments and effects still require their
own validation and authorization. See the public manual for the JSON schema
example. Completion requires revision-bound CLI/MCP transport evidence, not
registration or local unit tests alone. The completion contract also requires
the installed-wheel project cases: the installed console entry point and real
MCP server must agree outside the source checkout. These cases cover validation,
planning, target selection, unavailable profiles, malformed/missing/out-of-scope
manifests, input limits and symlink rejection; they check source digests and
workspace immutability. Impact acceptance also exercises direct source/contract
and manifest changes, unmapped paths and a branched dependency graph through
real MCP. Both source-checkout transport and installed-wheel interfaces reject
missing changes, target selection, traversal, duplicate/excessive paths and
changed paths supplied to planning. Adapter regressions separately confirm
that invalid requests stop before admission and service dispatch.
Wheel build and installation use no package index or
dependency downloads. Dependencies remain supplied by the provisioned test
environment, so this is not fresh dependency-resolution or backend qualification.

## Domain traversal infrastructure (not workflow admission)

The V2 in-process traverser now bounds discovered states, generated transitions
and work items separately. Default ceilings are 100,000 states, 1,000,000
transitions and 2,000,000 work items. The initial state counts toward the state
ceiling. A new state is rejected before retention if it would exceed that
ceiling; an already discovered state is never queued again. Parallel edges and
self-loops still count as transitions, so deduplication does not change the
reported state/transition semantics.

A work item is an atomic operation attempt, an actor successor attempt, or a
lock-protocol actor/idle-operation attempt. Disabled operations consume work
before guard evaluation, even when they generate no transitions. These are
deterministic count limits, not a wall-clock, byte or expression-complexity
guarantee. Input capture, typed parsing, expression depth and model rendering
must be bounded separately before remote admission.

The internal `validate_transitions_and_invariants` service accepts positive
integer `max_states`, `max_transitions` and `max_work_items` limits. Exhaustion
raises `UnsupportedV2Boundary`, never a partial successful result. The existing
domain validation orchestrator records a `bounded_traversal` failure and does
not render or invoke TLC after exhaustion. This is an incomplete check, not a
counterexample or evidence that the specification is invalid.

The internal `domain_validation_preparation.prepare_domain_candidate` stage
now provides a typed `DomainPreparationRequest` and requires explicit
`workspace_read` authority. Relative candidate paths are resolved under the
context's workspace, not the process working directory. Descriptor-based
capture rejects symlinks and nonregular files, reads the candidate once, and
enforces a 1 MiB byte ceiling and 32 path components. Returned source bytes,
canonical candidate JSON, semantic identity and TLA/CFG text are immutable.
The existing candidate hash and renderer semantics are preserved.

YAML (including JSON syntax) is limited during composition, before typed
schema construction: 8,192 nodes including keys, 48 levels, 4,096 characters per
scalar and 64 characters for integer literals/numeric strings. Aliases,
duplicate/non-string keys, merge keys, multiple documents, floats, timestamps,
binary blobs and non-core tags are rejected. Context limits can only lower
the installed ceilings. Generated text has a 2 MiB aggregate ceiling, with a
conservative pre-render expansion check to bound repeated state-name lists.
Large valid models can be rejected by that allowance without implying a model
defect. The result records the effective preparation limits and separate raw
source, semantic candidate, and generated model digests.

Preparation returns `DOMAIN_MODEL_PREPARED` / `NO_PROOF`, not `VALIDATED`.
It does not run static deadlock analysis, traversal, TLC or a provider; it
publishes nothing and returns no output paths. A model can be prepared even
when its invariants are false. Existing reviewed/unreviewed metadata is
reported as input data, never authenticated or promoted by preparation.

`validate-domain` remains **unadmitted**. Its next migration still requires a
permission-carrying shared workflow connecting these preparation/traversal
stages to strict TLC execution, immutable candidate/model evidence, controlled
`--emit-tla` publication and real CLI/MCP acceptance. Neither CLI nor MCP has
been switched to this preparation stage yet. The legacy validation-sidecar writer
is not made suitable for MCP by the traversal changes. No inventory or
completion count changes for this infrastructure slice.

## Semgrep execution infrastructure (not workflow admission)

`pipeline.isolated_semgrep.run_isolated_semgrep` requires explicit workspace-read
and external-execution authority. Its typed request names one Java/C/C++ source;
the executable and local rules are operator configuration, not model-proposed
registry names or URLs. Missing local rules fail without registry fallback.
Source capture rejects out-of-workspace paths and symlinks. Rules must be a
regular local file, opened without following a final symlink. Source and rules
are captured once into one digest-bound snapshot before execution.

The adapter permits at most two files and 4 MiB aggregate input, including at
most 1 MiB of rules, with 32 source-path components. Execution ceilings are 60
seconds, 2 GiB memory, 64 processes, 1 MiB output, 64 MiB per file, 128 MiB working
storage and 64 MiB temporary storage. At most 4,096 findings are normalized.
Context limits can lower these ceilings. Both inputs remain read-only inside
`StrictSandboxExecutor`; the original project and user credentials are not
mounted. No unrestricted execution fallback exists.
A configured tool root that would expose the workspace or original source is
rejected before execution; install the scanner in a separate runtime location.
The runtime also receives the public `/etc/ssl/certs/ca-certificates.crt`
bundle read-only: the pinned Semgrep initializes its TLS authenticator even with
metrics and version checks disabled. Neither `/etc/ssl/private` nor the broader
`/etc` tree is mounted, and network access remains denied.

The invocation uses local `--config`, OSS scanning, disabled metrics/version
checks, no Git-ignore lookup and no source-comment suppression. It never enables
autofix, uploads, builds, providers or remote rule discovery. These flags follow
the [Semgrep CLI reference](https://docs.semgrep.dev/cli-reference); isolation
independently denies network access. Rule parsing and analysis happen inside
the resource-controlled process, not in the controller.

`SAST_CLEAN` means no finding from those rules on the captured source, not secure
code. `SAST_FINDINGS` means the scan completed with reviewable findings. Both
remain `NO_PROOF`. A zero exit alone is insufficient: structured output must
identify the exact scanned snapshot path, contain no errors/skips and have valid
finding locations. Findings are returned with captured relative source paths;
raw tool output stays in the execution observation. Unknown CWE mappings remain
explicit. Partial results retain findings but return `SAST_INCOMPLETE` and an
unsatisfied request; invalid output and isolation failures are distinct failures.

The adapter itself does not publish evidence. The shared `assess-security` service
now admits single Java sources with isolated ESC and optional local SAST; its
`java-security-assessment` profile requires read, execution, evidence publication
and new-artifact write effects. It permits no provider, remote rule lookup or
source replacement. `security-inspect` remains a separate unadmitted migration.
The provisioned sandbox suite adds real
Java/C/C++ clean/finding cases, the packaged default rules and malformed-rule
rejection with Semgrep 1.138.0
in a dedicated venv; this is a pinned test toolchain, not a claim of full
dependency-lock or current-version deployment qualification.
CI retains the actual Semgrep execution observations as separate artifacts.

### Shared Java assessment

`assess_security(source, run_sast=True, result_export="security_verdict.json")`
captures once with a 4 MiB ceiling, rejects non-Java inputs and symlinks, and
feeds private copies to both judges. One aggregate execution allowance caps
elapsed time (180 seconds) and output (2 MiB); each backend retains its stricter
per-stage limits. Local rules also count toward the SAST capture allowance.
No model argument selects executables or rules. OpenJML contracts and assumptions
remain the formal scope, not proof that the specification is adequate.

The overall report is always `NO_PROOF`. `CHECKS_PASSED`,
`FORMALLY_VERIFIED_SAST_SKIPPED`, `SECURITY_FINDINGS`, formal verification failure
and incomplete execution remain distinct. Intentional SAST omission can satisfy
only the reduced request. Formal results and all actual observations survive a
later SAST or publication failure. Immutable ledger artifacts bind the source
identity, local-rule snapshot, invocation policies, stage results and limitations.
The ledger is prepared privately and published through the controlled no-replace
publisher. Its returned manifest path comes from publication metadata.

CLI defaults to a new `security_verdict.json`; `--json -` is stdout. MCP null
`result_export` omits the result-file export, not evidence. Unsafe input/export
aliases are rejected before execution; existing outputs are never replaced.
Negative results may be exported. Any requested publication failure makes the
request unsuccessful. The provisioned real-MCP/CLI matrix is a release gate;
unit tests and static admission alone do not establish completion.

## TLC execution infrastructure (not workflow admission)

`pipeline.isolated_tlc.run_isolated_tlc` accepts a typed generated-model request
and an explicit `external_execution` context. Operator-configured Java and TLC
paths are not model-selectable fields. It captures the jar (32 MiB maximum) and
the generated TLA/CFG pair (4 MiB aggregate maximum) into one snapshot, then
runs help/provenance and model checking through `StrictSandboxExecutor` against
those same bytes. Jar capture is bounded and rejects symlinks and nonregular
files. The workspace is not mounted; only the snapshot and runtime are supplied.
External model imports are not supported by this adapter.

Both actual observations, all three input digests, the snapshot manifest,
resolved invocation, version banner, requested/enforced resource policies and
authority summary remain available on failure as well as success. Resource
budgets can only lower adapter ceilings. The 120-second elapsed allowance and
1 MiB output allowance are shared across both stages; the provenance stage has
an additional 10-second ceiling. Per-stage ceilings are 2 GiB memory, 64 tasks,
64 MiB per file, 128 MiB working storage and 64 MiB temporary storage. These are
execution limits, not a provider or monetary consumption ledger.

A successful help command may exit 0 or 1 with a recognizable TLC banner.
Model checking requires enforced isolation, an untruncated normal zero exit and
TLC's completed/no-error marker. Missing prerequisites, resource failures or
inadequate output fail closed without an unrestricted runner fallback.
`TLC_MODEL_CHECK_PASSED` / `model_check_passed=true` is deliberately still
`claim=NO_PROOF`: this infrastructure result does not establish source/model
correspondence, reviewed assumptions, specification adequacy or published
evidence. Its `request_satisfied` refers only to this model-check request.

`validate-architecture` now uses this adapter through the shared bounded workflow
below. Legacy domain validation and the other architecture/composition workflows
remain separate migrations. The adapter itself creates no command-completion
claim. The provisioned sandbox CI job requires real TLC
success and invariant-failure cases using a digest-pinned jar; mocked unit tests
are not backend acceptance evidence.

### Bounded architecture validation

CLI `validate-architecture ARTIFACT --timeout 120 --json result.json` and MCP
`validate_architecture(artifact_path, timeout=120, result_export=None)` capture
one regular JSON file (4 MiB ceiling) without following symlinks. Parsing rejects
duplicate keys/nonfinite values; structure is limited to 16,384 nodes and depth
32. Typed validation precedes rendering and execution. The finite state-space
ceiling is 1,000,000; a conservative expansion allowance bounds repeated state
names before rendering and generated TLA/CFG together are capped at 1 MiB.

The current renderer flattens component state/actions. Duplicate or colliding
names and unresolved domain references are rejected rather than silently
checking a different composition. Operation contracts, use-case ordering,
external behavior, source correspondence, liveness and specification adequacy
are **not checked**. The bounded claim concerns generated `TypeOK` and default
TLC deadlock checking only. Model validation neither approves a specification nor
authorizes source changes.

The profile requires read, execution, new-artifact write and evidence publication.
It exposes no provider, tool path, jar path or unrestricted execution option.
The isolated adapter retains provenance and model-check observations under one
execution allowance (at most 120 seconds), with the same captured tool/model
bytes. Missing tools and sandbox/check failures remain `NO_PROOF`.

The immutable bundle contains generated TLA/CFG, captured-input digests, model
bounds, both actual observations, claim limits and admission policy. All user
references derive from controlled publication metadata. The model text itself
is embedded in the hash-chained ledger; standalone TLA/CFG files are derived
exports whose bytes must match the returned and recorded model digests before
reuse. Ledger integrity alone does not validate those external export paths.
JSON export is optional,
supports negative results and never replaces existing files; publication failure
leaves the request unsuccessful and `NO_PROOF`. CLI stdout uses `--json -`;
without a file export its evidence is under `.formalspecgen/cli-output`.
MCP always uses the designated output root. Provisioned real CLI/MCP acceptance,
not static admission or mocked execution, establishes completion.

## Review-only security templates

CLI `security-exploit` and MCP `security_exploit(report_path, target,
out_dir="security-pocs", result_export=None)` share a typed service requiring
workspace reads and new-artifact writes. There is no scanner, compiler,
provider, network, template execution, or approval authority.

Capture is no-follow and bounded to 4 MiB across two regular UTF-8 inputs,
32 path components and 256 findings. JSON lists and objects with a `findings`
list are accepted; malformed entries, duplicate keys and non-finite values are
rejected. Target bytes multiplied by finding count must fit a 16 MiB lexical
matching allowance; matching uses captured text and a linear method-name hint.
The output allowance is 8 MiB across templates and the optional result export.

Java retains its existing template families. Native `.rs`, `.c`, `.h`, `.cpp`
and `.cc` inputs support the existing CWE-125 bounds template only; other
findings are explicitly unsupported, not Java code mislabeled as native code.
All generated files remain unreviewed and unexecuted, with `claim=NO_PROOF` and
`exploit_proven=false`. Findings are untrusted assertions and their relationship
to the supplied target is not authenticated. Mixed supported/unsupported
reports can produce templates while retaining the unsupported finding list.

The default export is `<out_dir>/poc-verdict.json`. An explicit `result_export`
selects another authorized new path; `"-"` suppresses file export, matching CLI
JSON stdout. MCP roots remain operator-controlled. Publication metadata supplies
the returned file paths and digests before verdict serialization. All writes
are no-replace; aliases and unsafe paths fail closed, and publication failures
leave the request unsatisfied. An export failure may leave already-published
templates intact. No result constitutes exploit confirmation or acceptance.

## Bounded bisimulation preflight

CLI `verify-bisimulation` and MCP `verify_bisimulation(baseline, refactored,
mapping, result_export=None)` share typed requests, bounded capture and optional
no-replace publication. The profile permits workspace reads and separately
requested new-artifact writes, never external execution or provider access.

The combined baseline, mapping and candidate allowance is 4 MiB and 256 files.
Paths are limited to 32 components under the authorized root, with no-follow
descriptor opens and regular-file checks. A candidate directory is scanned
incrementally up to 4,096 entries and includes only sorted top-level `.java`
files. A single candidate is UTF-8 text. Duplicate JSON mapping keys are
rejected. Matching consumes the captured bytes, not reopened source paths.
Role/path/size/digest manifests identify every input and collaborator.

`BISIMULATION_PREFLIGHT_READY` means only that mapping class names occur and
legacy lexical public-method signatures match. This is not a Java parser or a
contract/equivalence prover. The legacy `contract_surface_preserved` field
reports lexical signature agreement only. Every outcome remains `NO_PROOF`,
with behavioral and heap-topology equivalence explicitly false.

CLI `--json -` is stdout; other filenames and MCP `result_export` use controlled
no-replace publication. MCP resolves exports beneath its operator-configured
workspace output root. Negative results may be exported when that destination
is authorized; invalid/aliased destinations or denied write permission cannot
be exported. Publication failure leaves the request unsatisfied without
replacing any source, candidate or existing artifact. Admission is not
revision-bound workflow completion.

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
> combinations fail before side effects. Human approval, promotion, and trust administration remain
> outside agent authority. An agent may request or retrieve an approved signing action, but cannot
> create the human decision or access the signing key.

## Current admitted profiles

| Workflow | CLI | Strict MCP | Modes / language / backend | Workspace effects | Provider access | Evidence | Human approval |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `verify_code` | Yes | Admitted | `parse`, `check`, `esc` / Java or JML / OpenJML | Read immutable input; strict execution; optional new JSON export | None | Exact execution observation and terminal manifest | Required for any later promotion or signing |
| `verify_code` | Yes | Admitted | `parse`, `check` / Rust / rustc | Reviewed and transformed compiler inputs are both snapshotted; strict execution | None | Static-check observation and terminal manifest; no proof claim | Required for any later promotion or signing |
| `verify_code` | Yes | Admitted | `esc` / Rust / Prusti or Kani | Read immutable input; strict execution | None | Deductive Prusti or bounded Kani evidence with terminal manifest | Required for any later promotion or signing |
| `verify_code` | Yes | Admitted | `esc` / C or C++ / Frama-C WP or ESBMC | Strict compiler/preflight and verifier stages | None | Deductive C or bounded C++ evidence with every execution stage | Required for any later promotion or signing |
| `verify_code` | Yes | Admitted | `parse`, `check` / C or C++ / structured rejection | Read request metadata; no external execution | None | Immutable unsupported-mode result | None |
| `verify_refactor` | Yes | Admitted | `preserve` or `preserve-signing` / Java or JML, Rust, C, or C++ / language verifier | Read immutable baseline and candidate snapshots; strict baseline/candidate execution; controlled result export for signing | None | One immutable bundle binding both inputs and observations; signing adds a separate detached signature and immutable action receipt | An authenticated reviewer decision is required before protected signing |
| `apply_refactor` | Yes | Admitted | deterministic patterns / Java or JML, Rust, C, or C++ / language verifier | Capture bounded inputs; prepare privately staged candidates; strict preservation execution; create new candidate and optional JSON artifacts | None | Candidate manifest plus immutable baseline/candidate observations and terminal manifest | Candidate remains unreviewed; applying it to authoritative source requires separate approval |
| `analyze_codebase` | Yes | Admitted | `analyze` / bounded polyglot source tree / built-in extractor | Capture bounded source files without following symlinks; create new architecture, domain-candidate, and optional JSON artifacts | None | Source manifest and published artifact digests; explicitly no proof receipt | Extracted models require human review before use or promotion |
| `inspect_code` | Yes | Admitted | `inspect` / Java or JML / built-in inspector | Read one bounded workspace input; optionally create one new JSON export beneath the designated output root | None | Structured findings and optional unreviewed export; no proof receipt | Required before applying proposed changes |
| `document_code` | Yes | Admitted | `deterministic` or `provider-assisted` / Java / built-in documentation | Read one bounded source; create new artifacts only beneath the designated output root | GLM, OpenAI, or Ollama through server-controlled endpoints and approved models | Unreviewed Markdown, V2 candidate, and optional JSON result; no proof receipt | Required before review, use, or promotion |
| `submit_work_item` | No coordinator CLI | Admitted | `submit` / approved workflow and A2A 1.0 worker | Read current revision; append service task state; dispatch to an approved worker | Worker endpoint only; no model/provider permission | Hash-chained worker-task events and unaccepted proposal references | Trusted acceptance and human merge review remain separate |
| `get_work_item` | No coordinator CLI | Admitted | local read or explicit remote refresh | Principal-scoped service-state read; refresh separately adds dispatch and state-write authority | Worker endpoint only for refresh | Current worker state; no proof claim | None for status; acceptance remains separate |
| `get_work_artifacts` | No coordinator CLI | Admitted | digest-bound artifact references | Principal-scoped service-state read only | None | Unaccepted worker artifact identities | Required before retrieval/application/integration |
| `cancel_work_item` | No coordinator CLI | Admitted | remote task cancellation | Principal-scoped state read/write and approved worker dispatch | Approved worker endpoint | Hash-chained cancellation outcome; no proof claim | None |
| `start_agent_run` / `resume_agent_run` | No supervisor CLI | Admitted | supervised `inspect` then `verify` / Java or JML / OpenJML | Exact source read; strict verification; protected service-state read/write | None | Child verification manifest plus no-replace goal review | Required for contract changes, applying source changes, signing, promotion, trust changes, or merge |
| `get_agent_run` / `cancel_agent_run` | No supervisor CLI | Admitted | principal-scoped local state | Protected service-state read, plus state write and terminal-review publication for cancellation | None | Hash-chained run events and no-replace cancellation review; cancellation never becomes proof | None |
| `get_approval_request` / `complete_refactor_signing` | No approval CLI | Admitted | status or completion / approval policy v2 protected signer | Protected approval-state read/write; completion may invoke only the fixed protected signer | None | Artifact-bound request, detached signature, and immutable action receipt | The decision must be signed out of band by an authorized reviewer |

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
optional `result_export`, and `signing_intent`. The preservation profiles preserve the existing
contract, proof-trust, semantic-context, and collaborator checks, then verify both snapshots through
strict execution. Negative results can be exported through the same no-replace publisher and cannot
erase successful baseline observations. Signing intent requires a controlled export and creates an
exact approval request only after evidence and export publication succeed. A reviewer records an
authenticated decision outside MCP. `complete_refactor_signing` then asks an operator-fixed signer
to revalidate the decision, artifact, evidence manifest, action, destination, identities, policy,
and expiry before producing a detached signature and separate receipt. MCP receives neither the
reviewer's secret key nor the protected signing key. Signing does not upgrade the verification claim.

`apply_refactor` accepts `source`, required `method` and `out`, optional `pattern` and Java/JML
`inspection`, and optional `result_export`. It captures bounded inputs before deterministic
transformation, verifies private baseline and candidate snapshots through the preservation service,
then publishes candidates only as new artifacts beneath the designated MCP output root. Java/JML
admits the declared deterministic pattern catalogue, Rust admits extract-method and strategy, and C
and C++ admit extract-method. Transformation rejection, verifier failure, sandbox failure, or
publication failure remains `NO_PROOF`; no profile claims general behavioral equivalence.

`analyze_codebase` accepts `target_dir`, `out_dir`, `project_root`, and optional
`result_export`. It captures supported source files once under aggregate byte, file, traversal-entry,
and depth limits, rejects symlink traversal, and runs extraction only against a private snapshot.
Architecture JSON and unreviewed domain candidates are published without replacement beneath the
designated MCP output root. It invokes no compiler, project hook, provider, or generated code. The
returned source manifest and artifact digests establish provenance, not behavioral correctness.

`generate_traceability_matrix` accepts `domain`, `source`, `requirements`,
`out`, and optional `result_export`. Both interfaces use one shared bounded
capture/matching/publication service. The default JSON sidecar uses the Markdown
destination with a `.json` suffix; an explicit export changes that destination.
All publications are no-replace. Negative outcomes can still publish JSON, but a
failed export makes the overall request unsuccessful. Returned `matrix_file`
comes from publication metadata; row sources are relative to the captured source
root and bind to source digests. Requirements with no invariant match remain
`UNMAPPED`; field/bound matching never proves a requirement.

The profile grants only workspace reading and new-artifact writing. Aggregate
capture limits are 8 MiB, 514 files, 4096 traversal entries, and depth 32;
matching has a weighted operation budget and combined outputs have an 8 MiB
limit. Neither providers nor subprocesses are authorized.

Submission, refresh and cancellation remain MCP-only coordination capabilities.
The local `get_work_artifacts` query also maps to `worker artifacts`, included in
the current generated CLI denominator; admission is not completion. Their policy and
append-only state live outside the agent workspace. Endpoint, Agent Card digest, principal,
credentials, path ceilings, workflow allowlists, and budgets are operator-controlled. See
[A2A_COORDINATION.md](A2A_COORDINATION.md). The provisioned A2A job exercises both the official
A2A 1.0 client/server round trip and submission through the real MCP stdio server.

Supervised start, resume and cancellation remain MCP-only. `get_agent_run` also
maps to the read-only `run show` CLI command, which is included in the live parity
denominator. It neither creates state nor resumes work. The supervised tools'
operator-owned state is outside the workspace, while the exact approved source remains bound by Git
revision and SHA-256. See [AGENTIC_SUPERVISOR.md](AGENTIC_SUPERVISOR.md). The initial profile accepts
only a typed `inspect` then `verify` proposal; it cannot edit source or contracts, call a provider,
delegate work, approve, sign, promote, or merge.

## Available through CLI but not admitted to strict MCP

The following legacy MCP handlers remain classified `unsupported`. Their CLI availability is
unchanged, but no command/mode/backend profile below is authorized for unattended MCP use:

```text
validate_architecture  implement_code
assess_security        security_inspect      security_exploit
remediate_code         correct_behavior
verify_bisimulation    optimize_algorithm
discover_algorithms    validate_domain        compose
reverify_composition   unified_system         draft_canonical_contract
architecture           system                 prove_equivalence
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

`promote_domain`, generic `sign_artifact`, and `manage_trust` are human trust actions. They cannot
acquire an MCP invocation profile even if their implementation could run in a sandbox. An agent may
prepare a review package or request completion of an already authenticated, exact signing action,
but it cannot create the approval, select arbitrary signing inputs, or change reviewer trust policy.

## Deployment

Leave `FORMALSPECGEN_MCP_STRICT_JAVA_ONLY` unset for the strict catalogue. Setting it to `0` restores
the full legacy catalogue for explicitly trusted local compatibility work; it is not an admission
mechanism and does not grant those workflows strict-isolation or durable-publication claims.

For a supervised agent deployment, install a pinned package outside the agent-editable checkout,
run the MCP service in a delegated cgroup-v2 leaf, and expose only the default strict catalogue.
