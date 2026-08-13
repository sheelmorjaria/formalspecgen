# FormalSpecGen CLI

FormalSpecGen is a terminal-first, human-in-the-loop tool for turning natural-language requirements
into reviewed formal contracts, bounded architecture evidence, and deductively verified code.

```text
Natural language → clarification → checked language contract
                                      │
                                      ├─ JML transition IR → deterministic TLA+ → TLC
                                      └─ trusted-surface synthesis
                                           ├─ Java/JML → OpenJML ESC
                                           ├─ Rust/Prusti → Prusti
                                           └─ C/ACSL → Frama-C WP
```

The governing rule is:

> The LLM proposes; deterministic compilers transform; formal tools judge; humans control trusted assumptions.

### Assurance claim disclaimer

FormalSpecGen produces hash-bound, reviewable bounded-model evidence and scoped source/model
refinement certificates suitable for inclusion in a larger assurance case. It does **not**
constitute DO-178C Level A, ISO 26262, IEC 62304, or other regulatory certification.

Certification remains an organizational and lifecycle activity that can require requirements
traceability, structural coverage such as MC/DC, configuration management, verification
independence, problem reporting, lifecycle evidence, and tool qualification under standards such
as DO-330. Formal methods may discharge selected objectives under guidance such as DO-333; they do
not automatically certify either generated software or FormalSpecGen itself.

Current bounded checks establish only their explicitly recorded safety properties, bounds,
abstraction, and execution assumptions. Liveness, fairness, concurrent linearizability, unbounded
correctness, reviewer identity, and non-repudiation are separate claims unless a corresponding
evidence gate explicitly establishes them. A SHA-256 digest establishes artifact identity, not who
approved it. Cryptographic reviewer identity requires a separately verified signature and key
policy.

The multi-actor V2 evidence design is documented in
[`docs/V2_DOMAIN_EVIDENCE_BLUEPRINT.md`](docs/V2_DOMAIN_EVIDENCE_BLUEPRINT.md). Its typed schema,
bounded traverser, deterministic TLA+ renderer, TLC adapter, evidence publication, and hash-bound
promotion primitives are implemented and tested. V2 is available through explicit
`--schema-version 2` domain and promotion options plus `validate-domain`; V1 remains the default,
and neither lifecycle inherits claims from the other.

The previous VS Code extension, browser UI, FastAPI server, WebSocket tests, and packaging files are
preserved under [`archive/`](archive/) but are no longer part of the active build or runtime.

## Install for development

Python 3.10 or newer is required.

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/formalspecgen --help
```

Runtime Python dependencies are deliberately small: Pydantic, PyYAML, Prompt Toolkit, and Rich.
Formal backends remain external tools configured through environment variables or repository-local
`tools/` installations.

The CLI does not silently download large verifier distributions at startup. Install only the
backends required for the language and assurance profile you intend to use, then configure their
paths as described in [Formal tool configuration](#formal-tool-configuration). This keeps local and
CI environments reproducible and prevents unreviewed binaries from becoming part of an assurance
claim.

## Interactive mode

Run without arguments:

```bash
formalspecgen
```

Enter a natural-language requirement directly or use a slash command:

```text
> A counter starts at zero, accepts positive increments, and never exceeds 1000.

/draft "Design a bounded counter"
/verify Counter.java --mode esc
/implement Counter.java --provider ollama
/architecture BankAccount.java --abstraction atomic_operations
/domain "A two-direction traffic-light controller"
/session
/reset
/quit
```

Commands may also be entered as `implement Counter.java ...` or pasted in full as
`formalspecgen implement Counter.java ...`. The REPL recognizes all three forms; other text is
treated as a natural-language drafting request.

Prompt history and non-secret clarification state are stored in `.formalspecgen/`. Required answers
are checkpointed after every response, so an interrupted terminal session can resume without asking
the same questions again. `/reset` explicitly clears the current session.

## Script and CI commands

### Draft a checked contract

```bash
formalspecgen draft \
  "A counter starts at zero and never exceeds 1000" \
  --provider ollama

formalspecgen draft "A bounded Rust counter" --lang rust --out-file Counter.rs
formalspecgen draft "A bounded C counter" --lang c --out-file counter.c
```

The result is a JML-annotated Java scaffold checked with `javac`, deterministic specification
linting, and `openjml -check`. This establishes static contract validity, not implementation proof.
Rust and C drafting produce Prusti-annotated Rust and ACSL-annotated C respectively; these lanes do
not inherit the Java/JML proof claim merely because drafting succeeded.

### Synthesize and verify an implementation

```bash
formalspecgen implement Counter.java \
  --provider ollama \
  --assurance-level critical \
  --json implementation-verdict.json
```

The trusted JML/API surface is immutable. Any generated modification is terminal
`TRUST_BOUNDARY_VIOLATION`. Successful OpenJML ESC produces a `DEDUCTIVE_PROOF` claim.

The command also routes trusted Rust/Prusti and C/ACSL scaffolds by extension:

```bash
formalspecgen implement Counter.rs --provider ollama --assurance-level critical
formalspecgen implement counter.c --provider ollama --assurance-level critical
```

For Rust, traits, function signatures, and Prusti contract attributes are immutable. For C,
function signatures and ACSL contract blocks are immutable. Any candidate that changes these
surfaces terminates as `TRUST_BOUNDARY_VIOLATION`. Rust candidates also fail before Prusti when
they introduce `unsafe`, raw pointers, panic paths, or other error-level safety findings; C
candidates pass ACSL lint and strict C11 compilation before Frama-C WP.

All three routes enter through `pipeline.orchestrator.run_implementation_loop()`. The orchestrator
selects the implementation loop from the source extension; the CLI does not own language policy.
Rust and C verification are normalized by `pipeline/verify_rust.py` and `pipeline/verify_c.py`, so
their diagnostics enter the same bounded resample-first, feedback-second repair strategy and shared
VC evidence schema as Java.

Before the expensive formal backend, Rust executes generated `#[test]` samples through `rustc
--test` with overflow checks, while C executes a bounded harness under ASan+UBSan. Concrete failures
are counterexample evidence for regeneration and skip Prusti/Frama-C for that candidate. Passing
samples are runtime evidence only. The detailed gate ordering and encoding boundaries are documented
in [`DESIGN.md`](DESIGN.md).

Rust and C also expose conservative, opt-in proof-support passes:

```bash
formalspecgen implement Counter.rs --method-proof-only \
  --accept-pass inject_pure --accept-pass inject_slice_bounds
formalspecgen implement counter.c --method-proof-only \
  --accept-pass inject_null_checks --accept-pass inject_loop_assigns
```

The Rust passes annotate only locally defined contract helpers, direct typed slice/index access,
and exact signed parameter/constant arithmetic intervals. The C overflow pass derives
`INT_MIN`/`INT_MAX` obligations for the corresponding restricted `int` arithmetic subset. Neither
pass invents a generic numeric policy such as `<= 1000`.
The C null pass handles only directly dereferenced pointer parameters with an existing ACSL
contract. The C loop-frame pass promotes explicit `// acsl-loop-assigns: ...` review markers; it
does not infer alias-sensitive frames. Any changed candidate remains proof-relevant and requires
explicit pass acceptance.

Choose an explicit assurance profile. The complete gate table currently applies to Java/JML:

| Profile | Required gates | Maximum successful claim |
| --- | --- | --- |
| `critical` | lint, OpenJML check, bounded TLC, `javac`, OpenJML ESC | `VERIFIED` / `DEDUCTIVE_PROOF` |
| `standard` | lint, OpenJML check, `javac`, RAC with at least one passing generated test | `STATIC_CHECKED_RUNTIME_TESTED` / `RUNTIME_SAMPLE` |
| `lightweight` | lint and `javac` | `COMPILED_LINTED` / `STATIC_CHECK` |

```bash
formalspecgen implement Bank.java --assurance-level critical \
  --clarifications "Operations are linearizable and atomic; account IDs are immutable."
formalspecgen implement Service.java --assurance-level standard
formalspecgen implement Prototype.java --assurance-level lightweight
```

Critical Java mode fails closed if no reviewed domain plugin can produce the required bounded TLA+
model. Standard Java mode does not treat an empty test run as runtime evidence. Lightweight Java
mode does not claim `RUNTIME_SAMPLE`, because it deliberately runs no tests.

Rust/C critical implementation requests Prusti or Frama-C WP deductive verification. Their
`standard` and `lightweight` implementation paths currently stop at the compiler/static gate and
report `STATIC_CHECK`; they do not inherit Java's RAC/JUnit evidence claim.

When a Java API has no reviewed TLA+ domain adapter, method-level deductive synthesis can be run
without weakening the evidence label:

```bash
formalspecgen implement Controller.java --method-proof-only --provider ollama
```

This can produce `DEDUCTIVE_PROOF` for the JML methods, but records
`assurance_scope: method_contract_only`, `bounded_architecture_checked: false`, and
`source_refinement_proved: false`. It is not a successful `critical` assurance-profile run.

For a reviewed two-field exclusion invariant such as `!(A == value && B == value)`, an existing
simple update guard can be strengthened deterministically with the explicitly accepted
`guard_exclusion_invariants` pass. The pass changes method bodies only and emits a reviewable diff:

```bash
formalspecgen implement Controller.java --method-proof-only \
  --accept-pass guard_exclusion_invariants
```

#### Worked example: mutually exclusive traffic lights

A generated controller declared the trusted invariant:

```java
//@ public invariant !(northSouthLight == 2 && eastWestLight == 2);
```

The initial LLM implementation checked only the field it was about to update. OpenJML therefore
reported `InvariantExit` for both green operations. Diagnostic feedback produced the same candidate
repeatedly, and the shared candidate-hash/error-fingerprint policy stopped the repair loop as
`stalled` rather than consuming the remaining budget.

The reviewed deterministic pass was then accepted explicitly:

```bash
formalspecgen implement TrafficLightController.java \
  --method-proof-only \
  --provider ollama \
  --accept-pass guard_exclusion_invariants \
  --out runs/traffic-light-method-proof
```

It strengthened the two existing guards without changing JML:

```java
if ((northSouthLight != 2) && eastWestLight != 2) { /* set NS green */ }
if ((eastWestLight != 2) && northSouthLight != 2) { /* set EW green */ }
```

OpenJML ESC then completed with zero remaining VCs. The evidence records the original and transformed
source, unified diff, accepted pass name, source/contract hashes, and `DEDUCTIVE_PROOF`. Because this
used `--method-proof-only`, it also records that bounded architecture checking and source/model
refinement were not established.

This example illustrates the intended division of labor: the LLM proposed the implementation, the
deterministic pass made a narrow human-approved transformation, OpenJML judged the result, and the
verdict retained the exact scope of the successful claim.

### Verify an existing source file

```bash
formalspecgen verify Counter.java --mode check
formalspecgen verify Counter.java --mode esc --json verdict.json
```

Modes are `parse`, `check`, and `esc`. Process exit status is zero only when the selected gate passes.

Verification routes by source extension:

```bash
formalspecgen verify BankAccount.java --mode esc       # OpenJML
formalspecgen verify Counter.rs --mode esc             # Prusti
formalspecgen verify Counter.rs --backend kani         # bounded Kani harness evidence
formalspecgen verify controller.c --mode esc            # Frama-C WP
```

Rust error-level safety lint findings block Prusti/Kani execution. `--mode check` on Rust erases
known Prusti attributes and invokes `rustc`, reporting only `STATIC_CHECK`. Kani requires an
explicit human-reviewed `#[kani::proof]` harness and reports bounded evidence, not deductive proof.
C/ACSL direct verification currently supports `--mode esc` only; Frama-C runs after ACSL lint and a
strict C11 compiler gate. Implementation synthesis supports `.java`/`.jml`, `.rs`, and `.c`;
unsupported file types fail explicitly.

Direct `verify` is non-mutating: it verifies the supplied source rather than applying speculative
repairs or proof-relevant postprocessor passes. Use `implement` for the controlled synthesis and
repair loop.

### Check a bounded architecture

```bash
formalspecgen architecture BankAccount.java \
  --abstraction atomic_operations \
  --emit-tla BankAccount.tla \
  --json architecture.json
```

Validated JML is parsed into a typed transition IR. A reviewed domain plugin owns semantic mapping,
and deterministic Python renders TLA+ and a separate TLC configuration. TLC success is reported as
`BOUNDED_ARCHITECTURE_EVIDENCE`; it never claims Java/JML source refinement.

Use `lock_protocol` instead of `atomic_operations` when checking lock acquisition interleavings and
deadlock freedom.

Reviewed built-in semantic domains currently cover banking, inventory, and train/road crossing.
Generated plugins are intentionally different: scaffolding registers their shape, but their AST
adapter and renderer remain fail-closed until reviewed. The included `traffic_light_controller`
plugin demonstrates this pending-review state and must not be presented as architecture evidence.

### Scaffold a new semantic domain

```bash
formalspecgen domain \
  "An elevator controller with bounded floors and doors that cannot open while moving" \
  --project-root .
```

The CLI elicits bounded state, operations, frames, guards, effects, and invariants. The LLM returns
schema-constrained JSON; Pydantic validates it and PyYAML serializes it. Generated AST adapters and
TLA+ renderers initially fail closed with `UNSUPPORTED_BOUNDARY` until a human reviews their TODOs.
Domain clarification answers are stored in the project session so generation can resume after a
terminal restart.

### V2 domain evidence lifecycle

The V2 implementation separates generated proposals, deterministic validation, and explicit human
promotion. It lives in `pipeline/domain_v2*.py` and is selected explicitly so existing V1 plugins
and candidates remain compatible.

```text
typed candidate
    ↓ schema and semantic validation
bounded Python traversal
    ↓ measured reachable states and transitions
deterministic TLA+ and TLC configuration
    ↓ strict tool provenance and successful TLC execution
VALIDATED evidence envelope
    ↓ explicit acceptance of the exact candidate SHA-256
reviewed canonical artifact
```

Generate a typed candidate from an interactive clarification session:

```bash
formalspecgen domain \
  "An elevator controller with bounded floors and doors that cannot open while moving" \
  --schema-version 2 \
  --restart-clarifications \
  --force
```

This writes `domains/candidates/<module>.v2.yaml`. It does not scaffold Python adapters because the
typed candidate is itself the deterministic renderer input. Validate it with the bounded Python
traverser and the configured real TLC installation:

```bash
formalspecgen validate-domain elevator_controller --emit-tla ElevatorController.tla
```

`validate-domain` accepts either the bare module name or a displayed V2 basename such as
`elevator_controller.v2.yaml`. A `.generated.yaml` file is a V1 plugin scaffold and cannot be
validated as typed V2 input; regenerate it with `domain --schema-version 2` rather than renaming or
implicitly converting the schema.

Successful validation writes `domains/candidates/elevator_controller.v2.validation.json` and
prints the exact canonical candidate digest. A failure instead writes
`elevator_controller.v2.validation_failed.json` and does not overwrite successful evidence.

After reviewing the candidate semantics, promote that exact digest:

```bash
formalspecgen promote-domain elevator_controller \
  --schema-version 2 \
  --accept-candidate-sha256 <digest-printed-by-validate-domain>
```

Reviewed V2 artifacts are written to `domains/v2/<module>.json`. They intentionally do not enter
the V1 `domains/*.yaml` plugin registry, whose schema and source/JML adapter contract are different.

Generate the trusted Java/JML contract deterministically from the reviewed V2 artifact:

```bash
formalspecgen draft "Generate the reviewed smart-lock contract" \
  --no-clarify \
  --canonical-domain smart_lock \
  --out-file SmartLock.java
```

This step makes no LLM call. The typed V2 expression tree is serialized into JML guards,
pre-state-aware effects, frames, class invariants, and constructor initialization. The public Java
class and output filename must match. A sibling `SmartLock.java.canonical.json` records the
deterministic transformation and the accepted candidate/evidence hashes. Unsupported operation or
expression semantics fail closed. Generated state fields are `private /*@ spec_public @*/`, keeping
runtime mutation behind the verified method surface while retaining specification visibility.

The same deterministic lowering is available for Rust/Prusti:

```bash
formalspecgen draft "Generate the reviewed bounded counter" --no-clarify \
  --canonical-domain bounded_counter --lang rust --out-file BoundedCounter.rs
```

`pipeline/v2_prusti_serializer.py` derives every `#[invariant]`, `#[requires]`, and
`#[ensures]` clause from the reviewed typed trees and transcribes the reviewed effects into
method bodies (pre-captured locals preserve simultaneous semantics). The command runs the Rust
safety lint and the contract-erased `rustc` gate before writing the file plus its
`.canonical.json` evidence (`DETERMINISTIC_V2_TO_PRUSTI`), and fails closed on unsupported
semantics. Prusti itself judges the annotated source when installed; without it the claim
remains `REVIEWED_TRANSFORMATION`, never `DEDUCTIVE_PROOF`. Deterministic ACSL lowering for C
is not yet implemented; `--lang c --canonical-domain` still routes to the LLM drafting path.

A critical Java/JML implementation can use a reviewed V2 artifact directly:

```bash
formalspecgen implement SmartLock.java --assurance-level critical \
  --v2-reviewed-domain domains/v2/smart_lock.json \
  --v2-validation-evidence domains/candidates/smart_lock.v2.validation.json
```

The two paths are required together. The generic refinement gate verifies the envelope and accepted
hashes, re-renders and hashes the deterministic TLA+, requires one JML method per V2 operation, and
checks guards, effects, frames, and explicit Boolean failure stuttering. It composes those
obligations with OpenJML ESC. Its `SOURCE_MODEL_REFINEMENT` claim is restricted to atomic contract
simulation and does not establish concurrent linearizability.

Typed REST-resource and IoT-sensor reference candidates live under `domains/examples/v2/`. They are
deliberately `unreviewed`: tests establish schema validity, bounded traversal, and deterministic
renderability, but only an explicit `validate-domain` and hash-accepted `promote-domain` workflow
may place adapted semantics in the reviewed V2 registry.

The implemented milestones provide:

- Recursive discriminated expression trees and distinct bounded integer/Boolean state variables.
- Typed guards, simultaneous effects, invariants, initial values, frames, and failure semantics.
- Bounded BFS traversal with state-space limits, bounds checking, and invariant checking.
- Per-actor `callResult` rendering for Boolean `false_and_stutter` operations, including explicit
  success and failure TLA+ actions.
- Complete next-state assignment for mixed APIs: when any Boolean operation introduces
  `callResult`, void actions explicitly preserve it with `UNCHANGED`.
- Separate deterministic `.tla` and `.cfg` rendering with fail-closed unsupported semantics.
- Strict TLC version provenance and execution-result capture without silent version fallbacks.
  TLC 2.19 exposes its version through `-help`, not `-version`; the parser requires a recognized
  banner and retains the observed help exit status.
- `PENDING` evidence with unmeasured fields represented as `null`; `VALIDATED` evidence requires
  measured counts, a generated-TLA hash, successful TLC status, and tool provenance.
- An evidence envelope whose `evidence_sha256` covers only canonical JSON for the inner `evidence`
  object, avoiding circular self-hashing.
- Same-directory temporary publication, file `fsync`, atomic replacement, directory `fsync`, and
  separate scrubbed failure artifacts that do not overwrite successful evidence.
- Hash-bound promotion that verifies the candidate hash, evidence-envelope digest, and
  evidence-to-candidate binding before atomically publishing a reviewed artifact. Both accepted
  candidate and evidence hashes are retained, while the original candidate remains unchanged.

V2 promotion provides deterministic artifact integrity and TOCTOU detection. It does **not**
authenticate the reviewer, provide non-repudiation, prove unbounded correctness, or establish
regulatory certification. GPG/Sigstore reviewer signatures and key policy remain future work.

### Multi-tier compositional verification

Complex architectures are not verified as one giant model. A composition artifact
(`pipeline/composition.py`) binds SOLID-linted architecture components to *promoted* V2
domains, and the deterministic renderer (`pipeline/composition_render.py`) emits one reviewed
class plus one dependency-inversion interface per component and one orchestrator per use
case. Every orchestrator `requires`/`ensures`/`assignable` clause is derived from the
reviewed typed expression trees — never from LLM-drafted clause text. OpenJML ESC then proves
the orchestrator satisfies each callee precondition:

```bash
formalspecgen compose composition.json --out-dir out/ --json verdict.json
formalspecgen reverify composition.json --changed-module smart_lock --json reverify.json
```

A successful run reports `COMPOSITION_VERIFIED` with claim `SCOPED_COMPOSITION_PROOF` and
scope `single_threaded_atomic_contract_composition`. Because the reviewed V2 effects fully
determine component behavior, composition transcribes them into deterministic Java method
bodies (simultaneous semantics via pre-captured locals; boolean `false_and_stutter`
operations check their guard, stutter on failure, and apply effects on success) — so real
OpenJML ESC proves concrete implementations, not just contract stubs. The drafting
serializer's empty-body contract classes are unchanged; only the composition tier emits
effect-executing bodies. After a reviewed module contract changes, `reverify` traces
reverse dependencies through the architecture edges and re-runs composition ESC, reporting
`REVERIFIED`, `REVERIFICATION_FAILED`, or `NOT_IMPACTED`. Real-toolchain E2E coverage lives
in `tests_e2e/test_composition_e2e.py`.

Composition currently fails closed outside a deliberately narrow boundary: one reviewed
operation per component per use case, void/unavailable semantics only (boolean
failure-and-stutter operations cannot yet be sequentially composed), and orchestrator
effects interpreted with `\old` at method entry. The claim establishes neither concurrent
linearizability (a `lock_protocol` abstraction and a separate linearizability proof would be
required) nor distributed asynchrony (message queues, duplication, and eventual consistency
are not modeled), and it binds the single reviewed implementation per component rather than
proving arbitrary dynamic dispatch. Exit-0 compositions that discharge no obligation are
reported as `VACUOUS_COMPOSITION`, not proof. An unreviewed example artifact lives at
`domains/examples/composition/secure_entry.composition.json`.

## Providers

The default CLI provider is Ollama. Configuration is read from environment variables or the
gitignored `.env` file:

```bash
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=qwen3-coder:30b

GLM_API_KEY=...
GLM_MODEL=glm-4.5-flash

OPENAI_API_KEY=...
OPENAI_MODEL=gpt-4o
```

When Ollama runs in WSL and the CLI also runs in WSL, use the loopback URL above. Confirm the model
exists with `ollama list` and pull it explicitly when necessary.

## Formal tool configuration

Defaults and overrides are defined in `pipeline/config.py`:

```bash
OPENJML_BIN=/path/to/openjml
OPENJML_HOME=/path/to/openjml-dist
DAFNY_BIN=/path/to/dafny
TLC_JAR=/path/to/tla2tools.jar
PRUSTI_BIN=/path/to/prusti-rustc
RUSTC_BIN=/path/to/rustc
KANI_BIN=/path/to/cargo-kani
FRAMAC_BIN=/path/to/frama-c
FRAMAC_PROVERS=z3
CC_BIN=gcc
```

OpenJML is expected under `tools/openjml-dist/` in this repository unless overridden. Downloaded
tool distributions, generated runs, credentials, and CLI sessions are ignored by Git.

Typical minimum tool sets are:

| Workflow | External tools |
| --- | --- |
| Java static checking/proof | JDK plus OpenJML |
| Bounded architecture | Java runtime plus `tla2tools.jar` |
| Rust static/proof lane | Rust compiler plus Prusti, or Kani for bounded harness checking |
| C/ACSL proof lane | C compiler plus Frama-C/WP and its configured prover |

Dafny remains available for explicitly supported boundary translation, but the assurance-profile
implementation command does not claim an automatic Dafny fallback unless that reviewed route was
actually executed and recorded in its evidence.

## Output and automation

Human-readable progress is printed to the terminal. Use `--json PATH` on `verify`, `implement`, or
`architecture` to persist machine-readable results. Implementation runs also write their candidate
and assurance evidence beneath the selected `--out` directory.

CLI exit codes are suitable for scripts and CI:

| Exit code | Meaning |
| --- | --- |
| `0` | The requested operation reached its declared successful status |
| `1` | A verification, consistency, lint, compile, test, or proof gate failed |
| `2` | Invocation, configuration, unsupported-language, or missing-tool error |

Consumers should inspect the structured status and claim type rather than treating every exit-zero
operation as a deductive proof.

## Evidence semantics

FormalSpecGen keeps different claims separate:

| Claim | Meaning |
| --- | --- |
| `STATIC_CHECK` | The selected language's compiler/static and deterministic lint gates passed |
| `DEDUCTIVE_PROOF` | A supported implementation satisfied its reviewed contract through a prover |
| `BOUNDED_ARCHITECTURE_EVIDENCE` | TLC checked the finite abstraction and declared invariants |
| `RUNTIME_SAMPLE` | RAC/tests exercised concrete executions; this is not proof |
| `NO_PROOF` | A required gate failed, was unsupported, or was not reached |

Every drafting run records the lifecycle:

```text
REQUIREMENTS → CONTRACT → CANDIDATE ⇄ CHEAP_GATES → PROOF → REVIEW_AND_MEASURE
```

Evidence includes source and contract hashes, candidate hashes, normalized failure fingerprints,
tool versions, commands, finite bounds, abstraction mode, attempts, token usage, and explicit skipped
gate reasons. RAC counterexamples drive regeneration but never establish proof. TLC counterexamples
repair validated IR rather than generated TLA+ text.

## Repository layout

```text
pipeline/              CLI, orchestration, language lanes, assurance policy, and tool adapters
pipeline/verify_*.py    Normalized Java, Rust, and C formal-tool judges
pipeline/domains/      Reviewed and scaffolded semantic-domain plugins
formalspec_core/       Shared deterministic postprocessor and proof-support core
domains/               Declarative domain specifications
tests/                 Mocked deterministic and integration tests
tests/v2/              Isolated tests for the typed V2 domain-evidence lifecycle
tests_e2e/             Opt-in real-tool and live-provider tests
tools/                 Local external verifier installations (ignored by Git)
archive/               Retired VS Code/FastAPI UI and historical compatibility sources
```

`pipeline/ide.py` is retained despite its historical name because the native implementation loop
still uses its deterministic transformation helpers. The old external `formalspecDD` handoff is
archived; implementation synthesis now runs inside this repository.

## Current scope and limitations

- JML-to-TLA+ conversion supports reviewed semantic patterns through typed IR and domain plugins;
  it is not a general translation of arbitrary JML or Java.
- TLC alone checks only a finite architecture abstraction. Source/model refinement is claimed only
  when a dedicated refinement gate also proves the scoped contract-simulation obligations.
- RAC/JUnit and Kani results are execution or bounded evidence, not universal deductive proof.
- Prusti support and Rust/C synthesis remain experimental. Standard Rust/C assurance requires a
  successful native static check plus an instrumented generated runtime sample and is capped at
  `RUNTIME_SAMPLE`; it is not deductive proof.
- Rust and C have conservative, explicitly accepted proof-support passes. They cover only
  signature-derived slice bounds, locally identifiable pure helpers, direct pointer validity, and
  human-authored loop-frame markers; they do not infer arithmetic policy, aliasing, or loop frames.
- Deterministic passes that alter proof-relevant annotations require explicit human acceptance.
- Unknown AST nodes, ambiguous domains, unreviewed renderer mappings, missing tools, and modified
  locked contracts fail closed.

## Testing and packaging

```bash
python3 -m pytest -c pytest.ini
python3 -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
```

The deterministic suite currently reports 99.06% combined statement/branch coverage and enforces a
minimum of 99%. Real-toolchain and optional live-Ollama checks remain in `tests_e2e/` and can be run
with:

```bash
scripts/run_e2e.sh
RUN_LIVE_LLM_E2E=1 scripts/run_e2e.sh
```

Run the real-TLC V2 lifecycle tests directly with:

```bash
python3 -m pytest -c tests_e2e/pytest.ini tests_e2e/test_v2_workflow.py -v
```

These tests validate and promote elevator and vending-machine candidates, exercise mixed
void/Boolean APIs and the per-actor last-result abstraction, and confirm post-validation candidate
tampering blocks promotion. All four cases pass against the repository-local TLC 2.19 distribution.
TLC may open an internal localhost RMI listener even with one worker;
locked-down containers must permit that loopback operation or the tool will report
`java.net.SocketException: Operation not permitted` before model checking.

## License

Copyright 2026 Sheel Morjaria. Licensed under the Apache License 2.0; see [LICENSE](LICENSE) and
[NOTICE](NOTICE).
