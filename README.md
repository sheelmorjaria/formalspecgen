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

Explicit lock protocol → bounded invocation histories → canonical Rust Mutex object
                                                       └─ restricted history refinement

Legacy Java → javalang AST inspection → hash-bound deterministic refactoring
                                      └─ baseline + refactored OpenJML ESC
                                           └─ REFACTOR_CONTRACT_PRESERVED

Hexagonal composition → contracted Port + explicit argument bindings → core OpenJML ESC
                      └─ generated Adapter → UNVERIFIED EXTERNAL BOUNDARY
```

The governing rule is:

> The LLM proposes; deterministic compilers transform; formal tools judge; humans control trusted assumptions.

### Full-lifecycle capability map

FormalSpecGen now covers three connected workflows:

| Workflow | Entry point | Strongest scoped evidence |
| --- | --- | --- |
| Synthesis | `domain` → `validate-domain` → `promote-domain` → `draft` → `implement` | Native `DEDUCTIVE_PROOF` and supported `SOURCE_MODEL_REFINEMENT` |
| Scaling | `system`, lock-protocol V2, Rayon wrapper, async-message V2 | `SYSTEM_COMPOSITION_PROOF`, restricted `CONCURRENT_LINEARIZABILITY`, `PARALLEL_PARTITION_VERIFIED`, or capped async static evidence |
| Hexagonal integration | `compose` with external Ports, adapter names, and explicit step arguments | `SYSTEM_COMPOSITION_PROOF` for core-to-Port contract use; `external_io_safety_proved: false` |
| Modernization | `inspect` → `apply-refactor` → `verify-refactor` | `REFACTOR_CONTRACT_PRESERVED` after independent baseline/refactored ESC |

These evidence classes are intentionally not interchangeable. In particular,
`REFACTOR_CONTRACT_PRESERVED` proves that both revisions discharge the same normalized JML/API
surface; it does not claim relational behavioral equivalence. Async Tokio generation similarly
stops at bounded architecture evidence plus static checking rather than claiming atomic refinement.
Hexagonal evidence likewise proves that core call sites establish Port preconditions while excluding
generated external adapters and remote I/O behavior from ESC.

### Verified polyglot scorecard

One reviewed V2 domain lowers deterministically into three languages and is proved by three
independent solver stacks — no LLM touches the contracts:

| Lane | Prover | Live evidence |
| --- | --- | --- |
| Java/JML | OpenJML ESC + TLC | `DEDUCTIVE_PROOF` with `SOURCE_MODEL_REFINEMENT` |
| Rust/Prusti | Prusti 0.2.2 (Viper/Silicon + Z3) | Peterson: 12/12 plus 6/6 refinement; ABP: 11/11 plus 6/6 refinement |
| C/ACSL | Frama-C WP + Z3 | Peterson: 87/87 plus 6/6 refinement; ABP: 82/82 plus 6/6 refinement |
| Concurrent Rust | TLC 2.19 + rustc + exact-source history gate | Bank account: 173 states / 356 transitions; `CONCURRENT_LINEARIZABILITY` |

```bash
formalspecgen draft "..." --canonical-domain <module> --lang {java,rust,c}   # deterministic
formalspecgen verify SmartLock.rs --mode esc                                 # native proof
```

Reproducible artifacts live under `domains/examples/polyglot/`. The deterministic baseline
also catches translation bugs an LLM draft would silently ship: the smart_lock run exposed
an `==>`-precedence under-encoding that a green prover had been accepting, now fixed and
unit-pinned in both serializer suites.

### Peterson mutual-exclusion benchmark

The bounded Peterson evaluation scalar-expands the two processes into six atomic transitions:
`request0`, `enter0`, `exit0`, and their process-1 counterparts. Explicit program counters make
critical-section occupancy observable without claiming that the generated sequential structs model
hardware atomics or weak-memory behavior.

TLC validated mutual exclusion across 10 reachable states and 16 transitions. The first native
proof attempt then exposed an important distinction: a property can hold over every reachable state
without its chosen invariant being strong enough for modular induction. Prusti rejected the two
`enter` methods until the reviewed model recorded four auxiliary protocol facts:

- a waiting process has already raised its flag; and
- a critical process still satisfies the entry condition that admitted it.

After revalidation and hash-bound promotion, Prusti proved 12/12 items, Frama-C WP proved 87/87
goals, and both native refinement gates proved all six transition correspondences. The complete
scope, certificates, artifacts, and the deliberate weak-memory limitation are recorded in
[`domains/examples/polyglot/peterson/README.md`](domains/examples/polyglot/peterson/README.md).

### Alternating Bit Protocol benchmark

The bounded ABP evaluation models unreliable single-slot message and acknowledgement channels with
`-1` as the empty sentinel. Six atomic transitions cover sending, receiving, retransmission, and
independent loss of data or acknowledgements. Four phase-consistency invariants prevent stale data
or acknowledgements from advancing the sender or receiver out of order.

TLC validated all 18 reachable states and 36 transitions. Prusti verified 11/11 items, Frama-C WP
proved 82/82 goals, and both native refinement gates proved all six transition correspondences.
The benchmark also hardened negative-integer lowering, scalar expression type checking, redundant
frame canonicalization, and conditional TLA+ `Integers` imports without invalidating existing
positive-only serialization hashes. Full results and scope are recorded in
[`domains/examples/polyglot/alternating_bit_protocol/README.md`](domains/examples/polyglot/alternating_bit_protocol/README.md).

### Concurrent bank-account linearizability benchmark

The concurrent bank-account benchmark was generated through the interactive V2/Ollama lifecycle,
not written directly as YAML. Human review caught the first generated candidate weakening the
request to `concurrency: null`: TLC correctly validated that smaller atomic model (3 states / 4
transitions), but the candidate was not promoted because it omitted the requested lock history.
The staged generator now fails closed whenever authoritative `lock_protocol` requirements produce
null or incomplete concurrency metadata.

After regeneration and hash-bound promotion, the model contains two actors, explicit
invoke/acquire/linearize-or-reject/release/respond phases, and reviewed `effect_commit`
linearization points for `Deposit` and `Withdraw`. TLC 2.19 validated 173 reachable states and 356
transitions. The deterministic Rust lowering places all concrete state behind one
`std::sync::Mutex`, handles poisoning without `unwrap` or `expect`, and returns
`LockError::Unavailable` on a false domain guard. An explicit TLA+ `Reject` transition mirrors that
observable failure path without changing domain state.

The implementation route minted `CONCURRENT_LINEARIZABILITY` with certificate
`1c43281d492e5e620138c57225d0b6c02b0156a6c697a4821937688d3ed2bd16`. Its scope is deliberately
restricted to `bounded_single_mutex_history_refinement`: successful lock acquisition serializes
the complete protected state, reviewed effects execute while the guard is live, `effect_commit`
is the successful-call linearization point, and guard release precedes response. Exact canonical
source matching excludes alternate control flow.

This benchmark did **not** use Prusti to prove mutex contracts. The native gate was `rustc`, and
its evidence explicitly records that Prusti annotations were erased and no contract was proved.
Java remains capped at `LOCK_DISCIPLINE_VERIFIED` because its canonical artifact is still a JML
contract scaffold; C lock-protocol lowering remains unsupported. Reproducible inputs are
[`domains/candidates/concurrent_bank_account.v2.yaml`](domains/candidates/concurrent_bank_account.v2.yaml),
[`domains/v2/concurrent_bank_account.json`](domains/v2/concurrent_bank_account.json), and
[`ConcurrentBankAccount.rs`](ConcurrentBankAccount.rs).

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

The same deterministic lowering is available for Rust/Prusti (install a Prusti release
under `tools/prusti/`; its bundled `rust-toolchain` pin is installed automatically by
rustup, and `python3 -m zipfile`-based extraction must be followed by `chmod +x` on the
bundled binaries):

```bash
formalspecgen draft "Generate the reviewed bounded counter" --no-clarify \
  --canonical-domain bounded_counter --lang rust --out-file BoundedCounter.rs
```

`pipeline/v2_prusti_serializer.py` derives every `#[requires]` and `#[ensures]` clause
from the reviewed typed trees and transcribes the reviewed effects into method bodies
(pre-captured locals preserve simultaneous semantics). Because Prusti's struct type
invariants remain an experimental feature that aborts the released driver, reviewed
invariants are encoded per-method instead: assumed by `requires` on entry and re-established
by `ensures` on exit, with the constructor proving them for the initial state. The command runs the Rust
safety lint and the contract-erased `rustc` gate before writing the file plus its
`.canonical.json` evidence (`DETERMINISTIC_V2_TO_PRUSTI`), and fails closed on unsupported
semantics. Prusti itself judges the annotated source when installed; without it the claim
remains `REVIEWED_TRANSFORMATION`, never `DEDUCTIVE_PROOF`. The same lowering exists for C/ACSL:

```bash
formalspecgen draft "Generate the reviewed bounded counter" --no-clarify \
  --canonical-domain bounded_counter --lang c --out-file bounded_counter.c
```

`pipeline/v2_acsl_serializer.py` emits a typedef struct plus `{module}_{operation}`
functions whose `requires`/`assigns`/`ensures` clauses derive from the reviewed typed
trees; bodies transcribe the reviewed effects with pre-captured locals.  ACSL has no
persistent struct invariants, so reviewed invariants are assumed on entry and
re-established on exit of every mutator (the same per-function encoding the Rust lane
uses).  The command runs ACSL lint and a strict C11 gate before writing the file plus
`.canonical.json` evidence (`DETERMINISTIC_V2_TO_ACSL`).  With Frama-C installed,
`formalspecgen verify bounded_counter.c --mode esc` runs WP; the deterministic
bounded_counter contract proves 27/27 goals including generated RTE obligations.

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
- Complete `lock_protocol` metadata with per-actor ownership values and reviewed operation
  linearization points. Domain operations cannot read or mutate the abstract protocol lock.
- Bounded invocation histories with separate invoke, acquire, successful `effect_commit`, false
  guard rejection, release, and response transitions.
- Deterministic non-panicking Rust `Mutex<State>` lowering plus exact structural lock-discipline
  evidence. Java `synchronized` lowering receives only the weaker structural claim.
- A restricted Rust history-refinement certificate that upgrades
  `concurrent_linearizability_proved` only after successful TLC evidence, native Rust compilation,
  complete reviewed lock metadata, and byte-exact canonical-source binding.

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

### System decomposition

`formalspecgen system` scales the existing component and composition gates across isolated CLI
processes. A strict system artifact embeds one `CompositionSpec` and supplies exactly one trusted
interface file, reviewed V2 domain, and validation-evidence path for every composition binding:

```bash
formalspecgen system system.json --out-dir runs/system --max-workers 4 \
  --json runs/system-verdict.json
```

The command starts at most `--max-workers` independent `formalspecgen implement` processes. Each
component writes its own verdict under `<out-dir>/<component>/verdict.json`. A missing verdict,
nonzero exit, `NO_PROOF` claim, process-launch error, duplicate component, incomplete binding set,
or mismatched system identity produces `SYSTEM_SYNTHESIS_FAILED`; the composition gate is never
called after a component failure. Only after every isolated component succeeds does the existing
OpenJML composition verifier run. Its successful result is hash-bound with every component verdict
into `SYSTEM_COMPOSITION_PROOF` under scope
`isolated_component_proofs_plus_scoped_composition`.

Parallel subprocess execution is an orchestration optimization, not a verified property of the
generated system: aggregate evidence records `concurrent_component_execution_proved: false`. The
claim composes the individual proof scopes already present in component verdicts with the existing
single-threaded atomic composition scope; it does not establish distributed execution semantics,
cross-process transactions, message delivery, or concurrent composition linearizability.

### Immutable data-parallel kernels

Phase 3 supports one deliberately narrow Rayon profile: a sequential Rust kernel with exact
signature `pub fn process_chunk(value: i32) -> i32` must first receive a native deductive-proof
claim. The implementation command can then append and check a deterministic immutable wrapper:

```bash
formalspecgen implement Kernel.rs --assurance-level critical \
  --parallel-wrapper rayon --parallel-kernel process_chunk \
  --parallel-out Kernel_parallel.rs --json parallel-verdict.json
```

The wrapper accepts `&[i32]`, partitions it through `par_iter()`, copies each scalar into the
unchanged proved kernel, and collects a fresh `Vec<i32>`. FormalSpecGen compiles the combined source
with offline `rayon=1.11.0` and warnings denied. Exact canonical-source matching plus the prior
kernel proof mints `PARALLEL_PARTITION_VERIFIED` under scope
`immutable_elementwise_rayon_partition`.

The claim establishes the shared-input/fresh-output alias boundary and proves that the verified
kernel source was not modified. It explicitly records `parallel_scheduler_proved: false` and
`parallel_functional_equivalence_proved: false`: Rayon scheduling, performance, panic behavior in
arbitrary kernels, effect ordering, mutable chunk partitioning, reductions, SIMD, and GPU execution
remain outside this profile. Static checking alone cannot authorize the wrapper.
The live scalar example at
[`domains/examples/parallel/IncrementKernel.rs`](domains/examples/parallel/IncrementKernel.rs)
is proved by Prusti 0.2.2 (1/1 item); the deterministic wrapper is separately compiled against
cached `rayon=1.11.0` in offline mode.

### Bounded asynchronous message transport

Phase 4 adds an intentionally narrow Rust/Tokio profile. An Ollama-generated V2 candidate may set
`execution_model: async_message_passing` with at least two actors. Validation still explores a
bounded atomic message-handler abstraction with TLC. After review and promotion, Rust drafting
deterministically emits a typed message enum, a bounded `tokio::sync::mpsc` channel, and panic-free
async send methods. The exact scaffold is checked offline against pinned `tokio=1.49.0`.

This lane only emits `BOUNDED_ARCHITECTURE_EVIDENCE` plus `STATIC_CHECK`. Its verdict records
`source_refinement_proved: false`, `async_linearizability_proved: false`, and
`distributed_delivery_proved: false`. Queue scheduling, message loss or duplication, fairness,
eventual delivery, handler execution, and correspondence between Tokio traces and atomic TLA+
steps are outside the claim. Java and C async lowering, noncanonical Rust sources, and attempts to
mint `SOURCE_MODEL_REFINEMENT` fail closed with `UNSUPPORTED_BOUNDARY`.

### Contract-preserving Java refactoring

The initial modernization profile compares two independently verified Java/JML revisions:

```bash
formalspecgen verify-refactor baseline/Account.java refactored/Account.java \
  --json refactor-verdict.json
```

Both revisions must retain the same public class identity, matching filenames, normalized JML
clauses, and public/protected method declarations. OpenJML `check` and `esc` must succeed for each
revision without dropped verification conditions. A successful run hash-binds both sources and the
shared surfaces in `REFACTOR_CONTRACT_PRESERVED` evidence.

This is deliberately not a relational equivalence proof. The verdict records
`behavior_equivalence_proved: false` and `refactor_verified: false`: two implementations can satisfy
the same incomplete contract while behaving differently. Contract inference from unverified legacy
code, automatic design-pattern rewrites, private behavior, reflection, concurrency, I/O, and heap
topology equivalence remain outside this first profile. Any changed contract/API surface or failed
baseline/refactored proof produces `NO_PROOF`.

### AST-based modernization inspection

Before changing legacy Java, the read-only inspection command parses exactly one concrete class
with pinned `javalang=0.13.0`:

```bash
formalspecgen inspect LegacyService.java --json inspection.json
```

An explicit detector registry owns small independent AST rules. The catalog flags repeated runtime
type dispatch (Strategy), classes at or above 10 fields and 15 callables (Facade/decomposition),
methods longer than 60 lines (Extract Method), constructors with at least five parameters,
private-constructor/static-accessor Singleton shapes (dependency-injection review), paired listener
registries (Observer), large mostly-literal construction calls (Builder), database calls mixed with
branching/calculation (Repository), and delegation-heavy single-field wrappers (Adapter). Findings
also cover conditional creation of multiple concrete products (Factory Method), repeated branching
on scalar `state`/`status`/`mode` fields (State), and interface wrappers that combine logging or
metrics with delegation in at least half their public methods (Decorator). Findings include source
lines, implicated methods or fields where relevant, metrics, recommendations, and a source hash.
Comments and literals cannot
manufacture findings because decisions are made from Java AST nodes; lexical scanning is used only
to calculate method end lines, which `javalang` does not expose.

The output claim is `STATIC_INSPECTION`, not a proof that a design is defective. It records
`formal_defect_proved: false`, `automated_refactor_applied: false`, and
`behavior_equivalence_proved: false`. Unsupported syntax, multiple top-level types, missing files,
and non-Java inputs fail closed. The command recommends patterns but never rewrites source.

### Deterministic Extract Method application

The first action profile consumes hash-bound inspection evidence and applies Extract Method to one
AST-identified long public or protected method:

```bash
formalspecgen apply-refactor baseline/Calculator.java \
  --inspection inspection.json --pattern extract-method --method calculate \
  --out refactored/Calculator.java --json applied-refactor.json
```

The complete body moves into a uniquely named private helper while the original signature remains
as a delegating wrapper. The helper repeats the original JML obligations so OpenJML can reason
modularly; normalized contract-set comparison ensures repeated annotation text is not mistaken for
a changed contract. Overloaded names, abstract/native bodies, stale inspection hashes, absent
long-method findings, helper collisions, and unreconstructable spans fail closed.

Writing source is not preservation evidence. The command immediately invokes `verify-refactor`;
only independent successful ESC results can produce `REFACTOR_CONTRACT_PRESERVED`. Output still
records `behavior_equivalence_proved: false` and `refactor_verified: false`. Strategy, Facade,
dependency injection, multi-file moves, arbitrary statement selection, and semantic rewrites remain
outside this initial action profile.

State and Decorator currently remain inspection-only recommendations. Their deterministic
application would introduce new objects and cross-file calls with transition or callback-order
semantics. `apply-refactor` does not offer those patterns until profile-specific obligations can
prove the generated collaborators and delegation glue rather than merely compiling them.

### Cross-file refactoring verification

`verify-refactor` also accepts a refactored source directory whose primary file retains the baseline
filename:

```bash
formalspecgen verify-refactor baseline/Service.java refactored/ \
  --json multifile-refactor-verdict.json
```

The primary class must preserve the baseline public/protected declarations and normalized JML
surface. The baseline is proved independently; every immediate Java/JML file in the refactored
directory is then checked and proved together so extracted interfaces, implementations, and
delegation glue share one OpenJML context. Evidence hash-binds a sorted per-file manifest and can
mint `MULTIFILE_REFACTOR_CONTRACT_PRESERVED`.

This closes the proof boundary needed before future Factory/State/Decorator actions can be admitted,
but does not itself implement those transformations. The claim records
`behavior_equivalence_proved: false`, `heap_topology_equivalence_proved: false`, and
`refactor_verified: false`: joint satisfaction of the preserved primary contract is not a
bisimulation proof of all private behavior, allocation identity, callback order, I/O, or timing.

### Hexagonal external ports and adapter stubs

Composition artifacts may declare a contracted external interface using `kind: "interface"` (or
the normalized input alias `type: "interface"`), `external: true`, and an optional adapter type:

```json
{
  "id": "payments",
  "name": "PaymentGateway",
  "type": "interface",
  "external": true,
  "adapter": "StripePaymentGateway",
  "operations": [{
    "name": "charge",
    "parameters": [{"name": "amount", "type": "int"}],
    "returns": "boolean",
    "requires": ["amount > 0"],
    "ensures": ["\\result ==> amount > 0"]
  }]
}
```

Every external operation must provide nonempty pre- and postconditions. Composition deterministically
renders the port interface and an adapter stub with copied JML plus a conspicuous external-boundary
marker and TODO body. The adapter source is distributed as integration scaffolding but excluded from
OpenJML check/ESC evidence. Verdicts list it under `unverified_boundaries`, record the skip reason
`Unverified external boundary`, and set `external_io_safety_proved: false`.

Parameterized Port calls use explicit step bindings:

```json
{"component":"payments", "operation":"charge", "arguments":{"amount":"amount"}}
```

Each Port parameter must be bound exactly once to a Java identifier or integer/Boolean literal.
Identifiers become typed orchestrator parameters; repeated identifiers must have the same declared
Port type. The renderer substitutes bindings into the Port preconditions, injects the Port through
the orchestrator constructor, and OpenJML proves the call site establishes those preconditions.
Missing, extra, expression-valued, or type-conflicting bindings fail closed.
Before rendering, the composition gate evaluates fully literal Port preconditions and checks the
supported integer-interval and Boolean constraint subset for contradictions. Ground-false bindings
return `UNSATISFIABLE_BINDING`; inconsistent variable constraints return
`CONTRADICTORY_COMPOSITION`. Recognized OpenJML false-precondition warnings are also classified as
`VACUOUS_COMPOSITION`, so an impossible caller contract cannot mint a composition proof.

When that core proof succeeds with external Ports present, composition evidence uses
`SYSTEM_COMPOSITION_PROOF`, lists every skipped adapter, and keeps
`external_io_safety_proved: false`. The claim proves the generated core respects contracted Port
calls; it does not prove the adapter implementation, remote service, transport, credentials,
availability, response authenticity, or network side effects.

### Restricted Factory Method application

After the cross-file gate, `apply-refactor` admits one narrow Factory Method shape:

```bash
formalspecgen apply-refactor baseline/Creator.java \
  --inspection inspection.json --pattern factory-method --method create \
  --out refactored/ --json factory-refactor-verdict.json
```

The inspected method must consist solely of one closed `if/else` whose return paths create at least
two distinct zero-argument concrete products. Its decision expression may reference parameters but
not instance fields or unqualified helper calls. The deterministic action emits the preserved
primary class, a product-typed factory interface, and a default implementation containing the exact
creation body. Existing product types must already be available in the output proof context.

The generated directory is immediately routed through the multi-file gate. Constructor arguments,
field-dependent decisions, additional statements, overloaded target names, type-name collisions,
side effects, or stale inspection evidence fail closed. State and Decorator transformations remain
inspection-only: their transition and callback-order mappings require stronger profile-specific
obligations than the Factory creation-policy extraction.

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
