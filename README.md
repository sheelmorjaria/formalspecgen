# FormalSpecGen

FormalSpecGen is a human-in-the-loop IDE and verification service for turning natural-language requirements into reviewed, mechanically checked formal specifications and verified code.

```text
Natural-language system requirement
              │
              ▼
Interactive ambiguity extraction + human clarifications
              │
              ▼
Architecture artifact + SOLID/STRIDE lint
              │
              ├──▶ Java/JML contract ──▶ typed JML AST ──▶ transition IR
              │                                               │
              │                                               ▼
              │                                    reviewed domain plugin
              │                                               │
              │                                               ▼
              │                              deterministic TLA+ + TLC checking
              ▼
Java/JML interfaces + use-case orchestrators ──▶ OpenJML check + composition ESC
              │
              ├── ADR evidence
              ├── RAC integration safety net
              └── dependency-aware safe refactoring
              │
              ▼
JML implementation pipeline / OpenJML ESC
              │
              ├── verified ─────────────────────────▶ result
              └── recognized encoding boundary ────▶ targeted Dafny/Z3
```

FormalSpecGen now contains the complete default path: NL → trusted JML → synthesized Java →
OpenJML deductive verification. The former `../formalspecDD` handoff remains available only as a
legacy compatibility path; it is not required for implementation synthesis.

## Highlights

- Natural language to complete JML-annotated Java stubs.
- Interactive requirement elicitation for proof-relevant bounds, failure behavior, state,
  nullability, frame conditions, concurrency, ordering, types, and environment assumptions.
- OpenJML-backed syntax, type, and specification validation.
- Native trusted-contract implementation synthesis with separate resample and diagnostic-repair
  budgets, candidate hashing, trust-boundary checks, and OpenJML ESC proof.
- Bounded LLM repair with stall detection and complete attempt history.
- VS Code Spec Chat sidebar and streamed pipeline progress.
- Workspace-persisted Spec Chat requirements, clarification questions, answers, repair inputs,
  selected passes, and activity log, with explicit session clearing.
- Inline verification-condition diagnostics in the editor and Problems panel.
- Dedicated JML language server with completion, hover help, and immediate structural diagnostics.
- Missing-spec and vacuity linting for frames, array nullability, postconditions, tautologies, and unsupported aggregates.
- Plain-English VC explanations and suggested proof repairs directly in diagnostic hovers.
- Cached, on-demand LLM explanations layered over deterministic VC guidance.
- Native VS Code Quick Fixes for deterministic lint repairs and guarded VC refinement.
- Experimental Rust/Prusti contract drafting with Rust-specific lint diagnostics and an explicitly non-proof `rustc` check.
- AWS Kani bounded Rust verification for explicit, human-reviewed `#[kani::proof]` harnesses,
  reported separately as `BOUNDED_RUST_EVIDENCE`.
- Independent C11/ACSL lane with deterministic safety linting, strict compiler gating, and
  Frama-C WP runtime-error proof obligations.
- Clause-aware refinement with protected clauses and no-clobber diff review.
- Selectable deterministic postprocessor passes with native VS Code diff previews.
- JML-first theorem proving with targeted Dafny fallback for four reviewed encoding boundaries.
- Retrieved toolchain guardrails injected dynamically into drafting and repair prompts.
- Deterministic cross-file JML retrieval injects relevant workspace method contracts, exact clauses,
  signatures, and source provenance into drafting and composition context.
- LLM-backed inline invariant suggestions for `while` loops.
- RAC/JUnit runtime evidence for failed verification conditions.
- Bounded TLA+/TLC concurrency abstraction and counterexample traces.
- Visual counterexample explorer: TLC state tables highlight changed variables at each transition,
  while OpenJML proof-obligation tables retain line, category, explanation, and suggested repair.
- Precedence-aware typed JML AST and generic method-transition IR.
- Fail-closed semantic domain plugins for banking, inventory, and train-road crossings.
- Deterministic domain scaffolding from validated YAML/JSON specifications.
- Proactive deterministic postprocessor-pass discovery.
- GitHub Action annotations, native implementation verdicts, and optional legacy handoff intents.
- Layered system-design wizard with Clean Architecture graphs, SOLID linting, TLA+ model checking, JML interfaces, and composition orchestrators.
- Automated ADRs, orchestrator RAC integration tests, dependency-aware safe refactoring, and STRIDE trust-boundary analysis.
- REST endpoints for the original browser interface and a stateful WebSocket protocol for IDE clients.

## Verification model

FormalSpecGen separates claims that are often incorrectly grouped together:

| Stage | Tool | What it establishes |
| --- | --- | --- |
| Draft validation | `openjml -check` | Java/JML grammar, types, names, and clause well-formedness |
| Deductive verification | `openjml -esc` + Z3 | Method bodies satisfy their JML contracts |
| Composition verification | Generated orchestrator + `openjml -esc` | Calls establish the next component's preconditions and the use-case contract |
| Boundary verification | Dafny + Z3 | A recognized JML encoding boundary verifies through a native Dafny encoding |
| Architecture verification | TLA+ + TLC | A bounded design model satisfies declared safety invariants across interleavings |
| Runtime evidence | OpenJML RAC + generated JUnit | Sampled executions respect instrumented contracts for the tested environment |

A clean draft check does not mean an implementation has been proved. A clean bounded TLA+ model
does not prove Java source equivalence, and passing RAC tests are not a proof. The IDE reports these
statuses separately.

### Assurance profiles

Set `formalspecgen.assuranceLevel` to `critical`, `standard`, or `lightweight`. The backend owns the
corresponding gate policy; the setting cannot promote weaker evidence into a stronger claim.

| Profile | Required evidence | Maximum successful claim |
| --- | --- | --- |
| Critical | `javac`, spec lint, OpenJML check, bounded TLA+, OpenJML ESC, reviewed boundary fallback | `VERIFIED` / `DEDUCTIVE_PROOF` |
| Standard | `javac`, spec lint, OpenJML check, RAC/JUnit | `STATIC_CHECKED_RUNTIME_TESTED` / `RUNTIME_SAMPLE` |
| Lightweight | `javac`, spec lint, ordinary runtime tests | `COMPILED_LINTED` / `RUNTIME_SAMPLE` |

Use the WebSocket actions `assurance_plan` to inspect required and skipped gates and
`assurance_verdict` to classify collected gate statuses. Every skipped gate includes the assurance
level as its reason. Missing or failed required gates produce `ASSURANCE_INCOMPLETE` with
`NO_PROOF`; only a complete Critical profile may set `deductive_proof_provided` or
`source_refinement_proved` to true.

### Six-state evidence lifecycle

Every drafting run uses one shared `PipelineState` vocabulary:

```text
REQUIREMENTS → CONTRACT → CANDIDATE ⇄ CHEAP_GATES → PROOF → REVIEW_AND_MEASURE
```

Each transition emits a `pipeline_transition` WebSocket event and writes an immutable JSON artifact
under `<run>/evidence/`. Candidate evidence includes a SHA-256 hash; failures include normalized
fingerprints derived from backend, VC category, method, line, and diagnostic. Repeated hashes detect
duplicate candidates and longer oscillation cycles, while repeated fingerprints detect proof
non-progress.

Fresh resampling and diagnostic feedback have independent budgets. Configure them through
`--resample-budget` and `--feedback-budget`; `--max-attempts` remains an optional overall cap. Cheap
gates have a fixed recorded order:

1. Java structure
2. `javac`
3. deterministic specification lint
4. OpenJML check
5. RAC quick test, or an explicit skip reason when no trusted implementation exists

A failed compiler gate prevents OpenJML from running. Every skipped gate records why it was skipped.
Draft verification ends with a `STATIC_CHECK` claim and an explicit skipped proof state; it is never
promoted to deductive proof.

Locked-clause modification is terminal `TRUST_BOUNDARY_VIOLATION`. The violating candidate is kept
as audit evidence, but the applicable `new_stub` remains the trusted original. Java and Rust
postprocessor changes are labelled unaccepted proof-relevant transformations until the user approves
their diff. RAC returns runtime/counterexample evidence and a regeneration recommendation, never a
proof. TLC returns `BOUNDED_ARCHITECTURE_EVIDENCE`, sets `source_refinement_proved` to false, and
directs invariant repair to validated IR rather than generated TLA+ text.

`verdict.json` records source, contract, and requirement hashes; backend and tool versions; executed
command; finite bounds and abstraction when applicable; token usage; gate records; evidence paths;
candidate hashes; failure fingerprints; and every lifecycle transition. TLA+ results additionally
hash the validated IR, generated module, and separate TLC configuration.

## JML-to-TLA+ methodology

FormalSpecGen does not translate arbitrary JML text directly into TLA+. JML describes sequential
method contracts using pre-state/post-state reasoning, while TLA+ describes whole-system state
transitions and interleavings. A syntax-to-syntax rewrite would lose atomicity, lock protocol,
environment, and finite-state assumptions.

The implemented compiler pipeline separates structure from domain meaning:

```text
Validated Java/JML contract
            │
            ▼
Deterministic tokenizer + precedence-aware JML parser
            │
            ▼
Discriminated Pydantic expression AST
            │
            ▼
Generic MethodTransitionIR
  guards / success effects / failure effects / frame / result condition
            │
            ▼
Conservative domain recognizer
            │
            ├── no match ─────────▶ UNSUPPORTED_BOUNDARY
            ├── multiple matches ─▶ AMBIGUOUS_DOMAIN
            ▼
Reviewed semantic adapter
  AST shapes → whitelisted guard/effect/frame identifiers
            │
            ├── inconsistency ────▶ CONSISTENCY_FAILED
            ▼
Bounded typed domain model
            │
            ▼
Deterministic TLA+ module + separate TLC configuration
            │
            ▼
Preflight → SANY semantic analysis → TLC
```

Raw clauses, declarative AST-pattern strings, and LLM-generated formal-language fragments never
reach the renderer. Unsupported tokens, unknown identifiers, calls, quantifiers, nonlinear
arithmetic, excessive frames, missing guards, unknown effects, and unlowered `\result` expressions
stop before TLC. Counterexamples remain associated with the validated IR; the pipeline does not
repair generated TLA+ text with regexes or ask an LLM to rewrite it.

### Clarifications and contracts have different roles

Validated JML supplies sequential facts:

- `requires` clauses become candidate transition guards.
- result-conditioned `ensures` clauses become explicit success/failure transitions.
- unconditional postconditions on supported void operations become transition assignments.
- `assignable` clauses become typed frame locations.
- `\old` identifies pre-state values and renders as unprimed TLA+ state.
- `\result` must be lowered before expression rendering.

Human clarification answers supply architectural facts JML cannot reliably infer: linearizability,
atomic-operation versus lock-protocol abstraction, lock ordering, immutable lock keys, actors,
environment behavior, and representative finite bounds. The semantic consistency gate compares
both sources and refuses contradictory models.

### Built-in domains

| Plugin | Recognized API | Main bounded properties |
| --- | --- | --- |
| `bank_account` | `deposit`, `withdraw`, `transfer` | Non-negative/bounded balances, funds/capacity guards, atomic transfer, optional ordered-lock protocol |
| `inventory` | `addStock`, `reserve`, `release` | Bounded stock and reservations; `reserved <= stock` |
| `train_crossing` | `trainApproaches`, `lowerGate`, `trainEnters`, `trainLeaves`, `raiseGate`, `carCrosses`, `carLeaves` | Typed controller states and no simultaneous train/car crossing |

Banking exposes two distinct abstractions. `atomic_operations` checks balance safety and atomic
state changes. `lock_protocol` exposes acquisition program counters and ordered account locks so
intermediate lock states are modelled. A single atomic action that merely mentions locks is not
reported as a deadlock analysis.

## Targeted Dafny boundary translator

The fallback is deliberately not a general Java-to-Dafny compiler. OpenJML already handles ordinary bounded arithmetic, arrays, loops, and search algorithms. The translator activates only for four reviewed boundary signatures:

| JML boundary | Dafny lowering |
| --- | --- |
| Indexed `\old(array)[…]` heap reasoning | Immutable ghost sequence snapshot |
| `\num_of` permutation contracts | Native `multiset(array[..])` equality |
| GCD/pure recursive induction | Mathematical Dafny `function` plus inductive loop invariant |
| Acyclic singly linked reachability | Identity-preserving Dafny class, ghost representation set, dynamic-frame predicate, and strict-subset termination |

Translation is fail-closed. A recognized, supported shape produces a complete standalone `.dfy` program and invokes the real Dafny verifier. Ambiguous or unknown shapes return `UNSUPPORTED_BOUNDARY`; they never produce mixed Java/Dafny syntax or a false verification result.

The original three corpus fixtures and the reviewed linked-reachability template verify with Dafny 4.11:

```text
Reverse.java        heap_snapshot          VERIFIED
InsertionSort.java  permutation_multiset   VERIFIED
GCD.java            recursive_helper       VERIFIED
Node.java           linked_reachability    VERIFIED
```

The linked boundary requires exactly one self-typed `next` field, explicit non-null start/target
preconditions, an explicit `acyclic(start)` assumption, `assignable \nothing`, and one exact pure
recursive reachability expression. It preserves reference identity. Link mutation, cycles, multiple
links, shared mutable tails, allocation, arbitrary aliases, and general object graphs fail closed.

## Repository layout

```text
server.py                         FastAPI REST and WebSocket service
static/index.html                 Lightweight browser interface
pipeline/
  orchestrator.py                 NL → JML draft/check/repair state machine
  elicit.py                       Validated ambiguity extraction and requirement augmentation
  llm.py                          Provider abstraction and guarded prompts
  verify.py                       OpenJML process wrapper
  jml_to_dafny.py                 Targeted boundary lowering and Dafny verifier
  architecture.py                 Architecture schema, SOLID, composition, and STRIDE linting
  system_design.py                Architecture/TLA repair loop and Java/JML scaffolding
  adr.py                          Evidence-backed Markdown ADR generation
  refactor_impact.py              Contract diffs, reverse dependencies, and re-verification
  rac.py                          Method and scaffold RAC/JUnit runtime evidence
  tla_backend.py                  Bounded concurrency abstraction and TLC runner
  jml_ast.py                      Typed expression AST and precedence-aware parser
  transition_ir.py               Generic transition IR and fail-closed expression visitor
  extract_tla_ir.py              Contract-to-transition extraction and consistency gates
  scaffold_domain.py             YAML/JSON domain scaffolding compiler
  domains/
    registry.py                   Static, PyInstaller-visible domain registry
    banking.py                    Banking plugin registration
    inventory*.py                Inventory IR, AST adapter, and renderer
    train_crossing*.py            Crossing IR, AST adapter, and renderer
  limitations.py/.json            Retrieved empirical toolchain guardrails
  spec_lint.py                    Missing-spec and vacuity checks
  explain_vc.py                   Deterministic VC explanations
  ci.py                           GitHub Checks annotations and JSON reports
  ide.py                          Postprocessor bridge and backend recommendation
  postprocess.py                  Compatibility facade for bundled deterministic passes
  refine.py                       Clause-aware, no-clobber refinement
  jml_io.py                       JML extraction, normalization, and clause diffs
  parse_check.py                  OpenJML compiler diagnostic parser
  parse_vcs.py                    OpenJML ESC verification-condition parser
  c_support.py                    C11/ACSL drafting, lint, compile gate, and Frama-C WP
  kani.py                         Explicit-harness bounded Rust verification
  workspace_contracts.py          Bounded cross-file JML contract retrieval
  strategy.py                     Attempt limits, stall detection, and routing decisions
  schemas.py                      Run and diagnostic data contracts
vscode-extension/
  src/extension.ts                Commands, Spec Chat, diffs, and diagnostics
  src/languageServer.ts           JML language-server process
  syntaxes/                       JML TextMate grammar
runs/                             Per-run source, logs, attempts, and verdict.json
handoff/                          Optional legacy external handoff artifacts
domains/                          Declarative domain specifications and examples
formalspec_core/
  postprocess.py                  Shared, self-contained deterministic pass library
```

See [SHARED_LINEAGE.md](SHARED_LINEAGE.md) for modules shared conceptually with `formalspecDD`.

## Requirements

- Python 3.10 or newer.
- FastAPI, Uvicorn, Pydantic, and PyYAML.
- Node.js 20 or newer for the VS Code extension.
- VS Code 1.90 or newer.
- OpenJML 21. The default path is `tools/openjml-dist/openjml`.
- Java plus `tla2tools.jar` for bounded TLA+/TLC architecture verification.
- JUnit Platform Console and `javac` for RAC integration evidence.
- Dafny 4.11 for boundary verification. The defaults are:
  - executable: `~/.dotnet/tools/dafny`
  - runtime: `~/.dotnet`
- Frama-C 33.0 and a C11 compiler for C/ACSL verification. This source checkout includes the
  official relocatable Linux x86-64 distribution at `tools/frama-c-33.0`. On Linux x64, the
  Marketplace extension can download the same pinned distribution into extension global storage.
- Z3 available to Frama-C WP. The repository installation detects Z3 4.8.12.
- No sibling checkout is required. `../formalspecDD` is supported only by the optional legacy
  `/handoff` compatibility endpoint.

## Configuration

Create a project-root `.env` file. At least one LLM provider must be configured for drafting or refinement.

```dotenv
# GLM / Z.ai
GLM_API_KEY=...
GLM_BASE_URL=https://api.z.ai/api/paas/v4
GLM_MODEL=glm-4.5-flash

# Optional OpenAI-compatible provider
OPENAI_API_KEY=...
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o

# Optional local Ollama provider
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_API_KEY=ollama
OLLAMA_MODEL=qwen3-coder:30b
```

Optional runtime settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `OPENJML_BIN` | `tools/openjml-dist/openjml` | OpenJML executable |
| `OPENJML_HOME` | directory containing `OPENJML_BIN` | OpenJML installation root |
| `OPENJML_SPECS` | `$OPENJML_HOME/specs` | Internal Java/JML specifications passed with `--specs-path` |
| `CHECK_TIMEOUT` | `60` | OpenJML check timeout in seconds |
| `ESC_TIMEOUT` | `180` | OpenJML ESC timeout in seconds |
| `LLM_TIMEOUT` | `240` | LLM request timeout in seconds |
| `DAFNY_BIN` | `~/.dotnet/tools/dafny` | Dafny executable |
| `DOTNET_ROOT` | `~/.dotnet` | .NET runtime used by Dafny |
| `DAFNY_TIMEOUT` | `180` | Dafny verification timeout in seconds |
| `TLC_JAR` | `tools/tla2tools.jar` | TLA+ TLC model checker |
| `TLC_TIMEOUT` | `60` | TLC timeout in seconds |
| `PRUSTI_BIN` | `prusti-rustc` | Prusti verifier executable for CLI or managed Rust verification |
| `PRUSTI_TIMEOUT` | `180` | Prusti verification timeout in seconds |
| `KANI_BIN` | `cargo-kani` | AWS Kani executable; the managed extension uses `kani-driver` |
| `KANI_TIMEOUT` | `180` | Kani bounded-verification timeout in seconds |
| `FRAMAC_BIN` | `tools/frama-c-33.0/bin/frama-c` | Frama-C executable |
| `FRAMAC_TIMEOUT` | `180` | Frama-C WP timeout in seconds |
| `FRAMAC_PROVERS` | `z3` | Comma-separated WP prover selection |
| `CC_BIN` | `gcc` | Strict C11 compile-gate executable |
| `OPENJML_JAVA` | bundled OpenJML JDK | Runtime used by RAC-instrumented classes |
| `JMLRUNTIME` | bundled `jmlruntime.jar` | RAC runtime library |
| `JUNIT_JAR` | `tools/lib/junit-platform-console-standalone.jar` | Generated integration-test runner |
| `JAVAC` | `javac` | Java test compiler |
| `RAC_TIMEOUT` | `180` | RAC compile/test command timeout |
| `FORMALSPEC_DD_ROOT` | unset | Optional legacy sibling implementation pipeline |
| `FORMALSPEC_DD_PYTHON` | current Python; `python`/`python3` when frozen | Python executable for the optional legacy subprocess |

The managed VS Code backend sets `LLM_TIMEOUT` from
`formalspecgen.llmTimeoutSeconds` (default: 600 seconds). CLI runs retain the 240-second
default unless `LLM_TIMEOUT` is configured explicitly.

Workspace contract retrieval is local and bounded. Before Java/JML drafting, the extension scans at
most 80 `.java`/`.jml` files and 500 KB, excluding generated outputs and tool directories. The
backend parses only reviewed method-level `requires`, `ensures`, `assignable`, and `signals` clauses,
ranks exact owner/method matches, and records selected source paths and clauses in lifecycle evidence.
If either bound is exceeded, no partial index is used. Retrieved clauses are read-only context: they
help callers establish callee preconditions but do not become trusted clauses in the new contract
without human review.

## Start the backend

```bash
python3 server.py
```

The service listens on `127.0.0.1:8000` by default. Set `PORT` to override the port.

The browser interface is available at:

```text
http://127.0.0.1:8000/
```

## Build and run the VS Code extension

```bash
cd vscode-extension
npm install
npm run compile
```

Open `vscode-extension/` in VS Code and press `F5` to start an Extension Development Host. Open the **Formal Spec** activity-bar view to access Spec Chat and interactive repair.

### Experimental Rust target

Spec Chat offers **Rust / Prusti (experimental)** alongside Java/JML. The Rust lane produces
ownership-aware trait contracts using Prusti annotations, rejects dangerous generated idioms through
`pipeline/rust_support.py`, and surfaces line-addressed findings in the Problems panel. Its prompt
forbids raw pointers, `unsafe`, panic paths, unchecked indexing, and ambiguous overflow behavior;
mutable state is represented through exclusive borrows rather than JML frame clauses.

On first Rust use, the extension offers to install the pinned Prusti `v-2024-03-26-1504` development
package, rustup 1.29.0, and `nightly-2023-09-15` Rust toolchain. Prusti and standalone rustup
binaries are downloaded from their official distributions, SHA-256 verified, and placed in
extension global storage. The exact nightly and its `rustc-dev`, LLVM, standard-library, rustfmt,
and Clippy components are installed into extension-owned `RUSTUP_HOME` and `CARGO_HOME`
directories. No remote installer script is executed and no preinstalled Rust toolchain is required.
Windows x64, Linux x64, Intel macOS, and Apple Silicon macOS are pinned.

When Prusti is available, a draft is passed to the real verifier and reports `VERIFIED`,
`VERIFY_FAILED`, `TIMEOUT`, or `TOOL_ERROR`. Otherwise the backend erases only recognized Prusti
annotations in a temporary copy and invokes `rustc`; that fallback is named `RUST_CHECKED` and
always carries `verification_status: NOT_RUN`. Dafny-to-Rust is not a proof-preserving production
fallback here because Dafny documents its Rust compilation support as partial and growing.

The Rust postprocessor exposes four reviewable passes: explicit overflow-bound markers are promoted
to `#[requires]`, helpers referenced by contracts receive `#[pure]`, simple direct slice indexing
receives a signature-derived `index < slice.len()` precondition, and sum helpers already referenced
by a contract are normalized as pure. Passes never invent application bounds or silently narrow an
API. Every changed pass produces the same unified-diff preview used by the Java postprocessor.

Prusti and rustc error headers are parsed into the shared VC schema. Postconditions, preconditions,
loop invariants, overflow, indexing, panic safety, and termination failures therefore appear as
line-addressed VS Code diagnostics and participate in Hover-to-Explain. Rust linting additionally
flags non-pure contract helpers, owned `Vec<T>` parameters where a slice is sufficient, missing loop
invariants, raw pointers, unsafe code, panic paths, unchecked indexing, and missing public contracts.

Kani is a separate bounded lane. Optionally configure `formalspecgen.kaniPath`, open a Rust file containing a
human-reviewed `#[kani::proof]` harness, and run **Formal Spec: Bounded Rust Check with Kani**.
FormalSpecGen does not convert Prusti preconditions into Kani assumptions because that could weaken
the checked property. Missing harnesses return `HARNESS_REQUIRED`; successful exploration returns
`BOUNDED_RUST_EVIDENCE`, never Prusti-style deductive proof. Kani 0.67.0 release bundles are pinned
and checksum-verified for Linux x64/ARM64 and Intel/Apple Silicon macOS. Native Windows has no
upstream Kani release bundle and remains unsupported; use a WSL extension host for that lane.

### Experimental C/ACSL target

The C lane is independent of JML. Its drafting prompt emits C11 with ACSL `requires`, `assigns`,
`ensures`, loop invariants, loop assigns, and loop variants. Before WP, deterministic linting rejects
dynamic allocation, concurrency/volatile state, inline assembly, known unbounded library calls, and
missing function frames. The cheap gate runs `gcc -std=c11 -Wall -Wextra -Werror -fsyntax-only`.

Optionally configure `formalspecgen.framacPath`, open a reviewed C/ACSL file, and run **Formal Spec: Verify
C/ACSL with Frama-C WP**. FormalSpecGen invokes WP with runtime-error obligations and an explicit
configured prover list. The repository-local Frama-C 33.0 installation currently detects Z3 4.8.12.
`DEDUCTIVE_PROOF` is emitted only when Frama-C exits successfully and its
summary reports a positive number of goals with every goal proved. No JML postprocessor is reused:
each future ACSL transformation requires its own reviewed semantics and tests.
The verdict also records any `Skipped RTE guards` warnings. In that case `runtime_errors` is
`PARTIAL`; the deductive claim covers every generated WP goal, not the omitted RTE categories.

The Marketplace bootstrap installs the official Frama-C 33.0 Arsenic self-extracting distribution
on Linux x64 after SHA-256 verification. It extracts without privilege or system-wide writes into
VS Code global storage. Frama-C does not publish a native Windows bundle and recommends WSL; macOS
currently requires its official package installation and an explicit `framacPath`. A system C11
compiler remains required. Dafny's managed Z3 directory is added to the backend path for WP.

The installed toolchain has been exercised through the real `pipeline.c_support.verify_framac`
path using a bounded integer increment contract:

```text
Frama-C:       33.0 (Arsenic)
Prover:        Z3 4.8.12
Status:        VERIFIED
Claim:         DEDUCTIVE_PROOF
WP goals:      5 / 5 proved
RTE coverage:  PARTIAL
RTE caveats:   unaligned pointers; invalid function-pointer calls
```

The `PARTIAL` label is intentional. Frama-C reported that `\aligned` and `\valid_function` guards
are unsupported, even though the exercised scalar function uses neither feature. The proof claim is
therefore scoped to all generated goals and never silently expanded to omitted RTE categories.

### Desktop packaging and first-run bootstrap

Marketplace builds use a bootstrap architecture. Each platform-specific VSIX contains the bundled
JavaScript extension and one native PyInstaller backend, but not the large verifier distributions. On first
activation the extension asks for consent, downloads the available pinned OpenJML, Dafny, TLA+,
Kani, and Frama-C artifacts into VS Code global extension storage, verifies every SHA-256 digest
before extraction, and starts the backend on
loopback. An archive with a missing or mismatched digest is never executed. Runtime files and
generated runs also live in global storage rather than the read-only extension installation.

The checked-in [`tool-manifest.json`](vscode-extension/resources/tool-manifest.json) pins OpenJML
21.0.27, Dafny 4.11.0, TLA+ Tools 1.7.4, Prusti 2024-03-26, rustup 1.29.0, Kani 0.67.0, and
Frama-C 33.0 Arsenic. Kani covers supported Linux and macOS architectures; managed Frama-C currently
covers Linux x64. Every entry contains its official HTTPS release URL, SHA-256 digest, archive kind,
and executable path. Update and independently verify those pins deliberately when upgrading tools;
the release workflow refuses to publish placeholder, malformed, or incomplete entries.

Users who already manage the tools can set `openjmlPath`, `dafnyPath`, `tlcJarPath`, `kaniPath`, or
`framacPath`; existing paths bypass downloads. Teams can host a reviewed manifest and set
`toolManifestUrl`. LLM keys are
stored using VS Code Secret Storage through **Formal Spec: Configure LLM API Key** and are passed
only to the local backend process.

On Windows the managed backend passes the OpenJML installation and `specs` paths explicitly. If
OpenJML reports that its internal system specifications are missing, the run ends as `TOOL_ERROR`;
it does not spend LLM repair attempts on an infrastructure diagnostic. Verify that the configured
`openjmlPath` still points to the top-level `openjml.bat` and that a sibling `specs` directory exists,
then rebuild/restage the native backend after changing Python runtime code.

Build the standalone backend on its target operating system:

```bash
python3 -m pip install -r requirements.txt pyinstaller
pyinstaller --clean --noconfirm formalspecgen-server.spec
```

Stage the resulting `formalspecgen-server` (or `.exe`) in `vscode-extension/bin/`, then package a
platform VSIX:

```bash
cd vscode-extension
npm install
npm run compile
npx vsce package --no-dependencies --allow-unused-files-pattern --allow-missing-repository --target linux-x64
```

The tag-triggered [release workflow](.github/workflows/release.yml) performs native builds on Windows,
Linux, Intel macOS, and Apple Silicon macOS, creates targeted VSIX files, and attaches them to the
GitHub release. PyInstaller does not cross-compile, so each backend is built on its native runner.

### Marketplace publishing

Set `publisher` in `vscode-extension/package.json` to the immutable Publisher ID registered in the
Visual Studio Marketplace. For the current PAT-based workflow, add an Actions secret named
`VSCE_PAT` with Marketplace Manage permission. A tagged release publishes the four VSIX artifacts
with `vsce publish --packagePath`; it does not rebuild a generic extension in the publishing job.
Publishing is skipped when the secret is absent, while GitHub release artifacts are still produced.

Microsoft has announced retirement of global Azure DevOps PATs on December 1, 2026 and recommends
Microsoft Entra ID workload identity federation for automated Marketplace publishing. Treat
`VSCE_PAT` as a transitional mechanism, use a short expiry and minimum scope, and migrate the
publishing job to `vsce publish --azure-credential` before that deadline. See the
[official VS Code publishing guide](https://code.visualstudio.com/api/working-with-extensions/publishing-extension).

Extension settings:

| Setting | Default |
| --- | --- |
| `formalspecgen.serverUrl` | `ws://127.0.0.1:8000/ws/verify` |
| `formalspecgen.manageBackend` | `true` |
| `formalspecgen.managedPort` | `8765` |
| `formalspecgen.toolManifestUrl` | empty (use bundled manifest) |
| `formalspecgen.openjmlPath` | empty |
| `formalspecgen.dafnyPath` | empty |
| `formalspecgen.tlcJarPath` | empty |
| `formalspecgen.bootstrapPrusti` | `true` |
| `formalspecgen.prustiPath` | empty |
| `formalspecgen.rustupPath` | empty (use managed rustup 1.29.0) |
| `formalspecgen.provider` | `glm` |
| `formalspecgen.ollamaBaseUrl` | `http://127.0.0.1:11434/v1` |
| `formalspecgen.ollamaModel` | `qwen3-coder:30b` |
| `formalspecgen.safeRefactoring` | `true` |

### Commands

- **Formal Spec: Check JML** (`formalspecgen.verify`) — runs fast OpenJML syntax/type validation.
- **Formal Spec: Verify with OpenJML ESC** (`formalspecgen.deepVerify`) — runs deductive verification without fallback.
- **Formal Spec: Verify with Automatic Boundary Routing** (`formalspecgen.autoVerify`) — tries OpenJML first, then routes only a recognized boundary to Dafny.
- **Formal Spec: Configure LLM API Key** (`formalspecgen.setApiKey`) — saves a provider key in VS Code Secret Storage.
- **Formal Spec: Show Backend Log** (`formalspecgen.showBackendLog`) — opens the managed process output channel.
- **Formal Spec: Install Prusti Toolchain** (`formalspecgen.installPrusti`) — installs the verified Prusti archive and pinned nightly on demand.
- **Formal Spec: Verify Rust with Prusti** (`formalspecgen.verifyRust`) — runs deductive verification for the active Rust contract.

The sidebar also supports:

- NL specification drafting.
- Backend recommendations.
- Targeted Dafny translation and verification.
- Selection and preview of the deterministic postprocessor passes.
- Clause-aware repair instructions with optional locked clauses.
- A four-stage Architecture Wizard with ADR, RAC, composition, and STRIDE controls.

Every generated transformation is shown before it changes the active editor.

### Quick Fixes

Place the cursor on a diagnostic and open the lightbulb menu (`Ctrl+.` / `Cmd+.`):

- A missing array non-null warning offers a deterministic **Add missing non-null precondition** edit.
- OpenJML verification failures offer **Ask Formal Spec to repair …**. This sends a category-specific instruction to the clause-aware refiner, opens a diff, reports validation/conflicts, and still requires explicit approval before changing the document.

Direct deterministic fixes are preferred when the intended clause is unambiguous. Solver-driven fixes never edit source immediately.

## CLI usage

Generate and validate a JML stub:

```bash
python3 -m pipeline.orchestrator \
  "A counter starts at zero, accepts non-negative increments, and never exceeds 1000."
```

Choose another provider or fallback:

```bash
python3 -m pipeline.orchestrator \
  "A bounded integer square-root operation." \
  --provider ollama \
  --fallback-provider openai \
  --max-attempts 5
```

Each run writes an auditable directory under `runs/`, including every attempted Java stub, OpenJML output, and the final `verdict.json`.

Synthesize and prove an implementation from an accepted JML scaffold without any handoff:

```bash
python3 -m pipeline.implementation path/to/Counter.java \
  --provider ollama \
  --max-attempts 5 \
  --resample-budget 1 \
  --feedback-budget 4 \
  --out runs/counter-implementation
```

The synthesizer permits Java method-body changes and proof-only annotations, but fails terminally
with `TRUST_BOUNDARY_VIOLATION` if a candidate changes fields, signatures, constructors, or trusted
JML contract clauses. A deterministic annotation pass runs only when explicitly supplied with
`--accept-pass`; accepted passes are recorded in every attempt.

## REST API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Browser interface |
| `POST` | `/generate_spec` | NL → checked JML with repair history |
| `POST` | `/validate` | Check an edited Java/JML stub |
| `POST` | `/refine` | Produce a clause-aware candidate and conflict report |
| `POST` | `/implement` | Native trusted-JML → synthesized and ESC-verified Java |
| `POST` | `/handoff` | Optional legacy external DD compatibility path |

Example:

```bash
curl -X POST http://127.0.0.1:8000/validate \
  -H 'Content-Type: application/json' \
  -d '{"java_stub":"public class Tiny {}"}'
```

## WebSocket protocol

Connect to `ws://127.0.0.1:8000/ws/verify` and send JSON messages. A connection may process multiple requests sequentially.

### Actions

| Action | Important fields | Result events |
| --- | --- | --- |
| `draft_spec` | `nl_text`, `provider`, optional `fallback_provider` | `progress`, `spec_draft`, `vc_failure`, `attempt_complete`, `verified`/`complete` |
| `verify` | `code`, `mode`: `check`, `esc`, or `auto` | `progress`, `vc_failure`, `backend_route`, `verified`/`complete`/`dafny_result` |
| `postprocess_preview` | `code`, optional `passes` | `postprocess_result` |
| `route_backend` | `code` | `backend_route` |
| `translate_dafny` | `code` | `progress`, `dafny_result` |
| `refine` | `code`, `instruction`, optional `locked_clauses` | `progress`, `refine_result` |
| `capabilities` | none | `capabilities` |
| `lint` | `code` | `lint_result` |
| `suggest_invariant` | `code`, `loop_line`, `provider` | `invariant_suggestion` |
| `rac_evidence` | `code`, `diagnostics`, `provider` | `progress`, `rac_result` |
| `discover_passes` | `code` | `pass_suggestions` |
| `translate_tla` | `code`, saved clarifications, optional `abstraction` | `progress`, `tla_result` |
| `explain_vc` | `category`, `detail`, `source_line`, `provider` | `llm_vc_explanation` |
| `architecture_design` | `requirement`, `provider`, optional `max_attempts` | `progress`, `architecture_result` |
| `architecture_lint` | optional `architecture`, `source_files` | `architecture_lint_result` |
| `architecture_scaffold` | optional `architecture` | `architecture_scaffold_result` |
| `composition_check` | optional `architecture` | `composition_result` |
| `architecture_adr` | optional `architecture`, `verification`, `number` | `architecture_adr_result` |
| `architecture_rac` | scaffold `files`, `provider` | `progress`, `architecture_rac_result` |
| `refactor_impact` | `architecture`, `before_files`, `after_files` | `refactor_impact_result` |

Automatic routing example:

```json
{
  "action": "verify",
  "mode": "auto",
  "code": "public class Reverse { ... }"
}
```

All verification failures contain structured file, line, category, method, declaration, and message fields when OpenJML supplies them.

## Human-in-the-loop safety

- Generated specifications include assumptions and ambiguity questions.
- LLM output without a parseable public class is never treated as verified.
- ESC output that reports a dropped unsupported obligation is classified as `VACUOUS_VERIFIED`, not a proof.
- Repair attempts are bounded and stall-detected.
- Protected clauses are conflict-checked before refinement is applied.
- Postprocessor and refinement candidates require explicit acceptance.
- Dafny lowering accepts only reviewed signatures and rejects unknown shapes.
- `verdict.json` and tool logs preserve the evidence behind every final status.
- RAC results are labeled runtime samples; absence of a failing test is never reported as proof.
- TLA+ results are labeled bounded design abstractions rather than source-equivalence proofs.
- TLA+ source and TLC configuration are rendered deterministically from a typed, whitelisted IR;
  unsupported domains fail closed instead of falling back to direct LLM source generation.
- The banking TLA+ route semantically extracts reviewed guards, effects, frames, Boolean failure
  behavior, and concurrency metadata from validated JML plus saved clarification answers. Atomic
  operation and ordered-lock protocol abstractions are separate renderer modes.
- JML expressions pass through a precedence-aware tokenizer/parser, discriminated Pydantic AST,
  and generic method-transition IR. The TLA+ expression visitor rejects unknown identifiers,
  calls, quantifiers, nonlinear arithmetic, and result expressions that were not lowered into
  explicit success/failure transitions.
- Domain selection uses a fail-closed plugin registry. The second built-in plugin supports bounded
  inventory contracts with `addStock`, `reserve`, and `release`, enforcing exact AST effects,
  frames, capacity guards, failure preservation, and `reserved <= stock`.

### Scaffolding another TLA+ domain

Describe bounded state, operations, semantic IDs, reviewed AST patterns, frames, and invariant
names in YAML or JSON, then run:

```bash
python3 -m pipeline.scaffold_domain domains/vending.yaml
```

Alternatively, run **Formal Spec: Generate Domain Plugin Scaffold** from the VS Code command
palette. The IDE asks an LLM for domain-specific clarification questions, collects authoritative
human answers, requests schema-shaped JSON, validates it with `DomainSpec`, and serializes YAML
deterministically. It opens that YAML for review before a modal acceptance can write anything.
After acceptance it writes the YAML, strict IR, fail-closed adapter and renderer skeletons, tests,
and static registry entry into the current workspace. It refuses to overwrite existing artifacts.
The model never emits YAML directly and cannot make its proposed `ast_pattern` executable.

The accepted domain artifact is also handed directly to the Architecture Wizard. The IDE focuses
that view and pre-populates bounded state and invariants, operations with semantic guard/effect IDs,
and frames with expected JML patterns. This seed is kept in VS Code workspace state and restored
after an EDH/window reload. The view reports `SCAFFOLD_REVIEW_REQUIRED` until the generated AST
adapter and deterministic renderer have been reviewed and the bundled backend rebuilt/restarted;
only then can static domain routing and TLC evidence honestly activate for the new plugin.

This generates the strict IR, recognizer/extractor skeleton, renderer skeleton, tests, and a static
registry entry. Existing files are never overwritten unless `--force` is explicit. Newly generated
plugins deliberately return `UNSUPPORTED_BOUNDARY` until their AST matcher and complete-variable
TLA+ renderer TODOs receive human review; declarative `ast_pattern` values are documentation and are
never executed or copied into TLA+ source.

The built-in `train_crossing` plugin demonstrates a safety-critical state-machine domain. Its
reviewed model includes an explicit car-exit action, requires the crossing to be clear before the
gate lowers, separates train departure from gate raising, and checks
`~(trainPos = 2 /\ carPos = 1)` with TLC.

#### Domain plugin lifecycle

Adding a domain is a reviewed compiler-extension workflow, not prompt configuration:

1. Declare bounded state, operation names, semantic guard/effect IDs, frames, expected AST shapes,
   and TLC invariant names in YAML or JSON.
2. Run the scaffolder. It validates identifiers and bounds, refuses undeclared frames and duplicate
   names, generates four compilable files, and updates the deterministic registry.
3. Implement the AST adapter by structurally matching `MethodTransitionIR` nodes. Never compare or
   execute the declarative `ast_pattern` string.
4. Implement a deterministic renderer in which every action assigns or declares `UNCHANGED` for
   every state variable. Keep the `.tla` module and `.cfg` serialization separate.
5. Add positive, negative, consistency, SANY, TLC, and ambiguous-recognition tests. The plugin stays
   fail-closed until both TODOs are reviewed.

Generated files are:

```text
pipeline/domains/<domain>.py
pipeline/domains/<domain>_extract.py
pipeline/domains/<domain>_render.py
tests/test_<domain>_domain.py
```

Use `--force` only when intentionally replacing all generated files. A safer normal iteration is to
retain reviewed files and update them explicitly. Runtime directory scanning is intentionally not
used: static registration makes supported code reviewable, reproducible, and visible to PyInstaller.

## IDE acceptance testing

The **Guided Workflow** view is the normal product path. It persists a three-phase state machine:

1. **System Blueprint** selects a reviewed domain (or launches fail-closed domain generation),
   elicits missing requirements, and drafts the JML scaffold.
2. **Contract & Architecture** unlocks only after OpenJML `-check` returns `VERIFIED`. Its Verify
   button unlocks implementation only when TLC returns both `VERIFIED` and the explicit
   `BOUNDED_ARCHITECTURE_EVIDENCE` claim for the selected domain. A domain mismatch stays locked.
3. **Implementation & Proof** runs the repository-local synthesis loop, opens a scaffold/code diff,
   maps returned VCs to editor diagnostics, and displays its proof-bearing `verdict.json`. No sibling
   checkout or DD subprocess is used. RAC results and bounded TLC evidence are never displayed as
   source proof.

Specialist Spec Chat and Architecture Wizard views remain available for detailed repair, IR/TLA+
inspection, ADRs, RAC evidence, and refactoring analysis.

After rebuilding the native backend and launching an Extension Development Host:

1. Enter and clarify a requirement, generate Java/JML, and require a clean OpenJML check.
2. Confirm the generated public fields and method names match one complete reviewed domain API.
3. Click **Translate + check TLA+** in Interactive Repair.
4. Confirm the result includes the selected plugin, for example
   `TLC VERIFIED [train_crossing]`, and inspect the generated module and separate configuration.
5. Mutate one clause at a time and confirm the compiler fails at the expected boundary before TLC.

When TLC returns a trace, the IDE opens a counterexample panel beside the generated module. Rows are
states, columns are state variables, and changed values are highlighted. Failed OpenJML ESC runs use
the same explorer shape for ordered proof obligations. These views are diagnostic projections of
tool output: they do not edit generated TLA+, treat a VC as a concrete runtime counterexample, or
upgrade bounded evidence into source proof.

Expected negative tests:

| Mutation | Required result |
| --- | --- |
| Remove a required safety/capacity guard | `CONSISTENCY_FAILED` |
| Change an effect to an unreviewed AST shape | `UNSUPPORTED_BOUNDARY` |
| Expand `assignable` beyond the reviewed frame | `CONSISTENCY_FAILED` |
| Rename/remove one required operation | `UNSUPPORTED_BOUNDARY` |
| Combine two complete recognized APIs | `AMBIGUOUS_DOMAIN` |
| Add a call, quantifier, unknown identifier, or nonlinear expression | `UNSUPPORTED_BOUNDARY` |

For `train_crossing`, the key mutation is removing `requires car_pos == 0` from `lowerGate`; the
adapter must report the missing crossing-clear guard without invoking TLC. Changing
`ensures gate_state == 1` to `gate_state == 0` must be rejected as an unknown lowering. Expanding
its frame to `gate_state, train_pos` must produce a frame inconsistency.

Run the complete local regression suite with:

```bash
python3 -m unittest discover -s tests -v
```

For the enforced branch-coverage run, install development dependencies and invoke pytest:

```bash
python3 -m pip install -r requirements-dev.txt
pytest
```

Coverage is measured across `pipeline`, `formalspec_core`, and `server`. The CI floor is currently
99%; the 337-test unit/integration suite measures 99.04% with branch coverage enabled. The provider
and protocol
boundaries have focused regression protection: `pipeline/llm.py` is above 97%, while the
FastAPI/WebSocket server and OpenJML/Prusti diagnostic parsers are at 100%. Architecture linting is
above 99%; semantic JML-to-transition extraction is above 98%, while system-design orchestration
and the shared deterministic postprocessor are above 97%. Lifecycle provenance, bounded TLA IR,
repair-loop strategy decisions, the generic transition IR, RAC evidence collection, the drafting
orchestrator, JML validation gateway, OpenJML verifier wrapper, CI/PR annotation layer,
Rust/Prusti pipeline, and train-crossing domain model are at 100%. Targeted Dafny lowering and
implementation handoff are approximately 98%,
while the TLA+/TLC backend is above 99%. These tests cover
provider routing, empty-content retries,
HTTP and network failure normalization, Windows and Unix diagnostic paths, WebSocket actions,
architecture linting, implementation handoff, and dependency-driven reverification.

Treat the project floor as a ratcheting minimum, not a target. Pull requests run the same command and
upload `coverage.xml`. Runtime/formal-tool tests mock network and subprocess boundaries unless a test
explicitly declares itself as an external integration test. RAC tests enforce that counterexamples
are regeneration evidence and that successful samples never become proof claims. Rust tests likewise
keep erased-annotation `rustc` checks separate from Prusti verification and require human acceptance
for proof-relevant postprocessing. Backend tests reject ambiguous Dafny shapes, malformed TLA+/CFG
artifacts, contradictory transitions, dropped obligations, and bounded-model failures without
promoting them to proof. Specification linting is approximately 88%, domain scaffolding is above
91%, and the train-crossing semantic adapter is above 97%. Domain schemas reject unsafe identifiers,
unbounded or invalid state, duplicate operations, undeclared frames, empty AST patterns, and unsafe
overwrite/registration behavior. Human-facing VC explanations and clause-aware refinement are at
100%, limitation retrieval is above 95%, and anti-stall strategy logic is approximately 94%. Tests
ensure overflow diagnostics receive sound bounded-repair advice, retrieved guardrails remain ranked
and bounded, provider failures are non-destructive, locked clauses remain terminal trust boundaries,
and repeated diagnostics/candidate hashes stop repair. Domain generation and inventory schemas are
at 100%, the inventory semantic adapter is approximately 98%, and the server protocol is
approximately 93%. Tests keep incomplete APIs, unsupported abstractions, missing guards,
frame-changing failures, invalid operation ordering/bounds, unanswered domain questions, and
unsupported backend routing from reaching a verified state. The event runner and server utilities
are approximately 97%, the scaffolder is approximately 99%, and the banking/transition typed IR
layers are at 97% and 95%. Tests cover deterministic callback draining, API failure normalization,
YAML dependency/CLI behavior, lock-protocol rendering, IR mapping consistency, duplicate frames,
unsafe identifiers, and cross-language TLA contamination. Specification linting is above 99%, the
typed JML parser is approximately 99%, both generated-domain renderers are at 100%, and the
orchestrator is approximately 98%. Parser tests cover precedence, implication associativity, old and
receiver values, long literals, unary expressions, and precise rejection of empty, truncated,
unknown, and malformed expressions. Requirement elicitation is at 100%, the banking semantic
extractor is above 91%, and TLA backend handling is approximately 97%. Tests cover malformed
question containers, duplicate identifiers/text, category and length normalization, ignored unknown
answers, unsupported Java/JML clauses and frames, unsafe lock consistency, conservative CFG
preservation, missing module names, and deadlock-flag command construction. The next priorities are
remaining deterministic postprocessor branches, targeted Dafny recursive-expression tails, and the
few architecture/strategy edge branches still below the project baseline.

### End-to-end validation

E2E tests live in `tests_e2e/` and use a separate pytest configuration so real tool/network behavior
does not distort the unit coverage metric. The suite has three explicit evidence lanes:

| Lane | What is real | Default behavior |
| --- | --- | --- |
| `toolchain` | Filesystem artifacts, `javac`, OpenJML ESC, Dafny, TLC, Frama-C WP, Z3 | Runs locally when each tool exists; unavailable tools skip only their own tests |
| `protocol` | Uvicorn process, TCP/WebSocket transport, server event loop, OpenJML process | Runs locally; requires loopback binding |
| `live_llm` | Ollama HTTP generation plus drafting, implementation synthesis, and OpenJML | Opt-in with `--live-llm` or `RUN_LIVE_LLM_E2E=1` |

The deterministic source-fixture lane does not mock formal-tool subprocesses. It currently verifies:

- OpenJML ESC and native implementation `verdict.json` generation, including hashes and no handoff;
- the identity-preserving linked-reachability Dafny boundary using the real verifier;
- the banking IR/rendering path through real TLC with `BOUNDED_ARCHITECTURE_EVIDENCE` and
  `source_refinement_proved: false`;
- Frama-C WP with all generated goals proved and explicit RTE caveats;
- terminal trusted-contract mutation and unsupported Dafny shapes;
- the real WebSocket `verify` event sequence against a separate backend process.

Create the isolated E2E environment and run every non-LLM test with:

```bash
python3 -m venv .venv-e2e
.venv-e2e/bin/python -m pip install -r requirements-e2e.txt
.venv-e2e/bin/pytest -c tests_e2e/pytest.ini -m "not live_llm" tests_e2e
```

TLC and the protocol test open local coordination/listener ports. Run them outside containers or
sandboxes that prohibit loopback binding. The current real-tool result is **7 passed**.

To exercise a running Ollama service and its configured model:

```bash
RUN_LIVE_LLM_E2E=1 scripts/run_e2e.sh
```

The live test asserts pipeline states, proof claims, hashes, and the final verdict—not exact model
text. It remains intentionally opt-in because model availability, latency, and output are external
variables. The latest WSL run used `OLLAMA_BASE_URL=http://127.0.0.1:11434/v1` with
`qwen3-coder:30b` and passed **1/1** in 49.61 seconds, including real implementation synthesis and
OpenJML verification. This result is environment evidence, not a promise that every future model
generation will take the same path or produce identical source.

The VS Code extension uses the official `@vscode/test-electron` runner:

```bash
cd vscode-extension
npm ci
npm run test:e2e
```

This downloads an isolated VS Code build and validates activation, product command registration,
language-server diagnostics, exact diagnostic lines, hover content, and Quick Fix discovery. The
latest run used VS Code 1.132.0 and passed **2/2** tests. `.github/workflows/e2e.yml` runs this lane
weekly or manually; its real-tool job targets a self-hosted runner labeled `formalspec-tools` so CI
cannot silently substitute mocked verifiers.

The essential acceptance condition is not only that safe models verify, but that unsafe,
unsupported, incomplete, and ambiguous inputs cannot reach a `VERIFIED` state.

## Architecture wizard

The **Architecture Wizard** view separates macro design from method implementation:

1. Describe domain entities, state, actors, and safety invariants.
2. Describe use cases, ordering, concurrency, and external systems.
3. Record contract decisions, failure behavior, frames, and finite bounds.
4. Draft and verify a bounded TLA+ model, review the layered dependency graph, then generate Java/JML interfaces and composition orchestrators.

The architecture artifact is structured JSON rather than diagram-only output. Components declare
layers, abstractions, responsibilities, operations, JML-compatible contracts, trust zones, and
privilege. Use cases declare ordered component calls. Data flows declare classification,
authentication, authorization, encryption, auditing, bounds, and a verified sanitizer operation.

The architecture linter checks dependency direction, concrete outward dependencies, cycles,
oversized responsibilities/interfaces, runtime type switches, missing operations, and exact
precondition/postcondition flow across use-case steps. Dependency-inversion violations are rendered
as red graph edges. Generated interfaces and orchestrators are checked together with OpenJML before
they are opened in the editor.

The wizard can also generate a Markdown ADR from the actual artifact and verification evidence,
run RAC-instrumented integration tests with generated in-memory interface fakes, and trace saved
contract changes through reverse dependencies to affected use cases and orchestrators. Safe
refactoring is controlled by `formalspecgen.safeRefactoring` and is enabled by default.

Explicit `data_flows` add STRIDE checks to the same graph. The linter flags unauthenticated trust
crossings, missing verified sanitizers, absent audit evidence, unencrypted confidential data,
unbounded external inputs, and unauthorized flows into privileged components. Security-violating
flows are rendered as dashed red edges.

### Continuous safe refactoring

When a generated interface or orchestrator is saved and its JML clauses changed, the extension:

1. Computes a normalized clause-level diff.
2. Traces reverse dependencies from the changed component.
3. Identifies affected use cases and generated orchestrators.
4. Re-runs OpenJML checking across the complete source set.
5. Re-runs ESC composition verification and reports `REVERIFIED` or `REVERIFICATION_FAILED`.

Ordinary Java edits that do not change JML contracts do not trigger this workflow.

### Architecture Decision Records

The generated ADR uses the architecture artifact rather than free-form model prose. It records the
chosen layers and abstractions, role-specific interfaces, invariants, STRIDE mitigations, TLC status,
linter findings, assumptions, consequences, and unresolved blocking findings. An ADR is `Accepted`
only when no blocking architecture findings remain and the supplied architecture verification status
is `VERIFIED`; otherwise it remains `Proposed`.

## CI and structured handoff

The included [formal specification workflow](.github/workflows/formalspec.yml) checks changed
`.java` and `.jml` files and emits native GitHub Checks annotations at diagnostic lines. It also
uploads `formalspec-report.json` for downstream tooling. The runner must provide the configured
OpenJML distribution or restore it through the extension bootstrap manifest.

`POST /handoff` is retained for compatibility and accepts optional `expected_passes` and `backend`
fields. It writes both the Java
stub and `<Class>.intent.json`, containing the full specification, selected deterministic passes,
and backend. The intent path is also exported to the child implementation pipeline as
`FORMALSPEC_INTENT_PATH`.

## Development checks

Compile the Python service:

```bash
python3 -m py_compile server.py pipeline/*.py pipeline/domains/*.py
python3 -m unittest discover -s tests -v
```

Compile the extension and language server:

```bash
cd vscode-extension
npm run compile
```

Verify the installed Dafny runtime:

```bash
DOTNET_ROOT="$HOME/.dotnet" "$HOME/.dotnet/tools/dafny" --version
```

Verify the repository-local Frama-C installation and detected provers:

```bash
tools/frama-c-33.0/bin/frama-c -version
tools/frama-c-33.0/bin/frama-c -wp-list-provers
```

Run the changed-file CI checker locally:

```bash
python3 -m pipeline.ci --base HEAD^ --mode check
```

## Current scope

The boundary translator intentionally covers only the four reviewed patterns above.
Architecture verification checks a bounded TLA+ abstraction, and exact source/model refinement is
not automatically proved. TLA+ generation currently supports only the reviewed `bank_account`,
`inventory`, and `train_crossing` semantic plugins; the parser's ability to represent an expression
does not imply that a domain adapter or renderer exists for it. Scaffolding creates fail-closed
boilerplate, not an automatically trusted domain implementation. Complete JML semantics, arbitrary
object graphs, unrestricted aliasing, calls, general quantifiers, nonlinear arithmetic, recursive
predicates, unbounded collections, arbitrary Java method bodies, and automatic source/model
refinement remain outside the TLA+ compiler subset.

SOLID and STRIDE checks operate on explicit architecture metadata and targeted source smells rather
than a whole-program Java semantic graph. RAC uses generated tests and cannot establish coverage or
proof. General Java-to-Dafny compilation, enterprise secret rotation/provisioning, and comprehensive
retrieval over the full JML reference corpus remain outside the current scope. Rust compilation is
not Rust contract verification. Prusti and supported-platform Kani are bootstrapped, but Creusot
installation and arbitrary
verified Rust implementation synthesis, unsafe-code proofs, and source-level refinement from
TLA+/Dafny to Rust remain out of scope.

The C/ACSL lane currently supports single-file C11 verification under Frama-C WP's typed memory
model. Dynamic allocation, concurrency, volatile state, inline assembly, unsafe library calls,
cross-translation-unit proof, managed Frama-C bootstrap outside Linux x64, and proof claims for skipped
RTE guard categories remain outside the reviewed subset.

Native Java implementation synthesis is intentionally contract-driven rather than general project
generation: it fills one validated JML class at a time, preserves the trusted surface, applies only
human-accepted proof-annotation passes, and claims proof only after a non-vacuous OpenJML ESC result.

## License

Copyright 2026 Sheel Morjaria. Licensed under the Apache License, Version 2.0. See
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
