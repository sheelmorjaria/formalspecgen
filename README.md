# FormalSpecGen CLI

FormalSpecGen is a terminal-first, human-in-the-loop tool for turning natural-language requirements
into reviewed formal contracts, bounded architecture evidence, and deductively verified code.

The design thesis — the LLM proposes, deterministic compilers transform, formal tools judge, and
humans control trusted assumptions — is written up with the full six-port production evidence in
[`docs/THE_ENCODING_ARTIFACT.md`](docs/THE_ENCODING_ARTIFACT.md).

### Optional MCP server

FormalSpecGen exposes an optional Model Context Protocol façade for structured agent access:

```bash
pip install 'formalspecgen[mcp]'
python mcp_server.py
```

The server exposes 21 tools covering the full verification surface: `verify_code`,
`validate_architecture`, `implement_code`, `inspect_code`, `analyze_codebase`,
`document_code`, `assess_security`, `security_inspect`, `security_exploit`,
`remediate_code`, `correct_behavior`, `apply_refactor`, `verify_refactor`,
`verify_bisimulation`, `optimize_algorithm`, `discover_algorithms`,
`validate_domain`, `compose`, `reverify_composition`, `unified_system`, and
`draft_canonical_contract`. Inputs **and** outputs are restricted to the current
workspace, and responses are structured verdict objects; the server never converts a
tool failure into a success claim. LLM-backed tools (`remediate_code`,
`correct_behavior`, `optimize_algorithm`, `discover_algorithms`, and the optional
`document_code` narrative) fail closed when the provider is unreachable.

Deliberately not exposed: `promote-domain` — hash-bound acceptance of a reviewed
artifact is a human trust action that stays with the CLI — and the interactive
clarification wizards (`domain`, non-canonical `draft`, `design-system`).
Configure an MCP client with the server command and its absolute project path, for
example:

```json
{"mcpServers":{"formalspecgen":{"command":"python","args":["/path/to/formalspecgen/mcp_server.py"]}}}
```

### Verified algorithm optimization

For a verified Java/JML baseline, `optimize-algorithm` can ask a provider for a constrained
algorithm rewrite, preserve the trusted surface, and re-run ESC plus the refactor gate:

```bash
formalspecgen optimize-algorithm TwoSum.java --strategy hashmap \
  --out optimized/TwoSum.java --provider ollama --json optimization.json
```

The strongest claim is `ALGORITHM_OPTIMIZATION_VERIFIED`. It means the baseline and candidate
passed their configured proof gates and the shared contract surface was preserved; it does not
prove runtime bisimulation or asymptotic complexity. `nested_loop` is rejected as a possible
complexity regression.

### Algorithm discovery

`discover-algorithms` fans a Java/JML specification out across independent strategy prompts and
keeps only candidates that pass OpenJML ESC and the contract-preserving refactor gate. Candidates
are isolated in strategy-named directories so public Java class filenames remain valid:

```bash
formalspecgen discover-algorithms TwoSumSpec.java \
  --strategies all --provider ollama --max-workers 1 \
  --out-dir discovered --json discovered/discovery-verdict.json
```

The registry includes `brute_force`, `two_pointer`, `hashmap`, `sliding_window`,
`binary_search`, `prefix_sum`, `bit_manipulation`, and `dynamic_programming`. Use
`--strategies name1,name2` to select a subset. `--max-workers 1` is recommended for local Ollama
servers to avoid concurrent GPU/model contention. A successful run emits
`ALGORITHM_DISCOVERY_COMPLETE`; no candidate is admitted when generation, syntax, ESC, or the
trusted contract surface fails. Complexity labels are heuristics only; the discovery claim does
not prove asymptotic complexity or behavioral bisimulation.

### Security assessment

`assess-security` combines OpenJML evidence with an optional Semgrep Java SAST pass and writes a
machine-readable verdict:

```bash
formalspecgen assess-security src/Counter.java --json security-verdict.json
```

Recognized formal verification conditions are mapped to CWE evidence (for example,
`ArithmeticOperationRange` → CWE-190, index failures → CWE-125, and null dereferences → CWE-476).
Semgrep findings with `HIGH`, `ERROR`, or `CRITICAL` severity fail closed as `SECURITY_VIOLATION`.
If Semgrep is unavailable or skipped, the report cannot claim full security:

```bash
formalspecgen assess-security src/Counter.java --no-sast
# status: FORMALLY_VERIFIED_SAST_SKIPPED
```

`VERIFIED_SECURE` requires successful formal verification, no mapped formal findings, and a
successful clean Semgrep run. This is scoped evidence—not immunity from all CWEs, cryptographic
assurance, taint-flow proof, external-I/O safety, or regulatory certification.

The bundled [`security/java_custom.yml`](security/java_custom.yml) rules supplement Semgrep's
Java rules with CWE-22 path traversal, CWE-502 unsafe deserialization, CWE-327 weak cryptography,
CWE-209 exception-detail exposure, CWE-798 hard-coded credentials, and CWE-330 insecure
randomness; [`security/c_custom.yml`](security/c_custom.yml) adds CWE-415 double-free checking
for C/C++. Formal evidence additionally recognizes CWE-131 invalid
array sizes, CWE-190/CWE-191 overflow and underflow, and CWE-835 termination failures.

#### The CWE manifest

The entire security vocabulary is configuration-driven through
[`security/cwe_manifest.json`](security/cwe_manifest.json): one JSON block per CWE carries the
formal VC labels (`PossiblyNegativeIndex` → CWE-125), native-verifier diagnostic triggers
(OpenJML/Prusti/Frama-C/ESBMC), the Semgrep rule ids, the remediation prompt, and the
`correct-behavior` strengthening guidance. `pipeline/cwe_registry.py` loads the manifest once,
validates it strictly (duplicates, malformed ids, unknown languages, or invalid detection
methods raise `ManifestError` — the lane fails closed rather than silently losing rules), and
exposes the lookups every consumer uses. **Adding a CWE is one JSON block** — optionally
paired with a Semgrep rule and a PoC template — with zero orchestrator changes; the registry
tests pin that extension path. Semgrep rule ids that no manifest entry declares are surfaced
with `unmapped_rule_id: true` instead of silently mapping to no CWE, and SAST config selection
is language-scoped (`java_custom.yml` for Java, `c_custom.yml` for C/C++, other languages skip
SAST).

The pattern-detector catalog is likewise registry-driven
(`pipeline/pattern_registry.py`): each plugin declares a name, a GoF category
(Creational/Structural/Behavioral/Concurrency), its detector, and the optional
`apply-refactor` action profile it feeds. Proxy, Command, and Producer-Consumer are
inspection-only recommendations — detection never implies an admissible transformation.

For vulnerability triage, `security-inspect` writes a report combining Semgrep findings and
recognized OpenJML counterexample labels:

```bash
formalspecgen security-inspect src/Service.java --json vulnerability-report.json
```

`security-exploit` can turn supported findings (currently bounds violations and SQL-pattern
findings, plus path traversal, deserialization, weak crypto, null, and overflow findings) into
local JUnit PoC source templates:

```bash
formalspecgen security-exploit vulnerability-report.json src/Service.java \
  --out-dir security-pocs --json security-pocs/poc-verdict.json
```

PoCs are generated but never compiled, executed, or sent over a network automatically. The
result is `POC_GENERATED_NOT_EXECUTED`, not `EXPLOIT_PROVEN`; execution and remediation remain
explicit human-controlled steps. Unsupported findings produce `NO_SUPPORTED_POC` rather than
inventing an exploit.

The remediation loop generates a patched copy from a vulnerability report and proves that copy
with OpenJML without overwriting the original source:

```bash
formalspecgen remediate src/Service.java vulnerability-report.json \
  --provider ollama --out-dir remediated \
  --json remediated/remediation-verdict.json
```

`REMEDIATION_VERIFIED` means only that the generated copy passed ESC for the reported findings'
contract context. The original code is preserved, PoCs remain unexecuted, and external I/O,
runtime exploit neutralization, and behavioral equivalence are not claimed automatically.

Security inspection routes native source lanes by extension: Java uses OpenJML, Rust uses Prusti,
C/ACSL uses Frama-C, and C++ uses ESBMC when available. Native diagnostics are normalized to the
language-independent CWE vocabulary. PoCs are language-aware (`.java` JUnit, `.rs` Rust tests,
and C/C++ assertion harness templates), while remediation prompts select JML, Prusti, or ACSL
contract syntax from the target extension.

The complete defensive lifecycle is:

```text
security-inspect → security-exploit → remediate → OpenJML/Prusti/Frama-C/ESBMC re-check
      report          local PoC             patched copy          scoped proof
```

`security-inspect` produces findings, `security-exploit` produces review-only PoC source,
and `remediate` writes a separate patched artifact. Only a successful native verifier run can
mint `REMEDIATION_VERIFIED`; PoCs are never run automatically.

### Spec-driven behavior correction

Where `remediate` patches the implementation against a vulnerability report, `correct-behavior`
strengthens the *contract* first and then proves a defensive implementation of it:

```bash
formalspecgen correct-behavior src/UnsafeArray.java --cwe CWE-125 \
  --out-dir corrections --json corrections/correction_verdict.json
```

The loop is two-stage: a provider proposes a CWE-specific strengthened JML contract (CWE-125
asks for conditional postconditions plus the runtime bounds guard; CWE-476 asks for explicit
null handling), the strengthened source is written beside the original, and up to
`--max-attempts` OpenJML ESC runs — with diagnostic feedback fed back to the provider between
attempts — must discharge it. Only a successful ESC run mints `BEHAVIOR_CORRECTION_VERIFIED`
with `formal_proof: DEDUCTIVE_PROOF`; otherwise the verdict fails closed as
`CORRECTION_FAILED`/`NO_PROOF`. Evidence hash-binds the baseline and strengthened contract
clause sets, the corrected implementation, and the attempt count.

#### Capacity bounding (CWE-400): dynamic code → static, bounded code

`--strategy` rewrites unbounded code into static, bounded code — the transformation
embedded, aerospace (DO-178C-style), and hardening audiences want, and the reason it lives
under `correct-behavior` rather than `verify-refactor` is epistemic: rejecting work beyond
a capacity *changes observable behavior*, so it can never be certified as a
contract-preserving refactor. Three strategies are supported:

- `--strategy bound-loop` — `while (true)` becomes counter-bounded iteration
  (`while (i < n && i < 1000)` with `loop_invariant`/`decreases`)
- `--strategy static-pool` — dynamic `LinkedList`/`ArrayList` nodes become a pre-allocated
  fixed-size array or object pool with integer indices (`next_index`, `head`, `free_list`)
- `--strategy bounded-cache` — unbounded `HashMap`s become parallel fixed-size arrays with
  a count field and `requires count < 100` on mutation
- `--strategy bounded-pool` — dynamic collections become a bounded object pool
  (`BoundedPool<T>(capacity)` with `acquire`/`release`): the Linux-kernel/HFT middle
  ground. Objects are allocated on demand — only the **bound** is fixed — and the
  rejection at capacity is part of the *proof*: either `acquire` returns `false` (the
  reject-when-full postcondition `\result == (\old(count) < capacity)` is what Z3
  proves) **or** a dedicated `CapacityReachedException` is thrown under the capacity
  guard with the boundary pinned by `signals (CapacityReachedException e)
  \old(acquired) == capacity` — Z3 proves the exception fires exactly at the boundary
  and the count advances otherwise (the exception's constructor needs an explicit
  `assignable \nothing` frame for the caller's frame condition to verify). The
  pre-prover check fails closed if the rewrite keeps a dynamic collection, still calls
  the collection API (`.add`/`.remove` must map to `acquire`/`release`), constructs
  `new BoundedPool()` with no capacity, never argues an explicit capacity bound, or
  throws the capacity exception **unguarded** (not under a capacity comparison).

What the caller does at the boundary is a deployment decision the correction
deliberately leaves to the human — the proven fact is only *that* work beyond capacity
is rejected, never silently absorbed:

| Deployment | Boundary handling |
| --- | --- |
| Cloud/enterprise | **Backpressure** — catch at the API boundary, return 503/429, emit `pool_full_total` so an autoscaler reacts |
| Embedded/RTOS (DO-178C / ISO 26262) | **Fail-safe mode** — propagate to the safety supervisor, which halts the task and transitions to a safe deterministic state |
| Stream processing | **Spill** — write the rejected item to a disk-backed queue for later processing |

#### Hardening strategies (the wider correction vocabulary)

Beyond capacity, `correct-behavior` speaks five weakness-specific strategies. Each is a
contract *strengthening* plus a deterministic pre-prover residual check — the residual
is a necessary condition only, Z3 still judges the strengthened contract:

- `--strategy checked-math` (CWE-190) — unguarded `int` arithmetic becomes
  overflow-checked: `Math.addExact`/`multiplyExact` or an explicit
  `Integer.MAX_VALUE`/`MIN_VALUE` pre-test, with `requires`/`ensures` ranges that
  forbid wrapping. A rewrite that never argues an overflow bound fails closed
  `strategy_not_satisfied`.
- `--strategy lock-timeout` (CWE-667) — `synchronized` and bare `lock()` become
  `tryLock(timeout, TimeUnit)` returning an explicit failure value on timeout, with
  `finally { unlock(); }`. Surviving `synchronized`, bare `.lock()`, a missing
  `tryLock`, or a missing `finally`-release never reach the prover.
- `--strategy canonicalize` (CWE-79) — untrusted values are encoded
  (`Encode.forHtml` or an equivalent escape helper) before reaching markup or an
  output sink; a rewrite with no encoding call fails closed.
- `--strategy fail-safe` (CWE-617) — every reachable `assert` is replaced by explicit
  validation returning a failure value or throwing a checked exception; any surviving
  `assert` statement fails closed before verification.
- `--strategy immutable-snapshot` (CWE-362) — shared mutable state stops being
  shared: private final fields published through `List.copyOf`/`Arrays.copyOf`/
  `Collections.unmodifiable*` snapshots. A rewrite with no snapshot idiom, or a
  surviving public non-final array/collection field, fails closed.

Real-OpenJML evidence for the new set lives in
`tests_e2e/test_hardening_strategies_e2e.py` (Z3 proves the checked-math no-wrap
contract, the fail-safe conditional postconditions, and the immutable-snapshot
length contracts).

```bash
formalspecgen correct-behavior src/BatchRunner.java --cwe CWE-400 \
  --strategy bound-loop --out-dir corrections --json corrections/bound.json
```

The strategy runs a deterministic pre-prover check: if the rewritten source still contains
`while (true)`/`for (;;)` (bound-loop) or any dynamic collection or non-array `new`
(static-pool/bounded-cache), the verdict fails closed as `strategy_not_satisfied` before
OpenJML is consulted. Pattern absence is only a necessary condition — Z3 still has to prove
the strengthened `requires/ensures` capacity bounds. A successful run mints
`BEHAVIOR_CORRECTION_VERIFIED` with `mitigated_cwe: CWE-400` and `strategy` recorded in
the evidence; real-OpenJML coverage lives in `tests_e2e/test_capacity_bounding_e2e.py`.

#### Auto-strategy routing (the shape picks the correction)

`--auto-strategy` is an explicit opt-in that replaces the human's `--strategy` choice with
a deterministic router (`pipeline/correction_router.py` — no LLM, a pure function of the
source text, the CWE, and the optional hardware profile). Routing is **CWE-scoped**:
each weakness class owns its own shape table, and a shape from one class never routes a
strategy from another — an unbounded loop under a CWE-190 request cannot be mis-routed
to `bound-loop`:

| CWE | Detected shape | Routed strategy |
| --- | --- | --- |
| CWE-400 | `while (true)` / `while(1)` / `for (;;)` | `bound-loop` |
| CWE-400 | `new HashMap` / `HashSet` / `TreeMap` / … | `bounded-cache` |
| CWE-400 | `new LinkedList` / `ArrayList` / `ArrayDeque` / … or an injected collection's `.add`/`.put`/`.offer`/`.push` API | `bounded-pool` (collapses to `static-pool` when the profile-derived capacity is under 16 — the on-demand-allocation advantage is noise that small) |
| CWE-190 | `int` arithmetic (`*`, `+=`, `*=`) | `checked-math` |
| CWE-667 | `synchronized` or a bare `.lock()` | `lock-timeout` |
| CWE-79 | markup built by concatenation, or an output-sink call with `+` inside | `canonicalize` |
| CWE-617 | a line-leading `assert` | `fail-safe` |
| CWE-362 | a public/protected/static non-final array or collection field | `immutable-snapshot` |
| any | none of the above (or an unrecognized CWE) | `no_routable_strategy` — fails closed to manual review |

Routing only picks the strategy; it never weakens the downstream gates — the routed run
passes through the same strategy residuals, hardware residuals, and ESC as an explicit
`--strategy`, and the verdict records `strategy_routed: true` so reviewers can
distinguish a router-chosen strategy from a human one.

#### Hardware-aware bounding (physical SRAM limits drive the number)

A bound of 1000 pulled from thin air is a heuristic. On DO-178C / ISO 26262 class
targets every statically allocated pool must be derived from the physical memory and
provably fit. Pass a hardware profile and the pipeline — not the LLM — computes the
capacity from the silicon:

```json
{"target": "STM32F411", "total_sram_bytes": 131072,
 "reserved_system_bytes": 32768, "max_stack_depth_bytes": 4096, "word_size_bytes": 4}
```

```bash
formalspecgen correct-behavior src/OrderQueue.java --cwe CWE-400 \
  --strategy static-pool --hardware hardware_profile.json --struct-size-bytes 16
```

`safe_capacity` truncates `usable_sram × safety_margin(0.9) ÷ struct_size` (98304 × 0.9 ÷
16 = 5529 for the profile above), the strengthening prompt is injected with the exact
capacity, and two more deterministic checks run before the prover: every generated array
allocation must satisfy `bound × struct_size ≤ budget` (`hardware_bound_exceeded`), and a
recursive rewrite whose derived bound cannot fit the physical stack fails as
`STACK_OVERFLOW_RISK` (frame estimate = 2 × word size). A struct larger than the budget
fails before generation as `HARDWARE_MEMORY_EXCEEDED`. A verified hardware-aware run adds
`HARDWARE_MEMORY_BOUND_PROVEN` to the claims with `memory_footprint_bytes` (capacity ×
struct size) recorded — Z3 proves the software bound, the profile proves the physical
footprint, and neither is trusted alone. The struct-size estimate from scalar Java fields
is a lower bound only (references are not counted); exact sizes belong in
`--struct-size-bytes`.

#### Candidate capacity bounding (the C/Rust lane)

`correct-behavior` also accepts a **V2 candidate YAML** as the target. This is the
deterministic, LLM-free form of capacity bounding: the silicon picks the number, the
pipeline clamps the math, and every proof obligation stays with the normal gates
downstream:

```bash
formalspecgen correct-behavior domains/candidates/parser.v2.yaml --cwe CWE-400 \
  --strategy static-pool --hardware hardware_profile.json --out-dir domains/candidates
```

Int state-variable bounds are clamped to the hardware-derived capacity (`1048576 → 7372`
for an STM32F411-class profile over a 12-byte struct; `-1` sentinel lower bounds are
preserved; fields already within capacity are untouched; unbounded fields **gain** a
bound), `lo <= field <= capacity` hardware invariants are added, and a NEW
`<module>_bounded.v2.yaml` is written beside the original — the input candidate is
never modified. The verdict records the full derivation (usable SRAM, margin, struct
size, capacity, `memory_footprint_bytes = capacity × struct_size`) and mints
`CAPACITY_BOUNDING_APPLIED` with `claim: NO_PROOF` — deliberately not a PROVEN claim,
because proof is downstream: `validate-domain <module>_bounded` (real TLC), hash-bound
`promote-domain`, then `draft --canonical-domain <module>_bounded --lang rust` +
Prusti. `bound-loop` is rejected (`strategy_not_applicable`: loop rewrites are a
source-level correction, not a math-level one), non-CWE-400 targets fail closed
(`unsupported_cwe_for_candidate`), and a missing profile is `hardware_profile_required`.
Validated end to end against the Redis RESP machine with production bounds
(multibulklen ≤ 1048576, bulklen ≤ 512 MB) bounded to a 7372-element capacity:
real TLC 7 states / 14 transitions, Prusti 10/10, `SOURCE_MODEL_REFINEMENT`.

The bounded traverser's state-space cap binds on **actual exploration**, not the
worst-case bound product: hardware capacities legitimately produce wide bounds over
sparse reachable sets (a counter set to a literal then decremented explores one axis,
not the product), so the cap fires only when reachable states genuinely exceed it.

A correction is deliberately a contract *change*, not a refactor. Output that strengthens a
contract cannot mint `REFACTOR_CONTRACT_PRESERVED`: `verify-refactor` correctly rejects it as
`primary_contract_surface_changed`, and the correction verdict is the evidence class that
covers the new surface. The provider only proposes; ESC judges.

```text
Natural language → clarification → checked language contract
                                      │
                                      ├─ JML transition IR → deterministic TLA+ → TLC
                                      └─ trusted-surface synthesis
                                           ├─ Java/JML → OpenJML ESC
                                           ├─ Rust/Prusti → Prusti
                                           ├─ C/ACSL → Frama-C WP
                                           └─ C++17 → ESBMC (bounded)

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

FormalSpecGen covers five connected workflows:

| Workflow | Entry point | Strongest scoped evidence |
| --- | --- | --- |
| Synthesis | `domain` → `validate-domain` → `promote-domain` → `draft` → `implement` | Native `DEDUCTIVE_PROOF` and supported `SOURCE_MODEL_REFINEMENT` |
| Scaling | `system`, lock-protocol V2, Rayon wrapper, async-message V2 | `SYSTEM_COMPOSITION_PROOF`, restricted `CONCURRENT_LINEARIZABILITY`, `PARALLEL_PARTITION_VERIFIED`, or capped async static evidence |
| Hexagonal integration | `compose --lang {java,rust,c,cpp}` with external Ports, adapter names, and explicit step arguments | `SYSTEM_COMPOSITION_PROOF` for core-to-Port contract use (`BOUNDED_SYSTEM_COMPOSITION_PROOF` on the cpp lane); `external_io_safety_proved: false` |
| Modernization | `inspect` → `apply-refactor` → `verify-refactor`; rust/c/cpp extract-method via `apply-refactor --method` | `REFACTOR_CONTRACT_PRESERVED` after independent baseline/refactored ESC (`BOUNDED_REFACTOR_CONTRACT_PRESERVED` for C++) |
| Comprehension | `analyze-codebase` / `document-code` | `UNREVIEWED_EXTRACTION_CANDIDATE` / `UNREVIEWED_EXTRACTION_DOCUMENTATION` — never proof |
| Verified reimplementation | `analyze-codebase` → `validate-domain` → `promote-domain` → `draft --canonical-domain --lang` → `implement` | `SOURCE_MODEL_REFINEMENT` for a Rust port of a reviewed, TLC-validated extracted state machine |

### Post-push roadmap progress

The following milestones were added after the v1.0.0 tag push. Release lineage:
v1.0.0 → v2.1.0 → v2.3.0 → v2.3.1 → v2.4.0 → v2.4.1 → v3.0.0 → v3.3.0 → v3.5.0 →
v3.6.0 → v3.7.0 → v3.8.0 → v3.9.0 → v3.10.0 → v3.11.0 (Tomcat, the first Java
production port) → v3.12.0 (the six-CWE hardening agent) → v4.0.0 (the Encoding
Artifact paper and release).

Key commits: `a31463d`, `b8d1df4`, `5169ef5`, `a708fc6`, `6884f88`, `778ddd7`, `c367d3a`,
`692b234`, `4f0b2f8`, `a18a0c7`, `e9a966e`, and `360f567`, then `90f7015`, `fcb2767`, and
`ff97364` (v2.3.0), `84175b3`, `24f552e`, `2c94f02`, `61c4f61` (v2.3.1), `99623a8`
(v2.4.0), `47dc680` (v3.3.0, lwIP), `f790111` (v3.6.0, Redis), `17d3e78` (v3.7.0,
postfix counters), `41f7c84` (v3.8.0, LevelDB/C++), `e1372be` (v3.9.0, bounded-pool),
`be6c9d1` (v3.10.0, auto-strategy router), `bd82e45` (v3.11.0, Tomcat), and `3cad3bb`
(v3.12.0, hardening strategies).

- Narrow deterministic State, Decorator, and Facade profiles now emit multifile candidates with
  explicit heap-topology and callback/state limitations. Their outputs still require the
  multifile refactor gate.
- V2 promotions and refactor verdicts support optional detached GPG signatures. Signature
  verification, authorized-key policy, composition binding checks, and unified-system domain
  loading are opt-in through `FORMALSPECGEN_REQUIRE_SIGNATURES=1` and
  `AUTHORIZED_REVIEWER_KEYS`.
- Rust/C standard assurance now mints `STATIC_CHECKED_RUNTIME_TESTED` only after a passing
  instrumented runtime sample. C proof-support includes indexed `\\valid` and `\\separated`
  passes.
- Bisimulation preflight validates state mappings, resolves target classes, hashes sources, and
  rejects public-surface drift. Concurrent composition preflight emits bounded `Actors`,
  `callResult`, and `history` state; lock correspondence checks require synchronized Java regions
  and a lock-protocol model.
- Bottom-up codebase extraction (`analyze-codebase`, commits `90f7015`, `fcb2767`, `ff97364`)
  parses Java, Rust, C, and C++ with Tree-sitter — with a deterministic regex fallback for
  minimal installations — and infers guarded scalar assignments into typed V2 transitions that
  are compiled through the strict JML expression parser and registered as unreviewed candidates
  under `domains/candidates/`. See
  [Bottom-up codebase extraction](#bottom-up-codebase-extraction).

The following roadmap claims remain intentionally incomplete:

- `BEHAVIORAL_EQUIVALENCE_PROVED`: requires a genuine relational/bisimulation proof backend.
- `CONCURRENT_COMPOSITION_LINEARIZABILITY_PROVED`: requires TLC interleaving verification plus
  discharged Java lock-acquisition/release correspondence.
- Broad semantic Strategy/State/Decorator/Facade decomposition: the narrow literal-dispatch
  Strategy, scalar State, Decorator, Facade, and Factory profiles above are admitted with their
  stated restrictions; broader decomposition is not. Responsibility grouping, callback ordering,
  and heap topology are not inferred.

Preflight artifacts and mappings never mint these claims by themselves; unsupported or missing
proof evidence fails closed.

These evidence classes are intentionally not interchangeable. In particular,
`REFACTOR_CONTRACT_PRESERVED` proves that both revisions discharge the same normalized JML/API
surface; it does not claim relational behavioral equivalence. Async Tokio generation similarly
stops at bounded architecture evidence plus static checking rather than claiming atomic refinement.
Hexagonal evidence likewise proves that core call sites establish Port preconditions while excluding
generated external adapters and remote I/O behavior from ESC.

### Verified polyglot scorecard

One reviewed V2 domain lowers deterministically into four languages and is judged by independent
solver stacks — no LLM touches the contracts:

| Lane | Prover | Live evidence |
| --- | --- | --- |
| Java/JML | OpenJML ESC + TLC | `DEDUCTIVE_PROOF` with `SOURCE_MODEL_REFINEMENT` |
| Rust/Prusti | Prusti 0.2.2 (Viper/Silicon + Z3) | Peterson: 12/12 plus 6/6 refinement; ABP: 11/11 plus 6/6 refinement |
| C/ACSL | Frama-C WP + Z3 | Peterson: 87/87 plus 6/6 refinement; ABP: 82/82 plus 6/6 refinement |
| C++17 | ESBMC 8.4 + Z3 | Token Bucket: `BOUNDED_CPP_PROOF` with an autogenerated execution harness |
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

Runtime Python dependencies are deliberately small: Pydantic, PyYAML, Prompt Toolkit, Rich,
pinned `javalang` for the modernization inspection lane, and Tree-sitter plus the Java, Rust, C,
and C++ grammars for polyglot codebase extraction. Formal backends remain external tools
configured through environment variables or repository-local `tools/` installations.

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
  --accept-pass inject_valid_pointers --accept-pass inject_separated \
  --accept-pass inject_loop_assigns
```

The Rust passes annotate only locally defined contract helpers, direct typed slice/index access,
and exact signed parameter/constant arithmetic intervals. The C overflow pass derives
`INT_MIN`/`INT_MAX` obligations for the corresponding restricted `int` arithmetic subset. Neither
pass invents a generic numeric policy such as `<= 1000`.
The C null pass handles only directly dereferenced pointer parameters with an existing ACSL
contract. `inject_valid_pointers` is the explicit name for that same conservative validity pass;
it does not guess an index range such as `\valid(arr + (0..idx))` without a reviewed bound.
`inject_separated` adds `\separated(...)` only when an existing function contract has at least two
pointer parameters; it does not infer aliasing relationships across calls. The C loop-frame pass
promotes explicit `// acsl-loop-assigns: ...` review markers; it does not infer alias-sensitive
frames. Any changed candidate remains proof-relevant and requires explicit pass acceptance.

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
strict C11 compiler gate. Implementation synthesis supports `.java`/`.jml`, `.rs`, `.c`, and
`.cpp`/`.cc`/`.cxx`; unsupported file types fail explicitly. The C++ lane mirrors the Rust/C
generate→lint→verify→repair loop with ESBMC as its native prover: repair prompts carry the
structured `file:line category` VC list parsed from ESBMC counterexamples, a verified critical
run mints the bounded ceiling `BOUNDED_CPP_PROOF` (never `DEDUCTIVE_PROOF`), and
standard/lightweight stop at `check_cpp_syntax` → `STATIC_CHECK`. The Rust and C repair prompts
now carry the same structured Prusti/Frama-C VC lists ahead of the raw output tail.

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

### Bottom-up codebase extraction

The top-down workflows start from natural language. `analyze-codebase` adds the reverse
direction — extracting unreviewed architecture and domain candidates from an existing
polyglot source tree:

```bash
formalspecgen analyze-codebase legacy/ --out-dir extracted --json extracted/verdict.json
```

Sources are parsed with Tree-sitter grammars for Java, Rust, C, and C++; a deterministic
regex fallback keeps extraction working in minimal environments without the grammar wheels.
The analyzer extracts classes, interfaces, structs, and scalar (`int`/`boolean`) fields, then
writes:

- `extracted/extracted_architecture.json` — an unreviewed component map in which interfaces
  are recorded as external components without domain bindings;
- `extracted/<domain>.v2.json` — a state-variable sketch per concrete type; and
- `domains/candidates/<module>.v2.yaml` — a registered V2 candidate for Java classes and
  C structs.

For Java and C sources, guarded scalar assignments — `if (count < LIMIT) { count += N; }`
inside a method (Java) or `if (c->state == 1) { c->state = 2; }` inside a void
function (C, over `ptr->field`/`value.field` receivers) — are inferred deterministically
into typed transitions. The Java lane speaks the dialect real parsers use
(proven on Tomcat's `Http11InputBuffer`): methods may be **package-private** and return
**any scalar** (`boolean parseRequestLine(...) throws IOException`), method bodies are
**brace-matched** (not line-matched), and a method may mint **multiple transitions**
(phase-counter chains get collision-suffixed names: `parseRequestLine`,
`parseRequestLine_2`, …). A guard whose state write is wrapped in **nested control
flow** (try/switch inside the phase arm) is refused — the TinyUSB mis-pairing trap —
but reported as an `EXTRACTION_NOTE` naming the exact guard, so the reviewer knows
which phases to complete by hand. Register-time bounds fall back to the transitions'
own constants (`[0, max integer constant]`) when no comparison/enum evidence exists,
and — soundness — a comparison-derived bound that the machine's real writes exceed is
**widened to the write maximum**: code that assigns 7 cannot be bounded at 2 because
an earlier `phase < 2` comparison suggested it. The C lane also speaks the dialect
real stacks use: **enum
constants** are resolved to their integer values (implicit and explicit counters, hex
literals), **enum-typed fields** are bounded to the enum's extent, **switch
dispatch** (`switch (pcb->state) { case SYN_SENT: ... pcb->state = ESTABLISHED; break; }`)
is segmented one transition per `break`-terminated case, **anonymous typedef structs**
(`typedef struct { ... } usbd_device_t;` — the dominant embedded shape; tagged
`typedef struct tcp_pcb {...} tcp_pcb_t;` still registers once, under the tag) are
extracted under their typedef name, and **bare or negated boolean guards**
(`if (dev->connected) { dev->suspended = 1; }` → guard `connected != 0`, effect on a
*different* field) are extracted only when the write lives inside the guard's own brace
block — a guard block containing only callbacks never pairs with a later assignment
elsewhere in the function. **Postfix counters** are extracted in four shapes:
`if (!dev->field++)` mints the pair (guard `field == 0` → +1, guard `field != 0` → +1 —
the increment is a side effect of evaluating the condition, so both branch values
increment), postfix effects inside boolean guards (`if (dev->flag) { dev->count++; }`),
comparison-guarded counters (`if (dev->count < N) { dev->count++; }`), and
`while (dev->field) { ... field--; }` loops (abstracted to an unconditional transition,
reported as an over-approximation). **C++ sources participate fully**: `.cc`/`.cpp`/`.cxx`
translation units are preprocessed with `g++ -E` and join the same C-family two-pass —
structs/classes register as candidates, enums resolve, switch dispatch and postfix
counters infer, and out-of-line method definitions (`Status Reader::ReadPhysicalRecord`)
match with their unqualified name. The guard and effect are
compiled through the strict JML expression parser into the recursive V2
expression AST; no LLM infix text is stored in the
candidate. Guards accept `==`, `!=`, `<=`, `>=`, `<`, `>`; effects are literal state
writes or bounded increments. Bounds read from `<=`/`<` comparisons produce automatic
`0..N` invariants, and fields whose bound cannot be inferred are flagged
`UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW`.

Two conservative behaviors are reported, never silently applied: fall-through cases and
unknown enum constants are skipped (`EXTRACTION_NOTE`), and an inner `if` that conditions
a case on a *parameter* (e.g. `if (flags == 0x10)`) is extracted with that input
condition dropped (`INPUT_CONDITION_DROPPED`) — TLA has no parameters, so the model
over-approximates when the transition may fire, and the human reviewer sees exactly
which input conditions must be re-asserted before promotion.

The result claim is `UNREVIEWED_EXTRACTION_CANDIDATE` with validation deliberately `NOT_RUN`.
Extraction is an input to the normal V2 lifecycle, not a shortcut around it: review the
candidate, correct its semantics, then run `validate-domain` and hash-bound `promote-domain`
as usual. Extracted candidates never enter the reviewed registry by themselves. This closes
the bidirectional loop — NL → contract → proof top-down, and Code → Math → Architecture
candidates bottom-up.

### Verified polyglot reimplementation (Code → Math → New Code)

Combining bottom-up extraction with top-down polyglot synthesis turns the tool into a
mathematical Rosetta Stone for legacy C: extract the bounded state machine, promote its
math after human review, and lower a memory-safe Rust port that Prusti proves refines the
*same reviewed model*:

```bash
# 1. Extract the legacy machine (registers domains/candidates/connection.v2.yaml).
formalspecgen analyze-codebase legacy_c/ --out-dir extracted/

# 2. Human gate: review the candidate, then TLC proves the extracted machine bounded.
formalspecgen validate-domain connection --project-root .
HASH=$(jq -r '.evidence.candidate_sha256' domains/candidates/connection.v2.validation.json)
formalspecgen promote-domain connection --accept-candidate-sha256 "$HASH" --project-root .

# 3. Lower the reviewed math into a deterministic Prusti contract and prove the port.
formalspecgen draft "connection port" --canonical-domain connection --lang rust \
  --no-clarify --out-file Connection.rs
formalspecgen implement Connection.rs --provider ollama \
  --v2-reviewed-domain domains/v2/connection.json \
  --v2-validation-evidence domains/candidates/connection.v2.validation.json
```

A successful run mints `SOURCE_MODEL_REFINEMENT`: the Rust implementation carries a native
`DEDUCTIVE_PROOF` from Prusti, and the refinement gate binds that proof to the exact
candidate hash extracted from the C — the port did not just translate syntax, it ported
the mathematical proof of safety. The full chain runs against real TLC and real Prusti in
`tests_e2e/test_reimplementation_chain_e2e.py` (the LLM body-fill seam is the only
deterministically injected step).

**Boundary.** The tool supports verified polyglot reimplementation of bounded state
machines (e.g., protocol parsers, connection states, replication handshakes). Dynamic
heap structures (e.g., linked lists, hash maps) fail closed — their state is unbounded,
the extractor flags `UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW`, and no candidate is minted
without manual domain modeling. The refinement claim covers the reviewed state-machine
semantics only; it says nothing about performance, I/O behavior, or the original C's
unreviewed call graph.

**Real-codebase proof (lwIP).** The full chain has been run against upstream lwIP
(`lwip-tcpip/lwip` master). Preprocessing with `gcc -E -P` (plus minimal `arch/cc.h` and
`lwipopts.h` stubs) flattens the `TCP_PCB_COMMON`/`IP_PCB` macros so `state` becomes a
physical field; the analyzer then extracts **ten genuine TCP state transitions** from
`tcp_process`/`tcp_close_shutdown_fin`/`tcp_pcb_remove` across two translation units
(SYN_SENT/SYN_RCVD→ESTABLISHED, ESTABLISHED→FIN_WAIT_1/CLOSE_WAIT,
FIN_WAIT_1/2 and CLOSING→TIME_WAIT, CLOSE_WAIT→LAST_ACK, any-open→CLOSED) with the
`enum tcp_state` bound resolved to `[0,10]`. One flag-condition is honestly reported as
dropped (`INPUT_CONDITION_DROPPED`) and `tcp_connect`'s CLOSED→SYN_SENT write is
correctly NOT auto-extracted — its guard is a local variable, not state. The human
reviewer prunes the 60-field pcb candidate to the state machine, adds `tcp_connect` from
the review note, and the chain completes: real TLC (7 reachable states, 13 transitions,
VALIDATED) → hash-bound promotion → deterministic Rust lowering → real Prusti
`VERIFIED` + `SOURCE_MODEL_REFINEMENT`. The macro wall is gone: **preprocessing +
review is the documented workflow for macro-heavy codebases.**

**Real-codebase proof (Apache Tomcat — the Java lane).** The same chain runs against
real Java with no preprocessing at all: `analyze-codebase` over
`java/org/apache/coyote/http11/` extracts Tomcat's request-line parser
(`Http11InputBuffer.parseRequestLine` — package-private, `boolean`-returning,
`throws IOException`) as the phase counter `parsingRequestLinePhase` with three
transitions auto-inferred (0→1, 4→5, 7→0 — the brace-simple phase arms), seven
`EXTRACTION_NOTE`s naming every deeper try/switch-nested guard the extractor refused,
and a register-time bound widened to `[0, 7]` over the stale `phase < 2` comparison
hint. The reviewer prunes the 22-field candidate to the phase machine, completes the
cycle from the notes, and TLC itself catches the deadlock at the EOF state `phase = -1`
— forcing the reviewer to add Tomcat's real `recycle()` reset. The chain completes:
real TLC (9 states, 11 transitions, VALIDATED) → hash-bound promotion → deterministic
Rust lowering (camelCase field normalized to `parsing_request_line_phase`) → real
Prusti 0.2.2 **12/12 items VERIFIED** → `SOURCE_MODEL_REFINEMENT` under
`v2_atomic_contract_refinement`. With lwIP/TinyUSB/Redis/curl (C), LevelDB (C++), and
Tomcat (Java), every extraction lane has now carried a real production parser through
the full Code → Math → Reviewed Model → Proven Port circle.

### Code-to-requirements documentation

`document-code` completes the bottom-up circle with the final leg — translating the extracted
V2 math back into structured English Markdown for undocumented legacy code:

```bash
formalspecgen document-code legacy/LegacyCounter.java --out docs/LegacyCounter.md
```

The deterministic renderer writes exact sentences from the typed extraction — state variables
with bounds and initial values, guarded operations with preconditions and effects in English
("The 'increment' operation can only be called if count is less than 5. When called, it
increases the count by 1."), and `Safety Rule:` invariant lines — plus an evidence footer with
the source digest and extractor provenance. An optional provider pass adds an overview
paragraph and semantic invariant prose; when the provider is unavailable (or `--no-llm` is
passed) the command still succeeds with deterministic sections only, and the verdict records
`narrative_source` accordingly.

The command fails closed with `UNBOUNDED_STATE_REQUIRES_MANUAL_REVIEW` when an integer state
variable has no inferable bound — it refuses to document math it cannot state — and records
`operation_inference: java_only` for non-Java sources, where transition inference is not yet
available. The success claim is `UNREVIEWED_EXTRACTION_DOCUMENTATION` with validation
`NOT_RUN`: documentation is never verification, no TLC or ESC run has occurred, and the
registered candidate still needs the normal review lifecycle.

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

### Domain-referenced system workflow

For a multi-component system, generate and review the bounded domains first. The staged system
designer then maps components to those reviewed domains instead of asking the provider to invent
state variables, transitions, or nested expression trees. A component with `domain` is forbidden
from carrying inline `state_variables` or `transitions`; the reviewed V2 artifact is the sole source
of truth for those ASTs.

The complete workflow is:

```bash
# 1. Generate, validate, and promote the bounded core domain.
formalspecgen domain \
  "An inventory tracker for checkout. Stock is 0 to 5; reserve decrements it and release increments it." \
  --schema-version 2 --force --restart-clarifications
formalspecgen validate-domain inventory --project-root .
HASH=$(jq -r '.evidence.candidate_sha256' \
  domains/candidates/inventory.v2.validation.json)
formalspecgen promote-domain inventory --accept-candidate-sha256 "$HASH" --project-root .

# 2. Design the architecture in staged/domain-reference mode.
formalspecgen design-system \
  "Checkout uses the 'inventory' domain for InventoryService. PaymentGateway is external; OrderService orchestrates." \
  --provider ollama --staged --out-file checkout_architecture.json

# 3. Bind TLC evidence and lower the architecture into Java sources.
formalspecgen validate-architecture checkout_architecture.json \
  --json checkout_design_evidence.json
formalspecgen unified-system checkout_architecture.json \
  --evidence checkout_design_evidence.json --out-dir src/ \
  --json unified_verdict.json

# 4. Optionally fill the generated external adapter with an SDK implementation.
formalspecgen implement src/StripePaymentGateway.java \
  --dependencies stripe --provider ollama \
  --assurance-level lightweight --out src/
```

`unified-system` loads `domains/v2/<domain>.json`, emits the reviewed state and operation surface,
and keeps external adapters outside the OpenJML input set. A successful core composition reports
`SYSTEM_COMPOSITION_PROOF`; it proves the generated core respects the contracted port calls, not
the Stripe SDK, credentials, transport, remote response authenticity, availability, or network
side effects. Dependency injection must preserve the boundary marker, class/interface surface,
method signatures, and JML clauses; injected adapters remain
`UNVERIFIED_EXTERNAL_ADAPTER`.

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

The same artifact can be lowered onto the native lanes with `--lang rust|c|cpp`
(`pipeline/polyglot_composition.py`): Ports become Rust `#[requires]`/`#[ensures]` traits,
C function-pointer structs (`struct PaymentGateway { bool (*charge)(int); }`), or C++ pure
virtual classes; orchestrators inject the port (a generic `P: Trait` parameter for Rust —
Prusti 0.2 cannot reason about `Box<dyn Trait>` fields — a `struct` pointer for C, a raw
pointer member for C++) and call through it. The language-neutral core — parsing, binding
resolution, SOLID lint, coupling analysis — is the same code the Java lane uses; only
rendering and the judging prover differ:

```bash
formalspecgen compose composition.json --lang rust --out-dir out/ --json verdict.json
```

Each composition renders into ONE verified compilation unit per language (`.rs`, `.c`,
`.cpp`) because Prusti, Frama-C WP, and ESBMC verify single files here; multi-crate and
multi-translation-unit orchestration are out of scope. Generated external adapters are
written as sibling scaffolding files and never enter the prover input. A successful rust/c
run reports `SYSTEM_COMPOSITION_PROOF` under scope
`single_compilation_unit_native_contract_composition`; C++ is bounded-model-checked, so its
ceiling is `BOUNDED_SYSTEM_COMPOSITION_PROOF` with `bounded_only: true`. Exit-0 units that
carry no native obligation are `VACUOUS_COMPOSITION`. Real-Prusti coverage lives in
`tests_e2e/test_polyglot_composition_e2e.py`.

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
reported as `VACUOUS_COMPOSITION`, not proof. The polyglot lanes add two of their own
boundaries: the C and C++ orchestrators currently render external-Port steps only (mixed
core+Port use cases return `UNSUPPORTED_BOUNDARY` on those lanes; Rust renders both), and
polyglot `apply-refactor` supports extract-method only, via AST-guided byte splicing
(see Modernization below); the other refactor profiles and C++ out-of-line method
definitions remain Java-only or future work. An unreviewed example artifact
lives at `domains/examples/composition/secure_entry.composition.json`.

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

### Bounded C++ / ESBMC lane

Reviewed V2 domains can also be lowered deterministically to a standalone C++17 class:

```bash
formalspecgen draft "bounded counter" --canonical-domain bounded_counter \
  --lang cpp --out-file BoundedCounter.cpp
formalspecgen verify BoundedCounter.cpp --mode esc --json cpp-verdict.json
```

The serializer emits private state, a checked constructor, public operation methods, and
assertion-based invariant/guard checks. A local `g++ -std=c++17 -fsyntax-only` gate runs before
ESBMC. The adapter creates a temporary `main` harness for class-only translation units, exercises
public no-argument operations, and runs ESBMC's bounded (`--unwind 5`) Z3 check. A successful run
may mint `BOUNDED_CPP_PROOF`; otherwise the lane fails closed. Evidence always records
`unbounded_loop_proved: false` and does not mint source/model refinement or concurrency claims.
Async Tokio metadata, lock protocols, exception semantics, and unsupported expression forms are
rejected rather than approximated. Install ESBMC from its official Ubuntu PPA or release binary;
the verifier must be available as `esbmc` on `PATH`.

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

`verify-refactor` also covers **Rust, C, and C++** single-file refactors. The surface comparison
uses Tree-sitter public signatures (`pub fn`/trait items for Rust, function definitions for C,
class and method declarations for C++) plus the native contract set — Prusti
`#[requires]/#[ensures]` attributes, ACSL blocks, or C++ assertion checks — and both revisions are
re-proved with their native prover (Prusti, Frama-C WP, or ESBMC). Rust and C mint
`REFACTOR_CONTRACT_PRESERVED` with `baseline_deductive_proof: true`; C++ mints the bounded ceiling
`BOUNDED_REFACTOR_CONTRACT_PRESERVED` because ESBMC is a bounded model checker. Demoting a Rust
`pub fn` to a private `fn`, weakening a Prusti attribute, or editing an ACSL block fails closed
with `method_surface_changed`/`contract_surface_changed`. The gate is proven end to end against
real Prusti and Frama-C in `tests_e2e/test_polyglot_refactor_gate_e2e.py`.



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

State and Decorator remain inspection-only recommendations for general code. A narrow State
profile is admitted for methods containing two or more `int` equality branches whose bodies are
single return expressions; it emits stateless handler classes and routes the selected branch
through them. A narrow Strategy profile is admitted for one public `void` method taking a single
`int` parameter whose body is solely a `param == literal` chain assigning the same `int` field one
literal per branch under an `ensures <field> >= <k>` contract: it emits a strategy interface with
a total static selector (the baseline `requires` carried over, out-of-domain values rejected), one
constant implementation per branch (named from the branch's trailing comment when present), and a
primary that selects then delegates through `strategy.calculate()`; the interface carries the
translated `ensures \result >= k` so the primary's original postcondition still proves. The
generated directory still requires the multifile refactor gate — verified end to end with real
OpenJML ESC (`inspect → apply-refactor --pattern strategy → verify-refactor` minting
`MULTIFILE_REFACTOR_CONTRACT_PRESERVED`). Decorator and broad state transitions remain
unavailable until their callback/order and invariant obligations can be proved.

#### End-to-end modernization workflow

The intended legacy-modernization loop is inspection, hash-bound transformation, and independent
verification:

```bash
formalspecgen inspect baseline/LegacyService.java --json inspection.json
formalspecgen apply-refactor baseline/LegacyService.java \
  --inspection inspection.json --pattern extract-method --method processOrder \
  --out refactored/LegacyService.java --json refactor-candidate.json
formalspecgen verify-refactor baseline/LegacyService.java refactored/ \
  --json refactor-verdict.json
```

The supplied method must satisfy the deterministic detector (the current Extract Method profile
requires more than 60 method lines). Public JML clauses that mention private fields require the
usual `/*@ spec_public @*/` visibility annotation, and integer arithmetic requires preconditions
that rule out Java `int` overflow. These are contract obligations, not relaxations of the proof.

On success, `refactor-verdict.json` reports
`MULTIFILE_REFACTOR_CONTRACT_PRESERVED` with `contract_surface_preserved: true`. The proof covers
the baseline and refactored contracts independently with OpenJML; it intentionally keeps
`behavior_equivalence_proved: false` because full heap/bisimulation equivalence is outside this
profile.

### Parallel architectural behavior correction

`system --mode correct` hardens a flawed component architecture with isolated
correct-behavior sub-agents instead of one overloaded context window:

```bash
formalspecgen system correction-plan.json --mode correct \
  --out-dir corrected-system --max-workers 4 --provider ollama \
  --json corrected-system-verdict.json
```

The correction artifact lists each flawed component (`{"component", "file"}`), optionally with
an explicit `"cwe"`; without one, the orchestrator security-inspects the file and selects the
highest-severity actionable CWE. The master writes
`architecture_correction_plan.json`, then spawns at most `--max-workers` independent
`formalspecgen correct-behavior` subprocesses — each sub-agent sees exactly one component and
one CWE (context isolation), strengthens the local contract, repairs the code, and proves the
result with OpenJML ESC. Any sub-agent that does not return
`BEHAVIOR_CORRECTION_VERIFIED` fails that branch closed without corrupting the others.

Only when every component is corrected does the orchestrator re-run the composition gate
against the corrected copies (`composition` key optional in the artifact). Success reports
`SYSTEM_CORRECTION_VERIFIED` with claim `SYSTEM_COMPOSITION_PROOF`
(`ISOLATED_BEHAVIOR_CORRECTIONS_VERIFIED` without a composition), a hash-bound certificate
over the plan and component verdicts, and the scope limits:
`global_behavior_equivalence_proved: false` — hardening *intentionally* changes behavior, so
equivalence with the vulnerable system is neither claimed nor provable; what is proven is each
corrected component's strengthened contract plus the composition of those contracts.
`concurrent_component_execution_proved: false` — the worker pool is orchestration, not a
verified property.

### Parallel system refactoring

For a bounded modernization plan, `system --mode refactor` inspects and refactors independent
Java components through a bounded in-process worker pool. Each component receives one source file
and an optional supported pattern/method; unsupported or uninspected smells fail closed without
running a composition gate. These workers provide context isolation, but are not independent
LLM agents and their scheduling is not a verified property.

```json
{
  "components": [
    {"component": "legacy", "file": "baseline/LegacyService.java",
     "pattern": "extract-method", "method": "processOrder"}
  ]
}
```

Run the isolated refactor workers with a bounded pool:

```bash
formalspecgen system refactor-plan.json --mode refactor \
  --out-dir refactored-system --max-workers 4 \
  --json refactor-system-verdict.json
```

Every worker must produce `REFACTOR_CONTRACT_PRESERVED` (or the multifile equivalent) before
the aggregate result can be `SYSTEM_REFACTOR_VERIFIED`. A plan may also include a reviewed
composition artifact under `composition`; when present, the existing composition gate runs only
after every local proof succeeds and the aggregate claim becomes `SYSTEM_COMPOSITION_PROOF`.
The verdict always records `global_behavior_equivalence_proved: false`: local contract proofs and
composition soundness do not establish behavioral equivalence of the legacy system's heap,
scheduling, I/O, or runtime topology.

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

Generated adapter stubs can receive a provider-backed SDK implementation pass:

```bash
formalspecgen implement StripePaymentGateway.java --dependencies stripe \
  --provider ollama --json stripe-injection.json
formalspecgen implement AwsUploader.rs --dependencies aws \
  --provider ollama --json aws-injection.json
formalspecgen implement HttpClient.cpp --dependencies curl \
  --provider ollama --json curl-injection.json
```

This pass is restricted to files carrying the `UNVERIFIED EXTERNAL BOUNDARY` marker. It preserves
the adapter's class/interface and JML surface (Rust: the trait impl signature plus every
`#[requires]`/`#[ensures]`; C++: the virtual signatures and assertion guards), changes only
method bodies, and records
`UNVERIFIED_EXTERNAL_ADAPTER` with `external_io_safety_proved: false`. Provider output that removes
the marker or changes the trusted surface fails closed; the adapter remains excluded from
composition ESC even after SDK calls are injected. Rust adapters are filled with `aws-sdk-s3`
conventions and C++ adapters with libcurl; each dependency is gated to its language's file
suffix, and C adapters have no SDK lane yet (`unsupported_dependency`).

### Restricted Factory Method application

#### Polyglot extract-method (rust / c / cpp)

For `.rs`, `.c`, `.cpp`, `.cc`, and `.cxx` sources, `apply-refactor --pattern
extract-method` performs **AST-guided string splicing**: Tree-sitter locates the target
function and its exact byte range, and the transformation cuts and pastes the RAW source —
no AST is ever re-rendered, so formatting, comments, and native contracts (Prusti
attributes, ACSL blocks, C++ assertions) move verbatim. The supported shape is whole-body
delegation: a non-public `{name}_helper` receives the original signature, the original
body moves into it untouched (locals move with it — no hoisting), and the original
function becomes a one-line call. The preceding contract block is duplicated onto both
the helper and the wrapper so each can be reasoned about modularly:

```bash
formalspecgen apply-refactor baseline/lib.rs \
  --pattern extract-method --method process \
  --out refactored/lib.rs --json extract-verdict.json
```

The splice runs the existing polyglot refactor gate immediately: every baseline public
signature must survive verbatim (additions such as the helper are allowed), the
normalized contract set must be unchanged, and BOTH revisions are re-proved by the native
prover (Prusti / Frama-C WP / ESBMC) before `REFACTOR_CONTRACT_PRESERVED`
(`BOUNDED_REFACTOR_CONTRACT_PRESERVED` for C++) is minted. C++ supports in-class method
definitions only — out-of-line qualified definitions, partial-body extraction, and
free-variable hoisting fail closed. Java sources keep requiring hash-bound `--inspection`
evidence and the full profile set.

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
side effects, or stale inspection evidence fail closed. Decorator transformations remain
inspection-only: callback-order mappings require stronger profile-specific obligations than the
Factory, narrow State, narrow Decorator, and narrow Facade extraction profiles.

### Bisimulation preflight

`verify-bisimulation` validates a JSON state mapping and binds baseline/refactored source hashes,
but deliberately emits `behavior_equivalence_proved: false`; a mapping is not a relational proof.
The preflight also reports `contract_surface_preserved` by comparing public Java method signatures.

```bash
formalspecgen verify-bisimulation baseline/Legacy.java refactored/ mapping.json --json bisim.json
```

Composition can also prepare a bounded actor/interleaving model:

```bash
formalspecgen compose composition.json --actors OrderA,OrderB --no-esc --json concurrent.json
```

The artifact records `Actors`, `callResult`, and `history` state, but does not claim concurrent
linearizability until TLC and the Java lock correspondence are independently discharged.

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
pipeline/cwe_registry.py  Config-driven CWE manifest loader (see security/cwe_manifest.json)
pipeline/pattern_registry.py  Categorized design-pattern detector registry
pipeline/domains/      Reviewed and scaffolded semantic-domain plugins
formalspec_core/       Shared deterministic postprocessor and proof-support core
domains/               Declarative domain specifications (V2 candidates under candidates/)
extracted/             Unreviewed `analyze-codebase` output (architecture map and domain sketches)
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

The deterministic suite currently reports 99.01% combined statement/branch coverage across 1160
tests and enforces a minimum of 99%. Real-toolchain and optional live-Ollama checks remain in
`tests_e2e/` — including the chained-CLI platform tests
(`inspect → apply-refactor → verify-refactor`, `security-inspect → correct-behavior → verify`,
`analyze-codebase → document-code`) — and can be run with:

```bash
scripts/run_e2e.sh
RUN_LIVE_LLM_E2E=1 scripts/run_e2e.sh
```

Run the real-TLC V2 lifecycle tests directly with:

```bash
python3 -m pytest -c tests_e2e/pytest.ini tests_e2e/test_v2_workflow.py -v
```

The chained-command platform tests in `tests_e2e/test_platform_chains_e2e.py` drive multiple
subcommands in sequence against one fixture so the CLI is validated as a cohesive pipeline:
`inspect → security-inspect → apply-refactor null-object → verify-refactor` (which correctly
fails closed because the Null Object transform strengthens the contract),
`inspect → apply-refactor extract-method → verify-refactor` minting
`REFACTOR_CONTRACT_PRESERVED` through real ESC, and
`security-inspect → correct-behavior → verify` minting `DEDUCTIVE_PROOF` for CWE-125 and
CWE-476 with static fixtures standing in for the provider. Run them with:

```bash
python3 -m pytest -c tests_e2e/pytest.ini tests_e2e/test_platform_chains_e2e.py -v
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
