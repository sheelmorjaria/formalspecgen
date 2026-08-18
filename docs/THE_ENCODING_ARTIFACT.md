# The Encoding Artifact: Bidirectional Formal Synthesis with LLM Proposers and Mechanical Judges

*A design paper and experience report on FormalSpecGen (v6.0.0), August 2026.*

## Abstract

Large language models write plausible code and plausible contracts with equal fluency,
which is exactly why neither can be trusted as evidence. This paper describes an
architecture in which the LLM is demoted to a *proposer* inside a pipeline whose every
artifact of trust — the specification, the state machine, the correction, the proof
obligation — is a deterministically produced **encoding artifact** that independent
mechanical judges (Z3 via OpenJML ESC, Prusti/Viper, Frama-C WP, ESBMC, TLC) either
accept or reject. The contribution is not any single prover integration but the
discipline: LLM output never becomes evidence, every claim has a named ceiling, every
gate fails closed, and humans own exactly the trust assumptions (bounds, invariants,
promotions, signatures) that machines cannot invent.

We report the strongest result of this discipline: six full-production parser state
machines — lwIP TCP, TinyUSB USB device, Redis RESP, curl HTTP headers, LevelDB's WAL
reader, and Apache Tomcat's HTTP request-line parser — extracted from upstream C, C++,
and Java sources into reviewed TLA+ state machines, validated by real TLC, and lowered
into memory-safe Rust that Prusti proves refines the *same reviewed model*
(`SOURCE_MODEL_REFINEMENT`). In four of the six ports, the bounded traverser caught a
genuine transcription error the human reviewer had made — and a static pre-TLC gate now
catches that same missing-`recycle()` class in milliseconds. We further report a
correction lane covering six CWE classes with deterministic, CWE-scoped strategy routing
and hardware-derived capacity bounds, where every hardening claim is discharged by Z3
rather than asserted by the model that proposed the rewrite; a set of proof extensions
— behavioral bisimulation between machines, k-induction for unbounded loops, lock
correspondence for linearizability, and adversarial fault injection for distributed
safety — each with its epistemic division recorded in the verdict; a
reviewer-non-repudiation layer binding promoted artifacts to authorized GPG keys; and
an agent surface (28 tools) that exposes every machine-provable capability while
keeping acceptance, signing, and key policy in human hands.

## 1. Introduction

The trust problem in LLM-assisted programming is not that models are wrong; it is that
their output arrives pre-authenticated — fluent, confident, and indistinguishable (to a
casual reader) from verified truth. The industry response has been to add more review.
We argue the response should be to change the *unit of trust*.

FormalSpecGen is built on one governing rule:

> The LLM proposes; deterministic compilers transform; formal tools judge; humans
> control trusted assumptions.

Under this rule the interesting objects in the system are not prompts or completions
but **encoding artifacts**: typed, hash-bound intermediates that a deterministic
compiler produced from reviewed input and that a mechanical judge must accept before
anything downstream may claim evidence. An LLM may *propose* the contents of an
artifact; it may never *be* one.

The paper proceeds as follows. Section 2 defines the artifact lattice. Section 3
describes the top-down (natural language → proof) direction. Section 4 describes the
bottom-up (legacy code → math → new code) direction and the extraction dialects that
made six production ports possible. Section 5 reports the ports. Section 6 describes
the hardening/correction lane. Section 7 reports the proof extensions — behavioral
equivalence, unbounded induction, linearizability, and distributed fault tolerance.
Section 8 describes the non-repudiation layer and the agent boundary. Section 9 states
the evidence taxonomy and — as importantly — what is deliberately *not* claimed.
Section 10 discusses limitations and threats to validity.

## 2. The encoding artifact

Every claim in the system is backed by one of six artifact kinds:

1. **The typed V2 candidate** — a Pydantic-validated YAML domain (state variables with
   bounds, operations with guards/effects/invariants as a strict recursive expression
   AST; no LLM infix text is ever stored). Extraction or an interactive session may
   propose it; a bounded Python traverser and a strict schema decide whether it is
   even *stateable*.
2. **The TLA+ rendering + TLC evidence** — deterministically compiled from the
   candidate (never parsed back from prose), executed by the real TLC 2.19 with strict
   version provenance. Reachable-state and transition counts are *measured*, not
   estimated.
3. **The promotion binding** — a SHA-256 digest of the exact reviewed candidate plus
   the evidence-envelope digest. Promotion is a human trust action; the hash makes it
   auditable and TOCTOU-checked. A digest establishes artifact identity, not reviewer
   identity — signatures are an explicitly separate, optional mechanism.
4. **The native contract lowering** — JML, Prusti, or ACSL contracts *derived* from
   the reviewed typed trees by deterministic serializers. The deterministic baseline
   has itself caught translation bugs (an `==>`-precedence under-encoding) that a
   green prover had been silently accepting.
5. **The proof verdict** — OpenJML ESC / Prusti / Frama-C WP / ESBMC / TLC output,
   normalized into a shared schema with explicit vacuity guards (an exit-0 run with no
   real obligation is `VACUOUS_VERIFIED`, never `VERIFIED`; an empty file must never
   fake a pass).
6. **The reviewer signature** — a detached GPG signature over a promoted artifact,
   verified against a managed authorized-key registry (`trusted_keys.json`, merged with
   the legacy environment variable). A digest establishes artifact identity; a verified
   signature from a registry-authorized key establishes *who* accepted it — the
   non-repudiation layer on top of integrity.

The flow between artifacts is one-directional and compiled: candidate → TLA+ → TLC
evidence → promotion → lowering → proof. At no point does LLM output enter this chain
except as a *proposal* that the next deterministic stage validates or rejects.

## 3. Top-down: natural language to proof

The forward direction runs NL → clarification → checked JML contract → implementation
synthesis → formal judgment. Three design decisions carry the weight:

**Trusted surfaces are immutable.** Synthesis receives the contract surface (class,
signatures, JML clauses; Rust trait/fn signatures + Prusti attributes; C signatures +
ACSL blocks) as a fixed boundary. Any generated modification of that boundary is a
terminal `TRUST_BOUNDARY_VIOLATION` — the loop dies rather than negotiates.

**Assurance levels are claim ceilings, not effort dials.** `critical` may mint
`DEDUCTIVE_PROOF` because it requires ESC; `standard` caps at `RUNTIME_SAMPLE` because
RAC/JUnit evidence is execution, not proof; `lightweight` caps at `STATIC_CHECK`. A
gate skipped for cost leaves a recorded reason, never a silent upgrade.

**Repair is resample-first.** A failing candidate is regenerated before the expensive
prover re-runs, with diagnostic feedback second; identical-candidate loops are
detected and stop as `stalled` rather than burning budget (a behavior first observed
on a two-lights mutual-exclusion invariant OpenJML kept rejecting until a narrow,
explicitly-accepted deterministic guard-strengthening pass fixed it).

## 4. Bottom-up: the Rosetta Stone lane

The reverse direction is where production validation happened. The pipeline:

1. **Parse** the source tree with Tree-sitter (Java, Rust, C, C++), error-tolerant,
   with a deterministic regex fallback for minimal installations. Macro-heavy C is
   preprocessed with `gcc -E`/`g++ -E` first — *preprocessing + review is the
   documented workflow for macro-heavy codebases*.
2. **Infer transitions deterministically** into the strict V2 expression AST.
3. **Register unreviewed candidates** (`domains/candidates/*.v2.yaml`) — never
   reviewed artifacts; extraction is an input to the lifecycle, not a shortcut around
   it.
4. **Human review** prunes (lwIP: 60 fields → the TCP state machine; Redis: 87 → 3)
   and completes from the extractor's honest refusal notes.
5. **Real TLC validates** the reviewed machine.
6. **Hash-bound promotion**, then **deterministic Rust lowering** whose Prusti
   contracts derive from the same typed trees — the port is proved to refine the
   model, not merely to compile.

### 4.1 The extraction dialects

Real code did not match textbook shapes; each port taught the extractor a dialect,
always fail-closed:

- **Scalar-status returns** (lwIP's `static err_t tcp_process`, Tomcat's
  `boolean parseRequestLine`) — the return value is orthogonal to the state write;
  pointer returns stay outside the boundary.
- **Enum resolution** — implicit/explicit/hex counters, enum-typed field extents,
  switch dispatch segmented one transition per `break`-terminated case, fall-through
  skipped with a note.
- **Postfix counters** (curl's `if (!k->headerline++)`) — the increment is a
  condition side effect, so *both* branch values increment: the pair
  (`== 0` → +1, `!= 0` → +1) models the statement faithfully.
- **Bare boolean cross-field guards** (TinyUSB's `if (dev->connected) {
  dev->suspended = 1; }`) — extracted only when the write lives inside the guard's
  own brace block, so a guard block containing only callbacks never steals a later
  assignment.
- **Package-private Java methods with `throws`** (Tomcat) — real enterprise Java does
  not use `public void` everywhere; method bodies are brace-matched, multiple guarded
  writes per method mint collision-suffixed transitions, and nested control flow
  around a write is refused with an `EXTRACTION_NOTE` naming the exact guard.
- **Honest bounds** — register-time bounds fall back to the transitions' own
  constants, and a comparison-derived bound the machine's real writes exceed is
  *widened to the write maximum*: code that assigns 7 cannot be bounded at 2 because
  an earlier `phase < 2` comparison suggested it.

Every refusal is reported, never silently applied: fall-through cases, dropped input
conditions (TLA has no parameters — the model over-approximates and the reviewer sees
exactly which conditions must be re-asserted), and nested-guard skips all carry named
warning codes.

### 4.2 The traverser as the reviewer's guard dog

The bounded BFS traverser (real TLC behind it) rejected the human-reviewed model four
times across the six ports — each time correctly:

| Port | Traverser catch |
| --- | --- |
| curl | headerline bound mis-transcribed from the reviewer's reading |
| Redis | EOF guard left the machine able to read past end-of-input |
| LevelDB | the same EOF-guard error, made again despite the prior lesson |
| Tomcat | the EOF state `phase = -1` deadlocked — the machine was missing Tomcat's real `recycle()` reset between requests |

This is the paper's central empirical claim: when the encoding artifact is the unit
of trust, mechanical judges police *the human* as effectively as they police the
model. The fourth catch is the important one — the reviewer knew about the first
three and still missed that "parsing is complete" is not the same state as "ready to
parse again."

### 4.3 The pre-TLC deadlock net

The fourth catch motivated a deterministic net so that class of error never again
needs the expensive judge to surface. Three gates run before TLC is paid for:
a **static deadlock gate** performs three-valued partial evaluation of the typed
guards — fix one field's value, mark every other field unknown, let Kleene logic
decide — and flags any int value that can be entered (initial or literal-written)
but that no operation provably admits, failing closed
`DEADLOCK_RISK: state phase == -1 has no outgoing transition`; `terminal_states`
mark legitimate end states, which TLC still checks for reachability; and
**lifecycle idiom detection** reports `recycle`/`reset`/`clear`/`init` methods whose
brace-stripped bodies contain unconditional state writes — the exact shape the
guarded-transition dialect correctly refuses to extract — as
`POTENTIAL_LIFECYCLE_RESET` notes naming the method and the fields it resets. On
upstream Tomcat this flags `recycle()` in eleven classes. A canary test pins zero
false positives across every candidate in the repository, on every suite run.

## 5. The six production ports

All six ran against upstream sources with real tools end to end:

| Target | Lang | Extraction | Real TLC | Native proof | Claim |
| --- | --- | --- | --- | --- | --- |
| lwIP TCP (`tcp_process` et al.) | C | 10 auto transitions, 2 translation units | 7 states / 13 transitions | Prusti `VERIFIED` + 6/6 refinement | `SOURCE_MODEL_REFINEMENT` |
| TinyUSB (`usbd.c`) | C | 4-field machine, cross-field guards | 12 states / 80 transitions | Prusti 13/13 | `SOURCE_MODEL_REFINEMENT` |
| Redis RESP (`networking.c`) | C | 87 → 3 fields after review | 7 states / 14 transitions | Prusti 10/10 | `SOURCE_MODEL_REFINEMENT` |
| curl HTTP headers (`http.c`) | C | 2-field machine, postfix counters | 6 states / 12 transitions | Prusti 8/8 | `SOURCE_MODEL_REFINEMENT` |
| LevelDB WAL (`log_reader`) | C++ | switch-dispatch record machine | 3 states / 9 transitions | Prusti 8/8 | `SOURCE_MODEL_REFINEMENT` |
| Tomcat `Http11InputBuffer` | Java | 3 auto + 7 notes → 10-op machine | 9 states / 11 transitions | Prusti 12/12 | `SOURCE_MODEL_REFINEMENT` |

Two honest negatives belong in the same table. The LevelDB `Reader` class extracted
*pointers only* — the machine lived in one method's switch, and the extractor said so
rather than inventing state. And curl's first pass extracted **zero** transitions
(postfix counters were then outside the dialect); the machine was hand-transcribed,
and the dialect was subsequently extended so the re-probe auto-extracts the exact
operations that had been transcribed. Zero-with-a-reason is a feature.

## 6. The correction lane: hardening as a verified contract change

Where synthesis proves what was requested, *correction* fixes what was found. The
`correct-behavior` lane strengthens the contract first (provider proposes; a
CWE-manifest-driven prompt scopes it), rewrites the implementation, and requires the
prover to discharge the strengthened contract. Because rejecting work beyond a
capacity *changes observable behavior*, a correction is deliberately never certified
as a contract-preserving refactor — `verify-refactor` correctly rejects it as
`primary_contract_surface_changed`, and the correction verdict is the evidence class
that covers the new surface.

### 6.1 Capacity bounding (CWE-400)

Four strategies rewrite dynamic/unbounded code into static bounded code
(`bound-loop`, `static-pool`, `bounded-cache`, `bounded-pool`). A deterministic
pre-prover residual check fails closed `strategy_not_satisfied` if the rewrite keeps
the vulnerable shape — and pattern absence is only a *necessary* condition; Z3 still
has to prove the strengthened `requires`/`ensures`. With a hardware profile, the
silicon picks the number (`safe_capacity = usable SRAM × margin ÷ struct size`), and
the lane refuses allocations that cannot physically fit (`hardware_bound_exceeded`,
`STACK_OVERFLOW_RISK`, `HARDWARE_MEMORY_EXCEEDED`). The same bounding applies
deterministically — no LLM — to V2 candidate YAMLs, clamping state bounds to the
derived capacity; proof stays downstream with TLC and promotion.

**The proven rejection boundary.** Rejecting work beyond the capacity is not a
runtime convention bolted on after the fact — it is the proof obligation. The
boundary is proved in whichever native idiom the lane speaks: Java pins a dedicated
exception to the boundary with `signals (CapacityReachedException e)
\old(acquired) == capacity` (Z3 proves the throw fires exactly at
`acquired == capacity` and the count advances otherwise; the exception constructor
needs an explicit `assignable \nothing` frame or the caller's frame check fails);
Rust proves `Result::is_err()` at the boundary and the advance otherwise under
Prusti; C proves the errno-style `-1` return through two complete-and-disjoint ACSL
behaviors under Frama-C WP; C++ checks the throw path under ESBMC's bounded
exploration. What the caller does at the boundary — backpressure (503/429 plus an
autoscaler metric), a fail-safe mode under a safety supervisor, or spill to a
disk-backed queue — is a deployment decision the correction deliberately leaves to
the human. The proven fact is only *that* work beyond capacity is rejected, never
silently absorbed.

### 6.2 Hardening strategies (CWE-190/667/79/617/362)

Five further strategies give the lane a vocabulary beyond capacity: `checked-math`
(overflow-checked arithmetic with no-wrap contracts), `lock-timeout` (`tryLock`
with explicit failure values and `finally`-guaranteed release), `canonicalize`
(encoding untrusted output), `fail-safe` (reachable asserts become explicit
validation), and `immutable-snapshot` (shared mutable state becomes published
copies). Each carries its own necessary-condition residuals — a rewrite that never
argues an overflow bound, keeps a bare `.lock()`, or leaves a public non-final
mutable field never reaches the prover.

### 6.3 CWE-scoped routing

`--auto-strategy` replaces the human's strategy choice with a pure function of
(source text, CWE, optional hardware profile) — no LLM in the choice. Each CWE owns
its own shape table, and a shape from one class never routes a strategy from
another: an unbounded loop under a CWE-190 request routes to `no_routable_strategy`
(manual review), never to `bound-loop`. Routing only picks; every downstream gate
stays, and the verdict records `strategy_routed: true` so a reviewer can always
distinguish a router-chosen strategy from a human one.

## 7. The proof extensions

Four later capabilities extend the lattice beyond synthesis and correction. Each is a
separate claim with its epistemic division recorded in the verdict itself.

### 7.1 Behavioral equivalence (bounded bisimulation)

`prove-equivalence` proves two V2 machines behaviorally identical under a
reviewer-supplied state mapping — the relational claim `verify-refactor` deliberately
does not make. Both machines' finite reachable spaces are enumerated (the same bounded
evaluator and cap as the traverser); the mapping must be functional and injective,
cover every reachable baseline state, and at every related pair the *mapped successor
sets must coincide in both directions*. Exhaustive over the reachable spaces, this is a
complete proof for the bounded machines — not an induction. The claim
`BEHAVIORAL_EQUIVALENCE_PROVED` carries scope `bounded_state_space_bisimulation` and
`heap_equivalence_proved: false`: the machines are equivalent; Java heap topology,
timing, and I/O are not claimed.

### 7.2 Unbounded loops (k-induction)

`verify-unbounded` lifts the ESBMC bounded ceiling without unrolling the loop. Two
loop-free harnesses are generated deterministically per simple `while` loop:
*establishment* (the invariant holds for the program's own entry state — the counter's
literal initialization extracted from source) and *step* (assume invariant and guard
over nondeterministic state, execute one body copy, assert preservation). ESBMC
verifies each at unwind 1; both passing means the invariant is inductive. The
epistemic division is explicit: `inductiveness_machine_proved: true` but
`sufficiency_for_property: human_accepted_assumption` — the machine proves the
induction; whether the invariant is strong enough for the property the reviewer cares
about is a human-accepted assumption. A naive invariant is refused at the failing
harness, named: `i <= n` on `while (i < n)` genuinely fails establishment for
negative `n`, and the lane says so.

### 7.3 Concurrent linearizability (lock correspondence)

`verify-linearizability` proves a Java source's lock discipline corresponds to a
reviewed lock-protocol domain, then that every bounded concurrent history serializes
through the reviewed `effect_commit` linearization points. The correspondence gate is
deterministic: `synchronized` regions (brace-matched, acquire/release lines) on a
single receiver map to the modeled lock; explicit `x.lock()` sites must carry the
model's lock-variable name; anything else fails closed `LOCK_CORRESPONDENCE_FAILED`.
Full linearization-point coverage is enforced by the domain schema itself — a spec
with partial coverage never loads. The claim covers the model plus the lock
correspondence (`java_memory_model_proved: false` records the rest).

### 7.4 Distributed safety (adversarial fault injection)

`verify-distributed` proves an async-message-passing domain's reviewed invariants
hold under an unreliable network. The reviewer declares the message-slot fields;
synthetic fault operations are injected over them — `DropMsg` resets an occupied slot
to its sentinel, `DuplicateMsg` copies an occupied slot into an empty one,
`ReorderMsg` swaps occupied slots — and the traverser explores every fault-enabled
interleaving. Because faults only *add* behaviors, safety under the full fault set
implies safety under any subset the real network performs: the exploration
over-approximates by construction. Violations name the invariant, the fault, the
operation, and the state. The claim is safety only — `liveness_proved: false` and
`eventual_delivery_proved: false`, because loss can always fire.

### 7.5 Certification traceability

`generate-traceability-matrix` maps NL requirements to V2 invariants by shared
state-field mention and numeric bound, then to the source line enforcing them —
deterministic matching, no LLM. Unmapped requirements surface as `UNMAPPED` rows,
never silently dropped; the matrix carries no proof claim of its own. It is the
plumbing between the reviewed math and DO-178C/ISO 26262 traceability objectives.

## 8. Non-repudiation and the agent boundary

The trust layer binds *who* to *what*. `sign-artifact` writes a detached GPG
signature over any evidence artifact; `manage-trust` maintains the authorized-key
registry; the composition and unified-system gates, when
`FORMALSPECGEN_REQUIRE_SIGNATURES` is set, fail closed against it. A rogue or
compromised reviewer cannot inject a flawed domain into the Rosetta lane without a
signature from an authorized key.

The agent surface (a Model Context Protocol server, 28 tools) exposes every
machine-provable capability: extraction, validation, drafting, refinement proofs,
all nine correction strategies with silicon-derived bounds, equivalence, induction,
linearizability, distributed safety, traceability, and system orchestration. Exactly
three classes of action stay CLI-only, and the exclusion is the design:
`promote-domain` (hash-bound acceptance), `sign-artifact` (signing), and
`manage-trust` (key policy). Signing and authorization require the human reviewer's
own GPG key — an agent must never accept, sign, or authorize on a reviewer's behalf.
The division is the thesis in miniature: machine-provable work is delegated; human
trust is not.

## 9. What is claimed — and what is not

The evidence taxonomy is small and non-interchangeable: `STATIC_CHECK`,
`RUNTIME_SAMPLE`, `BOUNDED_ARCHITECTURE_EVIDENCE`, `DEDUCTIVE_PROOF` (and the scoped
specializations: `SOURCE_MODEL_REFINEMENT`, `SCOPED_COMPOSITION_PROOF`,
`SYSTEM_COMPOSITION_PROOF`, `BEHAVIOR_CORRECTION_VERIFIED`,
`HARDWARE_MEMORY_BOUND_PROVEN`, `BEHAVIORAL_EQUIVALENCE_PROVED`,
`CONCURRENT_LINEARIZABILITY_PROVED`, `DISTRIBUTED_SAFETY_PROVED`). The deliberate
negatives are part of the design:

- `SOURCE_MODEL_REFINEMENT` covers the reviewed state-machine semantics only — not
  performance, I/O behavior, or the original code's unreviewed call graph.
- `REFACTOR_CONTRACT_PRESERVED` proves both revisions discharge the same normalized
  contract surface; the relational strengthening lives in the separate
  `BEHAVIORAL_EQUIVALENCE_PROVED` claim, scoped to the bounded machines.
- Composition proves the core respects contracted ports;
  `external_io_safety_proved: false` for every generated adapter.
- Linearizability covers the bounded histories plus the lock correspondence —
  `java_memory_model_proved: false`; scheduler properties are never implied.
- `DISTRIBUTED_SAFETY_PROVED` covers bounded slot abstractions under the injected
  fault set; `liveness_proved: false` and `eventual_delivery_proved: false` always.
- None of it constitutes DO-178C/ISO 26262 certification; the tool produces
  hash-bound bounded-model evidence *suitable for inclusion in* an assurance case,
  and the traceability matrix is the plumbing toward that objective — never proof.

Fail-closed is the default posture at every seam: unknown AST nodes, unreviewed
renderer mappings, missing tools, modified locked contracts, vacuous obligations,
unmappable diagnostics, unauthorized signers — each dies with a named code rather
than degrading the claim.

## 10. Limitations and threats to validity

**Extraction is deliberately shallow.** Guarded scalar assignments, switch dispatch,
postfix counters, and brace-simple boolean guards. Heap topologies, callbacks,
aliasing, and responsibility grouping are refused, not approximated. The 22-field
Tomcat candidate yields a 1-field machine *because the other 21 fields were pointers
and counters the extractor honestly declined to encode*.

**The reviewer is the trust root.** Promotion binds a hash; the signature layer binds
an authorized key to that hash — establishing who accepted what, and nothing more.
The four traverser catches show the mechanical judges police transcription, but the
choice of what to promote and which keys to authorize remains human, and a signature
is not a substitute for review.

**LLM dependence is real but bounded.** Contracts, bodies, rewrites, and loop
invariant proposals come from models (locally hosted); when the provider is
unreachable every LLM-backed verdict fails closed. The deterministic lanes (candidate
bounding, routing, serialization, TLA+ rendering, refinement-gate re-rendering, fault
injection, deadlock analysis) do not consult models at all — and where a model
proposes an invariant, only its *inductiveness* is machine-proved; its sufficiency is
the reviewer's accepted assumption.

**Proof scope is the prover's scope.** Prusti/Frama-C/ESBMC verify the fragments
they are given; weak memory and JDK internals are outside what was proved. Unbounded
loops are covered only through reviewer-supplied (or LLM-proposed,
inductiveness-checked) invariants, not by default. The claim names the scope; the
scope names the boundary.

## 11. Related work

Verifying compilers (ESC/Java2, Dafny, Why3), model checkers (TLA+/TLC, SPIN), and
bounded verifiers (CBMC, ESBMC) supply the judges; this work is about the *lattice*
between them and an LLM that is only ever allowed to propose. Recent LLM-for-formal-
methods work typically asks the model to emit annotations or invariants and measures
acceptance rates; the encoding-artifact position inverts the question — it does not
matter how often the model is right if the artifacts make wrongness cheap to detect
and impossible to certify.

## 12. Conclusion

Six production parsers from three languages now sit in one reviewed, hash-bound,
provable artifact lattice — extended with behavioral equivalence between machines,
unbounded loop induction, lock-correspondence linearizability, adversarial fault
tolerance, certification traceability, and reviewer non-repudiation, all surfaced to
agents through 28 tools that expose every machine-provable capability and none of the
human trust actions. Four times the mechanical judge corrected the human, and the
static nets now catch that class before the judge is even paid for; every time the
model tried to shortcut the lattice, a deterministic gate refused. The engineering
claim is narrow and checkable: **with the encoding artifact as the unit of trust,
LLM-assisted development can produce evidence rather than assurance theater** — and
the evidence says exactly how far it reaches and where it stops.

---

### Reproducing the headline results

```bash
# One legacy C machine, end to end against real TLC and real Prusti:
formalspecgen analyze-codebase legacy_c/ --out-dir extracted/
formalspecgen validate-domain connection --project-root .
HASH=$(jq -r '.evidence.candidate_sha256' domains/candidates/connection.v2.validation.json)
formalspecgen promote-domain connection --accept-candidate-sha256 "$HASH" --project-root .
formalspecgen draft "port" --canonical-domain connection --lang rust --no-clarify --out-file Connection.rs
formalspecgen implement Connection.rs --provider ollama \
  --v2-reviewed-domain domains/v2/connection.json \
  --v2-validation-evidence domains/candidates/connection.v2.validation.json

# One hardening correction, judged by Z3:
formalspecgen correct-behavior src/Meter.java --cwe CWE-190 --strategy checked-math

# Behavioral equivalence between two machines (bounded bisimulation):
formalspecgen prove-equivalence baseline.v2.yaml refactored.v2.yaml --mapping states.json

# Unbounded loop verification (k-induction; the provider proposes when omitted):
formalspecgen verify-unbounded Counter.cpp --invariant "i >= 0 && (n <= 0 || i <= n)"

# Concurrent linearizability (lock correspondence + bounded histories):
formalspecgen verify-linearizability ConcurrentBank.java --domain bank.v2.yaml

# Distributed safety under an unreliable network:
formalspecgen verify-distributed ping_pong.v2.yaml \
  --message-fields cmd_slot,ack_slot --faults message_loss,duplication,reordering

# Certification traceability and reviewer non-repudiation:
formalspecgen generate-traceability-matrix bounded_counter.v2.yaml src/ --reqs requirements.req
formalspecgen manage-trust --add-key alice.pub
formalspecgen sign-artifact domains/v2/bank.json --key alice@example.com
```

The full deterministic suite (1231 tests, 99.01% combined coverage) is
`python3 -m pytest -c pytest.ini`; the real-tool end-to-end suites live in
`tests_e2e/` (`scripts/run_e2e.sh`). The agent surface is
`pip install 'formalspecgen[mcp]' && python mcp_server.py` — 28 tools, workspace-
contained, fail-closed, and deliberately without `promote-domain`, `sign-artifact`,
or `manage-trust`.
