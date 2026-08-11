# FormalSpecGen design

Copyright 2026 Sheel Morjaria. Licensed under Apache-2.0.

This document describes the active implementation. Evidence labels are deliberately narrower than
marketing claims: generated tests are samples, bounded model checking is bounded evidence, and only
a successful formal backend may issue its scoped proof claim.

## 1. Product rule

> The LLM proposes; deterministic compilers transform; formal tools judge; humans control trusted
> assumptions.

## 2. Trusted surfaces

Java/JML contracts and signatures, Rust traits/signatures/Prusti attributes, and C
signatures/attached ACSL contracts are immutable during ordinary synthesis. A generated mutation is
a terminal `TRUST_BOUNDARY_VIOLATION`. Explicitly accepted deterministic passes are recorded as
proof-relevant transformations and never silently promoted into user requirements.

## 3. Reference architecture

```text
trusted contract
  -> LLM implementation candidate
  -> trusted-surface comparison
  -> explicitly accepted deterministic passes
  -> compile/lint gate
  -> instrumented quick-test gate
  -> formal backend
  -> structured verdict and provenance
```

Java uses `javac`, OpenJML RAC/OpenJML ESC, and reviewed Dafny boundary translations. Rust uses
`rustc --test` with overflow checks, then Prusti. C uses strict C11 plus ASan/UBSan, then Frama-C WP.

## 4. Gate ordering

### 4.1 Compile and lint

Cheap syntax, type, safety-policy, and contract-shape checks run before proof tools.

### 4.4 Counterexample gate

Rust test modules are generated from the public contract and executed with `rustc --test -C
overflow-checks=yes`. C harnesses are compiled with `-fsanitize=address,undefined` and
`-fno-sanitize-recover=all`. A failing execution is `COUNTEREXAMPLE_EVIDENCE`, is fed to the repair
loop, and prevents Prusti/Frama-C from running for that candidate. A passing execution is only
`RUNTIME_SAMPLE`; it is not proof. Test-generation, compilation, timeout, and tool failures are
reported separately and do not become successful evidence.

### 4.7 Runtime evidence

The `standard` Rust/C profile requires both static checking and a non-failing instrumented runtime
sample. Its maximum claim is `STATIC_CHECKED_RUNTIME_TESTED` / `RUNTIME_SAMPLE`. Critical mode still
requires Prusti or Frama-C WP after the quick-test gate.

## 5–14. Shared orchestration constraints

All languages use separate resampling and feedback budgets, normalized diagnostics, candidate and
contract hashes, repeated-error/candidate stall detection, fixed gate ordering, and structured
evidence. Runtime counterexamples guide regeneration but never discharge a verification condition.

## 15. Test generation

Generated Rust tests must be deterministic `#[test]` code, use only public APIs, satisfy declared
preconditions, and avoid unsafe code and external crates. Generated C harnesses must have bounded
inputs, avoid allocation/randomness/concurrency, and use the public API. Both print
`FORMALSPEC_INPUT:` markers so concrete cases survive in evidence. The generated harness itself is
untrusted and must compile under the instrumented gate.

## 16. Deterministic encoding support

### 16.9 Rust purity

`inject_pure` adds `#[pure]` only to a locally defined helper referenced by a Prusti contract.

### 16.10 Rust slice bounds

`inject_slice_bounds` derives `index < slice.len()` only for direct indexing where the function
signature declares the slice and `usize` index.

### 16.11 Rust overflow bounds

`inject_overflow_bounds` promotes explicit `// prusti-requires:` facts and derives exact input
intervals for direct signed `i8/i16/i32/i64` parameter arithmetic with integer constants. It does
not invent a generic bound such as 1000 and does not handle variable-variable or nonlinear
expressions outside this reviewed subset.

### 16.12 C pointer and loop frames

`inject_null_checks` adds `\valid`/`\valid_read` only for directly dereferenced pointer parameters
attached to an existing ACSL contract. `inject_loop_assigns` promotes explicit
`// acsl-loop-assigns:` markers and never guesses alias-sensitive frames.

### 16.13 C overflow bounds

`inject_overflow_bounds` uses `INT_MIN`/`INT_MAX` obligations for direct signed `int`
parameter/constant addition, subtraction, and multiplication and adds `<limits.h>` when required.
Other arithmetic shapes fail through ordinary Frama-C RTE obligations unless a reviewer supplies an
explicit `// acsl-requires:` fact.

### 16.15 Encoding artifacts and fallback scope

| Artifact | Judge | Claim ceiling |
| --- | --- | --- |
| Java/JML source | OpenJML ESC | `DEDUCTIVE_PROOF` |
| Reviewed Java boundary translation | Dafny | scoped boundary proof |
| Rust/Prusti source | Prusti | `DEDUCTIVE_PROOF` |
| C/ACSL source | Frama-C WP | `DEDUCTIVE_PROOF` |
| Rust/C instrumented executions | native test/sanitizer gate | `RUNTIME_SAMPLE` or `COUNTEREXAMPLE_EVIDENCE` |
| Bounded TLA+ | TLC | `BOUNDED_ARCHITECTURE_EVIDENCE` |

Dafny fallback is Java/JML-only. Translating Rust or C into Dafny is not currently established as a
proof-preserving compilation and must not be used to upgrade a Rust/C verdict.

## 17. Polyglot implementation routing

`formalspecgen implement` routes `.java`/`.jml`, `.rs`, and `.c` to their native loops.
`--method-proof-only` skips TLA+/refinement and records `assurance_scope: method_contract_only`,
`bounded_architecture_checked: false`, and `source_refinement_proved: false`. It does not convert a
method proof into full critical architectural assurance.

Rust and C remain restricted subsets. Missing tools, unsupported language constructs, test-gate
failures, unknown deterministic passes, and formal verification failures all fail closed.
